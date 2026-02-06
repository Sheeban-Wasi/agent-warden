"""
Audit Logger - Structured compliance logging for Agent-Warden.

Provides structured JSON logging for all inspection verdicts, enabling:
- Compliance reporting (SOC2, HIPAA, GDPR audit trails)
- Security monitoring and alerting
- Forensic analysis of blocked attempts
- Performance tracking and optimization

Example:
    from warden.core.audit import AuditLogger, LogDestination

    # Simple setup - logs to stdout
    logger = AuditLogger()

    # Production setup - multiple destinations
    logger = AuditLogger(
        destinations=[
            LogDestination.STDOUT,
            LogDestination.FILE,
        ],
        log_file="warden_audit.jsonl",
        min_level=AuditLevel.BLOCK,  # Only log blocks
    )

    # Log a verdict
    logger.log(verdict, context={"user_id": "123", "agent": "sql-agent"})
"""

from __future__ import annotations

import json
import logging
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from queue import Queue
from typing import IO, Any, Protocol

from warden.core.verdict import Verdict, VerdictType


class AuditLevel(Enum):
    """
    Audit logging levels.

    Controls which verdicts get logged based on their outcome.
    """

    ALL = "all"  # Log everything (pass and block)
    BLOCK = "block"  # Only log blocked requests
    NONE = "none"  # Disable logging


class LogDestination(Enum):
    """Supported log output destinations."""

    STDOUT = "stdout"
    STDERR = "stderr"
    FILE = "file"
    CUSTOM = "custom"


class LogHandler(Protocol):
    """Protocol for custom log handlers."""

    def write(self, record: dict[str, Any]) -> None:
        """Write a log record."""
        ...

    def flush(self) -> None:
        """Flush any buffered records."""
        ...

    def close(self) -> None:
        """Close the handler and release resources."""
        ...


@dataclass
class AuditRecord:
    """
    A single audit log record.

    Contains all information about an inspection for compliance purposes.
    """

    # Core verdict info
    event_id: str
    timestamp: str
    verdict: str  # "PASS" or "BLOCK"
    inspector: str
    reason: str
    rule: str | None

    # Performance
    latency_ms: float

    # Context (optional, user-provided)
    context: dict[str, Any] = field(default_factory=dict)

    # Additional details from verdict
    details: dict[str, Any] = field(default_factory=dict)

    # Warden metadata
    warden_version: str = "0.1.0"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "verdict": self.verdict,
            "inspector": self.inspector,
            "reason": self.reason,
            "rule": self.rule,
            "latency_ms": self.latency_ms,
            "context": self.context,
            "details": self.details,
            "warden_version": self.warden_version,
        }

    def to_json(self, indent: int | None = None) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


class FileHandler:
    """
    File-based log handler.

    Writes JSON lines (one JSON object per line) for easy parsing.
    """

    def __init__(
        self,
        path: str | Path,
        mode: str = "a",
        encoding: str = "utf-8",
    ) -> None:
        self.path = Path(path)
        self.mode = mode
        self.encoding = encoding
        self._file: IO[str] | None = None
        self._lock = threading.Lock()

    def _ensure_open(self) -> IO[str]:
        """Ensure file is open, creating parent dirs if needed."""
        if self._file is None or self._file.closed:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, self.mode, encoding=self.encoding)
        return self._file

    def write(self, record: dict[str, Any]) -> None:
        """Write a record as a JSON line."""
        with self._lock:
            f = self._ensure_open()
            f.write(json.dumps(record, default=str) + "\n")

    def flush(self) -> None:
        """Flush the file buffer."""
        with self._lock:
            if self._file and not self._file.closed:
                self._file.flush()

    def close(self) -> None:
        """Close the file."""
        with self._lock:
            if self._file and not self._file.closed:
                self._file.close()
                self._file = None


class StreamHandler:
    """Handler that writes to a stream (stdout/stderr)."""

    def __init__(self, stream: IO[str] | None = None) -> None:
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()

    def write(self, record: dict[str, Any]) -> None:
        """Write a record as a JSON line."""
        with self._lock:
            self.stream.write(json.dumps(record, default=str) + "\n")

    def flush(self) -> None:
        """Flush the stream buffer."""
        with self._lock:
            self.stream.flush()

    def close(self) -> None:
        """No-op for streams (don't close stdout/stderr)."""
        pass


class AsyncHandler:
    """
    Async wrapper for any handler.

    Uses a background thread to write logs without blocking the main thread.
    """

    def __init__(self, handler: LogHandler, queue_size: int = 10000) -> None:
        self._handler = handler
        self._queue: Queue[dict[str, Any] | None] = Queue(maxsize=queue_size)
        self._thread = threading.Thread(target=self._worker, daemon=True)
        self._thread.start()

    def _worker(self) -> None:
        """Background worker that processes the queue."""
        while True:
            record = self._queue.get()
            if record is None:  # Shutdown signal
                break
            try:
                self._handler.write(record)
            except Exception:
                pass  # Silently ignore write errors in background
            finally:
                self._queue.task_done()

    def write(self, record: dict[str, Any]) -> None:
        """Queue a record for async writing."""
        try:
            self._queue.put_nowait(record)
        except Exception:
            pass  # Drop record if queue is full

    def flush(self) -> None:
        """Wait for queue to drain and flush underlying handler."""
        self._queue.join()
        self._handler.flush()

    def close(self) -> None:
        """Shutdown the background thread and close underlying handler."""
        self._queue.put(None)  # Shutdown signal
        self._thread.join(timeout=5.0)
        self._handler.close()


class AuditLogger:
    """
    Main audit logger for Agent-Warden.

    Provides structured JSON logging of all inspection verdicts for
    compliance, monitoring, and forensic analysis.

    Args:
        destinations: Where to send logs (stdout, stderr, file, custom)
        log_file: Path to log file (required if FILE destination)
        min_level: Minimum level to log (ALL, BLOCK, NONE)
        async_logging: Use background thread for non-blocking writes
        custom_handler: Custom handler for CUSTOM destination
        include_context: Whether to include context in logs

    Example:
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file="audit.jsonl",
            min_level=AuditLevel.BLOCK,
        )

        verdict = inspector.inspect(query)
        logger.log(verdict, context={"user": "agent-1"})
    """

    def __init__(
        self,
        destinations: list[LogDestination] | None = None,
        log_file: str | Path | None = None,
        min_level: AuditLevel = AuditLevel.ALL,
        async_logging: bool = False,
        custom_handler: LogHandler | None = None,
        include_context: bool = True,
    ) -> None:
        self.min_level = min_level
        self.include_context = include_context
        self._handlers: list[LogHandler] = []

        # Default to stdout if no destinations specified
        destinations = destinations or [LogDestination.STDOUT]

        for dest in destinations:
            handler: LogHandler

            if dest == LogDestination.STDOUT:
                handler = StreamHandler(sys.stdout)
            elif dest == LogDestination.STDERR:
                handler = StreamHandler(sys.stderr)
            elif dest == LogDestination.FILE:
                if not log_file:
                    raise ValueError("log_file required for FILE destination")
                handler = FileHandler(log_file)
            elif dest == LogDestination.CUSTOM:
                if not custom_handler:
                    raise ValueError("custom_handler required for CUSTOM destination")
                handler = custom_handler
            else:
                continue

            # Wrap in async handler if requested
            if async_logging:
                handler = AsyncHandler(handler)

            self._handlers.append(handler)

    def log(
        self,
        verdict: Verdict,
        context: dict[str, Any] | None = None,
    ) -> AuditRecord | None:
        """
        Log an inspection verdict.

        Args:
            verdict: The inspection verdict to log
            context: Additional context (user_id, agent_name, request_id, etc.)

        Returns:
            The audit record if logged, None if filtered out
        """
        # Check if we should log this verdict
        if not self._should_log(verdict):
            return None

        # Create audit record
        record = AuditRecord(
            event_id=verdict.event_id,
            timestamp=verdict.timestamp,
            verdict=verdict.verdict.value,
            inspector=verdict.inspector,
            reason=verdict.reason,
            rule=verdict.rule,
            latency_ms=verdict.latency_ms,
            context=context if self.include_context and context else {},
            details=verdict.details,
        )

        # Write to all handlers
        record_dict = record.to_dict()
        for handler in self._handlers:
            try:
                handler.write(record_dict)
            except Exception:
                pass  # Don't let logging failures break the app

        return record

    def log_custom(
        self,
        event_type: str,
        message: str,
        details: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Log a custom event (not tied to a verdict).

        Useful for logging policy loads, configuration changes, etc.

        Args:
            event_type: Type of event (e.g., "policy_loaded", "config_changed")
            message: Human-readable message
            details: Additional event details
            context: Request/session context
        """
        record = {
            "event_id": None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "message": message,
            "details": details or {},
            "context": context if self.include_context and context else {},
            "warden_version": "0.1.0",
        }

        for handler in self._handlers:
            try:
                handler.write(record)
            except Exception:
                pass

    def _should_log(self, verdict: Verdict) -> bool:
        """Check if verdict should be logged based on min_level."""
        if self.min_level == AuditLevel.NONE:
            return False
        if self.min_level == AuditLevel.BLOCK:
            return verdict.verdict == VerdictType.BLOCK
        return True  # AuditLevel.ALL

    def flush(self) -> None:
        """Flush all handlers."""
        for handler in self._handlers:
            try:
                handler.flush()
            except Exception:
                pass

    def close(self) -> None:
        """Close all handlers and release resources."""
        for handler in self._handlers:
            try:
                handler.close()
            except Exception:
                pass
        self._handlers.clear()

    def __enter__(self) -> AuditLogger:
        """Context manager entry."""
        return self

    def __exit__(self, *args: Any) -> None:
        """Context manager exit - close handlers."""
        self.close()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_audit_logger(
    log_file: str | Path | None = None,
    console: bool = True,
    level: str = "all",
    async_mode: bool = False,
) -> AuditLogger:
    """
    Create an audit logger with common configurations.

    Args:
        log_file: Optional file path for JSON logs
        console: Whether to also log to stdout
        level: "all", "block", or "none"
        async_mode: Use async logging for better performance

    Returns:
        Configured AuditLogger instance

    Example:
        # Development - console only
        logger = create_audit_logger()

        # Production - file + console, blocks only
        logger = create_audit_logger(
            log_file="audit.jsonl",
            level="block",
            async_mode=True,
        )
    """
    destinations: list[LogDestination] = []

    if console:
        destinations.append(LogDestination.STDOUT)

    if log_file:
        destinations.append(LogDestination.FILE)

    level_map = {
        "all": AuditLevel.ALL,
        "block": AuditLevel.BLOCK,
        "none": AuditLevel.NONE,
    }

    return AuditLogger(
        destinations=destinations,
        log_file=log_file,
        min_level=level_map.get(level.lower(), AuditLevel.ALL),
        async_logging=async_mode,
    )
