"""
Tests for the Audit Logger.

These tests verify that the audit logger correctly:
- Logs verdicts to various destinations
- Filters based on audit level
- Handles async logging
- Produces valid JSON output
"""

import json
import time
from io import StringIO

import pytest

from warden import (
    AuditLevel,
    AuditLogger,
    AuditRecord,
    LogDestination,
    create_audit_logger,
    inspect_sql,
)
from warden.core.audit import AsyncHandler, FileHandler, StreamHandler
from warden.core.verdict import create_block_verdict, create_pass_verdict

# =============================================================================
# AUDIT RECORD TESTS
# =============================================================================

class TestAuditRecord:
    """Test AuditRecord dataclass."""

    def test_record_to_dict(self):
        """Record converts to dictionary correctly."""
        record = AuditRecord(
            event_id="test-123",
            timestamp="2024-01-01T00:00:00Z",
            verdict="BLOCK",
            inspector="sql_inspector",
            reason="DROP TABLE blocked",
            rule="critical_node_detected",
            latency_ms=1.5,
            context={"user": "test"},
            details={"node_type": "Drop"},
        )

        d = record.to_dict()
        assert d["event_id"] == "test-123"
        assert d["verdict"] == "BLOCK"
        assert d["inspector"] == "sql_inspector"
        assert d["latency_ms"] == 1.5
        assert d["context"] == {"user": "test"}

    def test_record_to_json(self):
        """Record converts to valid JSON."""
        record = AuditRecord(
            event_id="test-123",
            timestamp="2024-01-01T00:00:00Z",
            verdict="PASS",
            inspector="sql_inspector",
            reason="Query allowed",
            rule=None,
            latency_ms=0.5,
        )

        json_str = record.to_json()
        parsed = json.loads(json_str)
        assert parsed["verdict"] == "PASS"
        assert parsed["rule"] is None


# =============================================================================
# HANDLER TESTS
# =============================================================================

class TestStreamHandler:
    """Test StreamHandler."""

    def test_write_to_stream(self):
        """Handler writes JSON to stream."""
        output = StringIO()
        handler = StreamHandler(output)

        handler.write({"test": "value"})
        handler.flush()

        output.seek(0)
        line = output.readline()
        parsed = json.loads(line)
        assert parsed["test"] == "value"

    def test_multiple_writes(self):
        """Handler writes multiple records."""
        output = StringIO()
        handler = StreamHandler(output)

        handler.write({"line": 1})
        handler.write({"line": 2})
        handler.flush()

        output.seek(0)
        lines = output.readlines()
        assert len(lines) == 2


class TestFileHandler:
    """Test FileHandler."""

    def test_write_to_file(self, tmp_path):
        """Handler writes JSON to file."""
        log_file = tmp_path / "test.jsonl"
        handler = FileHandler(log_file)

        handler.write({"test": "value"})
        handler.flush()
        handler.close()

        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["test"] == "value"

    def test_creates_parent_dirs(self, tmp_path):
        """Handler creates parent directories if needed."""
        log_file = tmp_path / "subdir" / "deep" / "test.jsonl"
        handler = FileHandler(log_file)

        handler.write({"test": "value"})
        handler.close()

        assert log_file.exists()

    def test_append_mode(self, tmp_path):
        """Handler appends to existing file."""
        log_file = tmp_path / "test.jsonl"

        # Write first record
        handler1 = FileHandler(log_file)
        handler1.write({"line": 1})
        handler1.close()

        # Write second record
        handler2 = FileHandler(log_file)
        handler2.write({"line": 2})
        handler2.close()

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2


class TestAsyncHandler:
    """Test AsyncHandler."""

    def test_async_write(self):
        """Async handler writes in background."""
        output = StringIO()
        base_handler = StreamHandler(output)
        handler = AsyncHandler(base_handler)

        handler.write({"test": "value"})
        handler.flush()  # Wait for queue to drain
        handler.close()

        output.seek(0)
        line = output.readline()
        parsed = json.loads(line)
        assert parsed["test"] == "value"

    def test_async_multiple_writes(self):
        """Async handler handles multiple writes."""
        output = StringIO()
        base_handler = StreamHandler(output)
        handler = AsyncHandler(base_handler)

        for i in range(10):
            handler.write({"line": i})

        handler.flush()
        handler.close()

        output.seek(0)
        lines = output.readlines()
        assert len(lines) == 10


# =============================================================================
# AUDIT LOGGER TESTS
# =============================================================================

class TestAuditLogger:
    """Test AuditLogger."""

    def test_log_verdict_to_stdout(self, capsys):
        """Logger writes verdict to stdout."""
        logger = AuditLogger(destinations=[LogDestination.STDOUT])

        verdict = create_block_verdict(
            inspector="test",
            reason="Test block",
            rule="test_rule",
        )

        logger.log(verdict)
        logger.flush()

        captured = capsys.readouterr()
        parsed = json.loads(captured.out.strip())
        assert parsed["verdict"] == "BLOCK"
        assert parsed["inspector"] == "test"

    def test_log_verdict_to_file(self, tmp_path):
        """Logger writes verdict to file."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        verdict = create_pass_verdict(inspector="test")
        logger.log(verdict)
        logger.close()

        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["verdict"] == "PASS"

    def test_log_with_context(self, tmp_path):
        """Logger includes context in output."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        verdict = create_pass_verdict(inspector="test")
        logger.log(verdict, context={"user_id": "123", "agent": "sql-agent"})
        logger.close()

        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["context"]["user_id"] == "123"
        assert parsed["context"]["agent"] == "sql-agent"

    def test_filter_by_level_block_only(self, tmp_path):
        """Logger filters based on audit level."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
            min_level=AuditLevel.BLOCK,
        )

        # Log a pass (should be filtered)
        pass_verdict = create_pass_verdict(inspector="test")
        logger.log(pass_verdict)

        # Log a block (should be recorded)
        block_verdict = create_block_verdict(inspector="test", reason="blocked", rule="test_rule")
        logger.log(block_verdict)

        logger.close()

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["verdict"] == "BLOCK"

    def test_filter_by_level_none(self, tmp_path):
        """Logger with NONE level logs nothing."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
            min_level=AuditLevel.NONE,
        )

        verdict = create_block_verdict(inspector="test", reason="blocked", rule="test_rule")
        logger.log(verdict)
        logger.close()

        # File should not exist or be empty
        assert not log_file.exists() or log_file.read_text() == ""

    def test_multiple_destinations(self, tmp_path, capsys):
        """Logger writes to multiple destinations."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.STDOUT, LogDestination.FILE],
            log_file=log_file,
        )

        verdict = create_pass_verdict(inspector="test")
        logger.log(verdict)
        logger.flush()
        logger.close()

        # Check stdout
        captured = capsys.readouterr()
        assert "PASS" in captured.out

        # Check file
        content = log_file.read_text()
        assert "PASS" in content

    def test_context_manager(self, tmp_path):
        """Logger works as context manager."""
        log_file = tmp_path / "audit.jsonl"

        with AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        ) as logger:
            verdict = create_pass_verdict(inspector="test")
            logger.log(verdict)

        # File should be written after context exit
        assert log_file.exists()
        content = log_file.read_text()
        assert "PASS" in content

    def test_log_custom_event(self, tmp_path):
        """Logger can log custom events."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        logger.log_custom(
            event_type="policy_loaded",
            message="Policy loaded successfully",
            details={"policy_file": "policy.yaml"},
        )
        logger.close()

        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["event_type"] == "policy_loaded"
        assert parsed["message"] == "Policy loaded successfully"

    def test_requires_log_file_for_file_destination(self):
        """Logger raises error if FILE destination without log_file."""
        with pytest.raises(ValueError, match="log_file required"):
            AuditLogger(destinations=[LogDestination.FILE])

    def test_async_logging(self, tmp_path):
        """Logger supports async logging."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
            async_logging=True,
        )

        for i in range(100):
            verdict = create_pass_verdict(inspector=f"test-{i}")
            logger.log(verdict)

        logger.flush()
        logger.close()

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 100


# =============================================================================
# INTEGRATION TESTS
# =============================================================================

class TestAuditLoggerIntegration:
    """Integration tests with SQL Inspector."""

    def test_log_sql_inspection_block(self, tmp_path):
        """Audit logger correctly logs SQL inspection blocks."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        verdict = inspect_sql("DROP TABLE users")
        record = logger.log(verdict, context={"agent": "sql-agent"})
        logger.close()

        assert record is not None
        assert record.verdict == "BLOCK"
        assert "Drop" in record.reason or "DROP" in record.reason

        # Verify file content
        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["inspector"] == "sql_inspector"
        assert parsed["context"]["agent"] == "sql-agent"

    def test_log_sql_inspection_pass(self, tmp_path):
        """Audit logger correctly logs SQL inspection passes."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        verdict = inspect_sql("SELECT * FROM users")
        record = logger.log(verdict)
        logger.close()

        assert record is not None
        assert record.verdict == "PASS"

    def test_convenience_function(self, tmp_path):
        """create_audit_logger convenience function works."""
        log_file = tmp_path / "audit.jsonl"

        logger = create_audit_logger(
            log_file=log_file,
            console=False,
            level="block",
        )

        # Pass should not be logged
        pass_verdict = inspect_sql("SELECT 1")
        logger.log(pass_verdict)

        # Block should be logged
        block_verdict = inspect_sql("DROP TABLE users")
        logger.log(block_verdict)

        logger.close()

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 1
        parsed = json.loads(lines[0])
        assert parsed["verdict"] == "BLOCK"


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================

class TestAuditLoggerPerformance:
    """Performance tests for audit logger."""

    def test_logging_latency(self, tmp_path):
        """Logging should be fast (<1ms per record)."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        verdict = create_pass_verdict(inspector="test")

        # Warm up
        logger.log(verdict)

        # Time 1000 logs
        start = time.perf_counter()
        for _ in range(1000):
            logger.log(verdict)
        elapsed = time.perf_counter() - start

        logger.close()

        avg_ms = (elapsed / 1000) * 1000
        assert avg_ms < 1.0, f"Average log time {avg_ms:.3f}ms exceeds 1ms"

    def test_async_logging_non_blocking(self, tmp_path):
        """Async logging should not block the caller."""
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
            async_logging=True,
        )

        verdict = create_pass_verdict(inspector="test")

        # Time 1000 async logs (should be very fast)
        start = time.perf_counter()
        for _ in range(1000):
            logger.log(verdict)
        elapsed = time.perf_counter() - start

        # Async log calls should complete almost instantly
        avg_ms = (elapsed / 1000) * 1000
        assert avg_ms < 0.1, f"Average async log time {avg_ms:.3f}ms exceeds 0.1ms"

        logger.flush()
        logger.close()
