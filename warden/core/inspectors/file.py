# ruff: noqa: I001
"""
File Access Inspector for Agent-Warden.

Provides security inspection for file path access, detecting:
- Path traversal attacks (../, encoded variants, null bytes)
- Symlink attacks (TOCTOU, symlink poisoning)
- Sensitive file access (.env, credentials, keys)
- Cloud metadata endpoint access
- File size limits (DoS prevention)

Philosophy: Deny by Default. If uncertain, block.

Example:
    >>> from warden import check_file, inspect_file
    >>> check_file("/app/data/file.txt", base_directory="/app")
    True
    >>> result = inspect_file("../../../etc/passwd")
    >>> result.is_safe
    False
    >>> result.violation_types
    {FileViolationType.PATH_TRAVERSAL}
"""
from __future__ import annotations

import fnmatch
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import ClassVar, Literal

from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict


class FileMode(Enum):
    """
    File access inspection modes.

    STRICT: Only allow paths in explicit whitelist (most secure)
    ALLOWLIST: Allow whitelist paths, block sensitive patterns
    BLOCKLIST: Block blacklist paths only, allow everything else
    MONITOR: Log only, don't block (for policy tuning)
    """

    STRICT = "strict"
    ALLOWLIST = "allowlist"
    BLOCKLIST = "blocklist"
    MONITOR = "monitor"


class FileViolationType(Enum):
    """Types of file access violations that can be detected."""

    PATH_TRAVERSAL = "path_traversal"
    SYMLINK_ATTACK = "symlink_attack"
    SENSITIVE_FILE = "sensitive_file"
    BLOCKED_EXTENSION = "blocked_extension"
    CLOUD_METADATA = "cloud_metadata"
    FILE_SIZE_EXCEEDED = "file_size_exceeded"
    OUTSIDE_ALLOWLIST = "outside_allowlist"
    IN_BLOCKLIST = "in_blocklist"
    NULL_BYTE = "null_byte"
    ENCODED_TRAVERSAL = "encoded_traversal"
    EMPTY_PATH = "empty_path"


@dataclass
class FileMatch:
    """A single file access violation found during inspection."""

    violation_type: FileViolationType
    path: str
    resolved_path: str | None
    pattern_matched: str | None
    confidence: float = 1.0

    @property
    def description(self) -> str:
        """Human-readable description of the violation."""
        descriptions = {
            FileViolationType.PATH_TRAVERSAL: "Path traversal attempt detected",
            FileViolationType.SYMLINK_ATTACK: "Symlink pointing outside allowed scope",
            FileViolationType.SENSITIVE_FILE: f"Access to sensitive file pattern: {self.pattern_matched}",
            FileViolationType.BLOCKED_EXTENSION: f"Blocked file extension: {self.pattern_matched}",
            FileViolationType.CLOUD_METADATA: "Cloud metadata endpoint access blocked",
            FileViolationType.FILE_SIZE_EXCEEDED: "File size exceeds maximum allowed",
            FileViolationType.OUTSIDE_ALLOWLIST: "Path outside allowed directories",
            FileViolationType.IN_BLOCKLIST: "Path in blocked directories",
            FileViolationType.NULL_BYTE: "Null byte injection detected",
            FileViolationType.ENCODED_TRAVERSAL: "URL-encoded traversal pattern detected",
            FileViolationType.EMPTY_PATH: "Empty or invalid path",
        }
        return descriptions.get(self.violation_type, "Unknown violation")


@dataclass
class FileResult:
    """
    Result of file access inspection.

    Contains the verdict and details about any violations found.

    Attributes:
        verdict: The security verdict (PASS or BLOCK)
        original_path: The original path that was inspected
        normalized_path: Path after normalization (cross-platform)
        resolved_path: Fully resolved canonical path (if resolvable)
        findings: List of violations found
    """

    verdict: Verdict
    original_path: str
    normalized_path: str
    resolved_path: str | None
    findings: list[FileMatch] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if the file access is allowed."""
        return self.verdict.passed

    @property
    def violation_types(self) -> set[FileViolationType]:
        """Get set of violation types found."""
        return {f.violation_type for f in self.findings}

    def to_audit_log(self) -> dict:
        """Convert to audit log format."""
        log = self.verdict.to_audit_log()
        log["file_findings"] = [
            {
                "type": f.violation_type.value,
                "path": f.path,
                "resolved_path": f.resolved_path,
                "pattern": f.pattern_matched,
                "confidence": f.confidence,
            }
            for f in self.findings
        ]
        log["paths"] = {
            "original": self.original_path,
            "normalized": self.normalized_path,
            "resolved": self.resolved_path,
        }
        return log


# Default blocked extensions (secrets and keys)
DEFAULT_BLOCKED_EXTENSIONS: frozenset[str] = frozenset({
    ".env",
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".crt",
    ".cer",
    ".der",
    ".pub",
})

# Default sensitive file patterns (filename-based for cross-platform compatibility)
DEFAULT_SENSITIVE_PATTERNS: frozenset[str] = frozenset({
    # Environment files
    ".env",
    ".env.*",
    ".env.local",
    ".env.production",
    ".env.development",
    # Git
    ".git",
    ".gitconfig",
    # SSH
    "id_rsa",
    "id_rsa.*",
    "id_ed25519",
    "id_ed25519.*",
    "id_dsa",
    "authorized_keys",
    "known_hosts",
    # AWS/Credentials
    "credentials",
    "credentials.*",
    # Secrets
    "secrets",
    "secrets.*",
    "*password*",
    "*secret*",
    # Config files
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".htpasswd",
    ".htaccess",
    ".dockercfg",
    # System files
    "shadow",
    "passwd",
})

# Cloud metadata IPs
DEFAULT_CLOUD_METADATA_IPS: frozenset[str] = frozenset({
    "169.254.169.254",
    "100.100.100.200",
    "fd00:ec2::254",
    "metadata.google.internal",
})


@dataclass
class FileInspectorConfig:
    """Configuration for the File Inspector."""

    mode: FileMode = FileMode.ALLOWLIST
    allowed_paths: frozenset[str] = field(default_factory=frozenset)
    blocked_paths: frozenset[str] = field(default_factory=frozenset)
    base_directory: str | None = None
    allowed_extensions: frozenset[str] | None = None
    blocked_extensions: frozenset[str] = field(
        default_factory=lambda: DEFAULT_BLOCKED_EXTENSIONS
    )
    sensitive_patterns: frozenset[str] = field(
        default_factory=lambda: DEFAULT_SENSITIVE_PATTERNS
    )
    block_cloud_metadata: bool = True
    cloud_metadata_ips: frozenset[str] = field(
        default_factory=lambda: DEFAULT_CLOUD_METADATA_IPS
    )
    follow_symlinks: bool = False
    max_file_size: int = 100 * 1024 * 1024
    check_file_size: bool = True
    fail_closed: bool = True


class FileInspector:
    """
    File access security inspector.

    Validates file paths for security threats including:
    - Path traversal (../, encoded variants, null bytes)
    - Symlink attacks (TOCTOU, symlink poisoning)
    - Sensitive file access (.env, credentials, keys)
    - Cloud metadata endpoint access
    - File size limits (DoS prevention)

    Philosophy: Deny by Default. If uncertain, block.

    Args:
        mode: Inspection mode (strict, allowlist, blocklist, monitor)
        allowed_paths: Directories/files explicitly allowed
        blocked_paths: Directories/files explicitly blocked
        base_directory: Root directory all paths must be under
        blocked_extensions: File extensions to block
        sensitive_patterns: Glob patterns for sensitive files
        fail_closed: If True, block on any uncertainty

    Example:
        >>> inspector = FileInspector(
        ...     mode="allowlist",
        ...     allowed_paths={"/app/data", "/app/uploads"},
        ...     base_directory="/app",
        ... )
        >>> result = inspector.inspect("/app/data/file.txt")
        >>> result.is_safe
        True
        >>> result = inspector.inspect("../../../etc/passwd")
        >>> result.is_safe
        False
    """

    INSPECTOR_NAME = "file_inspector"

    # Path traversal patterns to detect
    PATH_TRAVERSAL_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"\.\.[\\/]"),
        re.compile(r"\.\.%2[fF]"),
        re.compile(r"\.\.%5[cC]"),
        re.compile(r"%2[eE]%2[eE][\\/]"),
        re.compile(r"%2[eE]%2[eE]%2[fF]"),
        re.compile(r"%2[eE]%2[eE]%5[cC]"),
        re.compile(r"%252[eE]%252[eE]"),
        re.compile(r"\.\.\/"),
        re.compile(r"\.\.\\"),
        re.compile(r"\.\.\.\.\/\/"),
    ]

    # Null byte patterns
    NULL_BYTE_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"\x00"),
        re.compile(r"%00"),
        re.compile(r"\\0"),
    ]

    def __init__(
        self,
        mode: FileMode | str = FileMode.ALLOWLIST,
        allowed_paths: set[str] | frozenset[str] | list[str] | None = None,
        blocked_paths: set[str] | frozenset[str] | list[str] | None = None,
        base_directory: str | None = None,
        allowed_extensions: set[str] | frozenset[str] | list[str] | None = None,
        blocked_extensions: set[str] | frozenset[str] | list[str] | None = None,
        sensitive_patterns: set[str] | frozenset[str] | list[str] | None = None,
        block_cloud_metadata: bool = True,
        follow_symlinks: bool = False,
        max_file_size: int = 100 * 1024 * 1024,
        fail_closed: bool = True,
    ) -> None:
        """Initialize the FileInspector with configuration."""
        if isinstance(mode, str):
            mode = FileMode(mode)

        def to_frozenset(
            items: set[str] | frozenset[str] | list[str] | None,
        ) -> frozenset[str]:
            if items is None:
                return frozenset()
            return frozenset(items)

        self.config = FileInspectorConfig(
            mode=mode,
            allowed_paths=to_frozenset(allowed_paths),
            blocked_paths=to_frozenset(blocked_paths),
            base_directory=base_directory,
            allowed_extensions=(
                frozenset(e.lower() for e in allowed_extensions)
                if allowed_extensions
                else None
            ),
            blocked_extensions=(
                frozenset(e.lower() for e in blocked_extensions)
                if blocked_extensions
                else DEFAULT_BLOCKED_EXTENSIONS
            ),
            sensitive_patterns=(
                frozenset(sensitive_patterns)
                if sensitive_patterns
                else DEFAULT_SENSITIVE_PATTERNS
            ),
            block_cloud_metadata=block_cloud_metadata,
            follow_symlinks=follow_symlinks,
            max_file_size=max_file_size,
            fail_closed=fail_closed,
        )

    def inspect(self, path: str) -> FileResult:
        """
        Inspect a file path for security violations.

        Args:
            path: The file path to inspect

        Returns:
            FileResult with verdict and violation details
        """
        start_time = time.perf_counter()
        findings: list[FileMatch] = []

        # Pre-validation: empty path
        if not path or not path.strip():
            return self._create_block_result(
                path=path or "",
                normalized_path="",
                resolved_path=None,
                findings=[
                    FileMatch(
                        violation_type=FileViolationType.EMPTY_PATH,
                        path=path or "",
                        resolved_path=None,
                        pattern_matched="empty_path",
                    )
                ],
                reason="Empty or whitespace-only path",
                rule="empty_path",
                start_time=start_time,
            )

        # Check for null bytes (must be first - before any parsing)
        null_byte_check = self._check_null_bytes(path)
        if null_byte_check:
            findings.append(null_byte_check)
            return self._create_block_result(
                path=path,
                normalized_path=path,
                resolved_path=None,
                findings=findings,
                reason="Null byte injection detected in path",
                rule="null_byte_injection",
                start_time=start_time,
            )

        # Check for cloud metadata IPs
        if self.config.block_cloud_metadata:
            cloud_check = self._check_cloud_metadata(path)
            if cloud_check:
                findings.append(cloud_check)
                return self._create_block_result(
                    path=path,
                    normalized_path=path,
                    resolved_path=None,
                    findings=findings,
                    reason="Cloud metadata endpoint access blocked",
                    rule="cloud_metadata_blocked",
                    start_time=start_time,
                )

        # Check for path traversal patterns (before normalization)
        traversal_check = self._check_path_traversal(path)
        if traversal_check:
            findings.append(traversal_check)
            return self._create_block_result(
                path=path,
                normalized_path=path,
                resolved_path=None,
                findings=findings,
                reason=f"Path traversal pattern detected: {traversal_check.pattern_matched}",
                rule="path_traversal",
                start_time=start_time,
            )

        # Normalize the path
        normalized_path = self._normalize_path(path)

        # Try to resolve to canonical path
        resolved_path = self._resolve_path(normalized_path)

        # Check symlinks
        if not self.config.follow_symlinks:
            symlink_check = self._check_symlink(normalized_path, resolved_path)
            if symlink_check:
                findings.append(symlink_check)
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason="Symlink attack detected",
                    rule="symlink_attack",
                    start_time=start_time,
                )

        # Use resolved path for remaining checks if available
        check_path = resolved_path or normalized_path

        # Check base directory constraint
        if self.config.base_directory:
            if not self._is_under_base(check_path):
                findings.append(
                    FileMatch(
                        violation_type=FileViolationType.OUTSIDE_ALLOWLIST,
                        path=path,
                        resolved_path=resolved_path,
                        pattern_matched=self.config.base_directory,
                    )
                )
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason=f"Path escapes base directory: {self.config.base_directory}",
                    rule="outside_base_directory",
                    start_time=start_time,
                )

        # Check extension (skip in monitor mode)
        ext_check = self._check_extension(check_path)
        if ext_check:
            findings.append(ext_check)
            if self.config.mode != FileMode.MONITOR:
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason=f"Blocked file extension: {ext_check.pattern_matched}",
                    rule="blocked_extension",
                    start_time=start_time,
                )

        # Check sensitive patterns (skip in monitor mode)
        sensitive_check = self._check_sensitive_patterns(check_path)
        if sensitive_check:
            findings.append(sensitive_check)
            if self.config.mode != FileMode.MONITOR:
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason=f"Access to sensitive file: {sensitive_check.pattern_matched}",
                    rule="sensitive_file_access",
                    start_time=start_time,
                )

        # Mode-specific checks
        if self.config.mode == FileMode.STRICT:
            if not self._is_in_allowlist(check_path):
                findings.append(
                    FileMatch(
                        violation_type=FileViolationType.OUTSIDE_ALLOWLIST,
                        path=path,
                        resolved_path=resolved_path,
                        pattern_matched="strict_mode",
                    )
                )
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason="Path not in strict allowlist",
                    rule="not_in_strict_allowlist",
                    start_time=start_time,
                )

        elif self.config.mode in (FileMode.ALLOWLIST, FileMode.BLOCKLIST):
            blocklist_check = self._check_blocklist(check_path)
            if blocklist_check:
                findings.append(blocklist_check)
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason=f"Path in blocklist: {blocklist_check.pattern_matched}",
                    rule="in_blocklist",
                    start_time=start_time,
                )

        # Check file size if file exists and size checking is enabled
        if self.config.check_file_size:
            size_check = self._check_file_size(check_path)
            if size_check:
                findings.append(size_check)
                return self._create_block_result(
                    path=path,
                    normalized_path=normalized_path,
                    resolved_path=resolved_path,
                    findings=findings,
                    reason="File size exceeds maximum allowed",
                    rule="file_size_exceeded",
                    start_time=start_time,
                )

        # MONITOR mode: log but allow
        if self.config.mode == FileMode.MONITOR and findings:
            return FileResult(
                verdict=create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Path allowed (monitor mode) with {len(findings)} finding(s)",
                    latency_ms=self._elapsed_ms(start_time),
                ),
                original_path=path,
                normalized_path=normalized_path,
                resolved_path=resolved_path,
                findings=findings,
            )

        # All checks passed
        return FileResult(
            verdict=create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason="Path passed all security checks",
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_path=path,
            normalized_path=normalized_path,
            resolved_path=resolved_path,
            findings=[],
        )

    def _normalize_path(self, path: str) -> str:
        """Normalize path for cross-platform compatibility."""
        if not path:
            return ""
        try:
            p = Path(path)
            return p.as_posix()
        except Exception:
            return path.replace("\\", "/")

    def _resolve_path(self, path: str) -> str | None:
        """Resolve path to canonical form."""
        try:
            p = Path(path)
            if p.exists():
                return str(p.resolve())
            return str(p.absolute())
        except (OSError, ValueError):
            return None

    def _check_null_bytes(self, path: str) -> FileMatch | None:
        """Check for null byte injection."""
        for pattern in self.NULL_BYTE_PATTERNS:
            if pattern.search(path):
                return FileMatch(
                    violation_type=FileViolationType.NULL_BYTE,
                    path=path,
                    resolved_path=None,
                    pattern_matched=pattern.pattern,
                )
        return None

    def _check_path_traversal(self, path: str) -> FileMatch | None:
        """Check for path traversal patterns."""
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return FileMatch(
                    violation_type=FileViolationType.PATH_TRAVERSAL,
                    path=path,
                    resolved_path=None,
                    pattern_matched=pattern.pattern,
                )
        return None

    def _check_cloud_metadata(self, path: str) -> FileMatch | None:
        """Check for cloud metadata IP access."""
        for ip in self.config.cloud_metadata_ips:
            if ip in path:
                return FileMatch(
                    violation_type=FileViolationType.CLOUD_METADATA,
                    path=path,
                    resolved_path=None,
                    pattern_matched=ip,
                )
        return None

    def _check_symlink(
        self, original: str, resolved: str | None
    ) -> FileMatch | None:
        """Check if symlink points outside allowed scope."""
        try:
            p = Path(original)
            if not p.exists():
                return None
            if p.is_symlink():
                if self.config.base_directory and resolved:
                    base_resolved = str(Path(self.config.base_directory).resolve())
                    if not resolved.startswith(base_resolved):
                        return FileMatch(
                            violation_type=FileViolationType.SYMLINK_ATTACK,
                            path=original,
                            resolved_path=resolved,
                            pattern_matched="symlink_escape",
                        )
                elif not self.config.follow_symlinks:
                    return FileMatch(
                        violation_type=FileViolationType.SYMLINK_ATTACK,
                        path=original,
                        resolved_path=resolved,
                        pattern_matched="symlink_blocked",
                    )
        except (OSError, ValueError):
            if self.config.fail_closed:
                return FileMatch(
                    violation_type=FileViolationType.SYMLINK_ATTACK,
                    path=original,
                    resolved_path=resolved,
                    pattern_matched="symlink_check_failed",
                )
        return None

    def _check_extension(self, path: str) -> FileMatch | None:
        """Check if file extension is blocked."""
        try:
            ext = Path(path).suffix.lower()
        except Exception:
            return None

        if ext in self.config.blocked_extensions:
            return FileMatch(
                violation_type=FileViolationType.BLOCKED_EXTENSION,
                path=path,
                resolved_path=None,
                pattern_matched=ext,
            )

        if self.config.allowed_extensions is not None:
            if ext and ext not in self.config.allowed_extensions:
                return FileMatch(
                    violation_type=FileViolationType.BLOCKED_EXTENSION,
                    path=path,
                    resolved_path=None,
                    pattern_matched=f"not_in_allowed:{ext}",
                )

        return None

    def _check_sensitive_patterns(self, path: str) -> FileMatch | None:
        """Check if path matches sensitive file patterns."""
        normalized = path.replace("\\", "/")
        filename = Path(path).name.lower()
        path_parts = normalized.lower().split("/")

        for pattern in self.config.sensitive_patterns:
            pattern_lower = pattern.lower()
            # Check filename match
            if fnmatch.fnmatch(filename, pattern_lower):
                return FileMatch(
                    violation_type=FileViolationType.SENSITIVE_FILE,
                    path=path,
                    resolved_path=None,
                    pattern_matched=pattern,
                )
            # Check if pattern appears in any path segment
            for part in path_parts:
                if fnmatch.fnmatch(part, pattern_lower):
                    return FileMatch(
                        violation_type=FileViolationType.SENSITIVE_FILE,
                        path=path,
                        resolved_path=None,
                        pattern_matched=pattern,
                    )
        return None

    def _is_under_base(self, path: str) -> bool:
        """Check if path is under base directory."""
        if not self.config.base_directory:
            return True

        try:
            base = Path(self.config.base_directory).resolve()
            target = Path(path)
            if target.is_absolute():
                target = target.resolve()
            else:
                target = (base / target).resolve()
            return str(target).startswith(str(base))
        except (OSError, ValueError):
            return not self.config.fail_closed

    def _is_in_allowlist(self, path: str) -> bool:
        """Check if path is in allowlist."""
        if not self.config.allowed_paths:
            return False

        try:
            target = Path(path)
            if not target.is_absolute():
                return False
            target = target.resolve()

            for allowed in self.config.allowed_paths:
                allowed_path = Path(allowed).resolve()
                if str(target).startswith(str(allowed_path)):
                    return True
        except (OSError, ValueError):
            pass
        return False

    def _check_blocklist(self, path: str) -> FileMatch | None:
        """Check if path is in blocklist."""
        if not self.config.blocked_paths:
            return None

        try:
            target = Path(path)
            if target.is_absolute():
                target = target.resolve()

            for blocked in self.config.blocked_paths:
                blocked_path = Path(blocked)
                if blocked_path.is_absolute():
                    blocked_path = blocked_path.resolve()
                if str(target).startswith(str(blocked_path)):
                    return FileMatch(
                        violation_type=FileViolationType.IN_BLOCKLIST,
                        path=path,
                        resolved_path=str(target),
                        pattern_matched=blocked,
                    )
        except (OSError, ValueError):
            pass
        return None

    def _check_file_size(self, path: str) -> FileMatch | None:
        """Check if file size exceeds maximum."""
        try:
            p = Path(path)
            if p.exists() and p.is_file():
                size = p.stat().st_size
                if size > self.config.max_file_size:
                    return FileMatch(
                        violation_type=FileViolationType.FILE_SIZE_EXCEEDED,
                        path=path,
                        resolved_path=None,
                        pattern_matched=f"size:{size}>{self.config.max_file_size}",
                    )
        except (OSError, ValueError):
            pass
        return None

    def _create_block_result(
        self,
        path: str,
        normalized_path: str,
        resolved_path: str | None,
        findings: list[FileMatch],
        reason: str,
        rule: str,
        start_time: float,
    ) -> FileResult:
        """Create a blocked result."""
        return FileResult(
            verdict=create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=reason,
                rule=rule,
                details={
                    "path": path,
                    "normalized_path": normalized_path,
                    "resolved_path": resolved_path,
                    "violation_count": len(findings),
                },
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_path=path,
            normalized_path=normalized_path,
            resolved_path=resolved_path,
            findings=findings,
        )

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# Convenience functions


def check_file(
    path: str,
    mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist",
    base_directory: str | None = None,
    allowed_paths: list[str] | None = None,
    blocked_paths: list[str] | None = None,
) -> bool:
    """
    Quick check if a file path is safe to access.

    Args:
        path: File path to check
        mode: Inspection mode (default: allowlist)
        base_directory: Root directory constraint
        allowed_paths: Explicitly allowed directories
        blocked_paths: Explicitly blocked directories

    Returns:
        True if path is safe, False if blocked

    Example:
        >>> if check_file("/app/data/file.txt", base_directory="/app"):
        ...     process_file(path)
        ... else:
        ...     raise SecurityError("File access blocked")
    """
    inspector = FileInspector(
        mode=mode,
        base_directory=base_directory,
        allowed_paths=set(allowed_paths) if allowed_paths else None,
        blocked_paths=set(blocked_paths) if blocked_paths else None,
    )
    result = inspector.inspect(path)
    return result.is_safe


def inspect_file(
    path: str,
    mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist",
    base_directory: str | None = None,
    allowed_paths: list[str] | None = None,
    blocked_paths: list[str] | None = None,
    blocked_extensions: list[str] | None = None,
    sensitive_patterns: list[str] | None = None,
) -> FileResult:
    """
    Inspect a file path and get full result details.

    Use this when you need the audit trail or detailed violation info.

    Args:
        path: File path to inspect
        mode: Inspection mode
        base_directory: Root directory constraint
        allowed_paths: Explicitly allowed directories
        blocked_paths: Explicitly blocked directories
        blocked_extensions: File extensions to block
        sensitive_patterns: Glob patterns for sensitive files

    Returns:
        FileResult with verdict and violation details

    Example:
        >>> result = inspect_file("../../../etc/passwd")
        >>> if not result.is_safe:
        ...     logger.warning(result.to_audit_log())
        ...     raise SecurityError(result.verdict.reason)
    """
    inspector = FileInspector(
        mode=mode,
        base_directory=base_directory,
        allowed_paths=set(allowed_paths) if allowed_paths else None,
        blocked_paths=set(blocked_paths) if blocked_paths else None,
        blocked_extensions=set(blocked_extensions) if blocked_extensions else None,
        sensitive_patterns=set(sensitive_patterns) if sensitive_patterns else None,
    )
    return inspector.inspect(path)
