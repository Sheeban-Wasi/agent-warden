# ruff: noqa: I001
"""
Tests for the File Inspector.

Tests verify:
- Path traversal detection (../, encoded variants, null bytes)
- Symlink attack prevention
- Sensitive file pattern blocking
- Cloud metadata protection
- Extension filtering
- Allowlist/blocklist modes
- Cross-platform path handling
"""

import os
import tempfile
from pathlib import Path

import pytest

from warden import (
    FileInspector,
    FileMatch,
    FileMode,
    FileResult,
    FileViolationType,
    check_file,
    inspect_file,
)
from warden.integrations.strands import guard
from warden.exceptions import PolicyViolation


class TestPathTraversalDetection:
    """Test path traversal attack detection."""

    @pytest.mark.parametrize(
        "path",
        [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "foo/../../../etc/passwd",
            "foo/bar/../../../etc/passwd",
            "..%2f..%2f..%2fetc/passwd",
            "..%5c..%5c..%5cwindows\\system32",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "....//....//etc/passwd",
            "../",
            "..\\",
        ],
    )
    def test_traversal_patterns_blocked(self, path):
        """Various path traversal patterns must be blocked."""
        result = inspect_file(path)
        assert not result.is_safe
        assert FileViolationType.PATH_TRAVERSAL in result.violation_types

    def test_safe_relative_path_allowed(self):
        """Normal relative paths without traversal should be allowed."""
        result = inspect_file("data/file.txt", mode="blocklist")
        assert result.is_safe

    def test_safe_absolute_path_allowed(self):
        """Normal absolute paths should be allowed in blocklist mode."""
        result = inspect_file("/app/data/file.txt", mode="blocklist")
        assert result.is_safe


class TestNullByteDetection:
    """Test null byte injection detection."""

    @pytest.mark.parametrize(
        "path",
        [
            "file.txt\x00.jpg",
            "file.txt%00.jpg",
            "/etc/passwd\x00.png",
        ],
    )
    def test_null_byte_patterns_blocked(self, path):
        """Null byte injections must be blocked."""
        result = inspect_file(path)
        assert not result.is_safe
        assert FileViolationType.NULL_BYTE in result.violation_types


class TestCloudMetadataBlocking:
    """Test cloud metadata endpoint blocking."""

    @pytest.mark.parametrize(
        "path",
        [
            "http://169.254.169.254/latest/meta-data/",
            "169.254.169.254/user-data",
            "http://100.100.100.200/latest/meta-data",
            "metadata.google.internal/computeMetadata",
        ],
    )
    def test_cloud_metadata_blocked(self, path):
        """Cloud metadata endpoints must be blocked."""
        result = inspect_file(path)
        assert not result.is_safe
        assert FileViolationType.CLOUD_METADATA in result.violation_types

    def test_cloud_metadata_blocking_can_be_disabled(self):
        """Cloud metadata blocking can be disabled."""
        inspector = FileInspector(block_cloud_metadata=False, mode="blocklist")
        result = inspector.inspect("169.254.169.254/meta-data")
        assert result.is_safe


class TestSensitiveFilePatterns:
    """Test sensitive file pattern detection."""

    @pytest.mark.parametrize(
        "path",
        [
            "/app/.env",
            "/app/.env.local",
            "/home/user/.ssh/id_rsa",
            "/project/.git/config",
            "/app/credentials.json",
            "/app/secrets.yaml",
            "/.aws/credentials",
            "/home/.netrc",
            "/app/.htpasswd",
        ],
    )
    def test_sensitive_patterns_blocked(self, path):
        """Sensitive file patterns must be blocked."""
        result = inspect_file(path)
        assert not result.is_safe
        assert FileViolationType.SENSITIVE_FILE in result.violation_types

    def test_custom_sensitive_patterns(self):
        """Custom sensitive patterns work."""
        inspector = FileInspector(
            sensitive_patterns={"my_secret_*"},
            mode="blocklist",
        )
        result = inspector.inspect("/app/my_secret_file.txt")
        assert not result.is_safe


class TestExtensionFiltering:
    """Test file extension filtering."""

    @pytest.mark.parametrize(
        "path",
        [
            "/app/secrets.env",
            "/app/key.pem",
            "/app/server.key",
            "/app/cert.p12",
            "/app/store.pfx",
            "/app/store.jks",
        ],
    )
    def test_blocked_extensions(self, path):
        """Blocked extensions must be rejected."""
        result = inspect_file(path)
        assert not result.is_safe
        assert FileViolationType.BLOCKED_EXTENSION in result.violation_types

    def test_custom_blocked_extensions(self):
        """Custom blocked extensions work."""
        inspector = FileInspector(
            blocked_extensions={".secret", ".private"},
            mode="blocklist",
        )
        result = inspector.inspect("/app/data.secret")
        assert not result.is_safe

    def test_allowed_extensions(self):
        """Only allowed extensions should pass when configured."""
        inspector = FileInspector(
            allowed_extensions={".txt", ".md", ".csv"},
            mode="blocklist",
        )
        result = inspector.inspect("/app/data.txt")
        assert result.is_safe

        result = inspector.inspect("/app/data.exe")
        assert not result.is_safe


class TestModeStrict:
    """Test strict mode behavior."""

    def test_not_in_allowlist_blocked(self):
        """Paths not in strict allowlist blocked."""
        inspector = FileInspector(
            mode="strict",
            allowed_paths={"/app/allowed"},
        )
        result = inspector.inspect("/app/other/file.txt")
        assert not result.is_safe
        assert FileViolationType.OUTSIDE_ALLOWLIST in result.violation_types

    def test_in_allowlist_allowed(self):
        """Paths in allowlist allowed in strict mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            allowed_dir = Path(tmpdir) / "allowed"
            allowed_dir.mkdir()
            test_file = allowed_dir / "file.txt"
            test_file.write_text("test")

            inspector = FileInspector(
                mode="strict",
                allowed_paths={str(allowed_dir)},
            )
            result = inspector.inspect(str(test_file))
            assert result.is_safe


class TestModeAllowlist:
    """Test allowlist mode behavior."""

    def test_blocklist_checked(self):
        """Blocklist is checked in allowlist mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            blocked_dir = Path(tmpdir) / "blocked"
            blocked_dir.mkdir()
            test_file = blocked_dir / "file.txt"
            test_file.write_text("test")

            inspector = FileInspector(
                mode="allowlist",
                blocked_paths={str(blocked_dir)},
            )
            result = inspector.inspect(str(test_file))
            assert not result.is_safe


class TestModeBlocklist:
    """Test blocklist mode behavior."""

    def test_only_blocklist_checked(self):
        """Only blocklist is checked in blocklist mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            blocked_dir = Path(tmpdir) / "blocked"
            blocked_dir.mkdir()
            test_file = blocked_dir / "file.txt"
            test_file.write_text("test")

            inspector = FileInspector(
                mode="blocklist",
                blocked_paths={str(blocked_dir)},
            )

            # Allowed path
            allowed_file = Path(tmpdir) / "allowed.txt"
            allowed_file.write_text("test")
            result = inspector.inspect(str(allowed_file))
            assert result.is_safe

            # Blocked path
            result = inspector.inspect(str(test_file))
            assert not result.is_safe


class TestModeMonitor:
    """Test monitor mode behavior."""

    def test_monitor_allows_sensitive_files(self):
        """Monitor mode logs sensitive files but doesn't block them."""
        inspector = FileInspector(mode="monitor")
        # Note: Path traversal is ALWAYS blocked for security reasons,
        # but sensitive file patterns are allowed in monitor mode
        result = inspector.inspect("/app/.env")
        # Monitor mode allows sensitive file access (logs but doesn't block)
        assert result.is_safe

    def test_monitor_still_blocks_critical(self):
        """Monitor mode still blocks critical security issues like path traversal."""
        inspector = FileInspector(mode="monitor")
        result = inspector.inspect("../../../etc/passwd")
        # Path traversal is still blocked even in monitor mode
        assert not result.is_safe


class TestBaseDirectoryConstraint:
    """Test base directory constraints."""

    def test_escape_base_blocked(self):
        """Paths escaping base directory blocked."""
        inspector = FileInspector(base_directory="/app", mode="blocklist")
        result = inspector.inspect("/etc/passwd")
        assert not result.is_safe
        assert FileViolationType.OUTSIDE_ALLOWLIST in result.violation_types

    def test_under_base_allowed(self):
        """Paths under base directory allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "data" / "file.txt"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text("test")

            inspector = FileInspector(base_directory=tmpdir, mode="blocklist")
            result = inspector.inspect(str(test_file))
            assert result.is_safe


class TestCrossPlatformPaths:
    """Test cross-platform path handling."""

    def test_windows_backslash_normalized(self):
        """Windows backslashes handled correctly."""
        result = inspect_file("C:\\Users\\test\\file.txt", mode="blocklist")
        assert "/" in result.normalized_path or "\\" in result.normalized_path

    def test_mixed_separators_normalized(self):
        """Mixed path separators normalized."""
        result = inspect_file("/app\\data/file.txt", mode="blocklist")
        assert result.normalized_path is not None


class TestEmptyPath:
    """Test empty path handling."""

    def test_empty_path_blocked(self):
        """Empty paths are blocked."""
        result = inspect_file("")
        assert not result.is_safe
        assert FileViolationType.EMPTY_PATH in result.violation_types

    def test_whitespace_path_blocked(self):
        """Whitespace-only paths are blocked."""
        result = inspect_file("   ")
        assert not result.is_safe


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_check_file_returns_bool(self):
        """check_file returns boolean."""
        assert check_file("/app/data/file.txt", mode="blocklist") is True
        assert check_file("../../../etc/passwd") is False

    def test_inspect_file_returns_result(self):
        """inspect_file returns FileResult."""
        result = inspect_file("/app/data/file.txt", mode="blocklist")
        assert isinstance(result, FileResult)
        assert result.original_path == "/app/data/file.txt"

    def test_check_file_with_base_directory(self):
        """check_file works with base_directory."""
        assert check_file("/app/data/file.txt", base_directory="/app") is True
        assert check_file("/etc/passwd", base_directory="/app") is False


class TestFileResult:
    """Test FileResult properties."""

    def test_is_safe_property(self):
        """is_safe property works correctly."""
        result = inspect_file("/app/data/file.txt", mode="blocklist")
        assert result.is_safe is True

        result = inspect_file("../../../etc/passwd")
        assert result.is_safe is False

    def test_violation_types_property(self):
        """violation_types property works correctly."""
        result = inspect_file("../../../etc/passwd")
        assert FileViolationType.PATH_TRAVERSAL in result.violation_types

    def test_to_audit_log(self):
        """to_audit_log produces valid output."""
        result = inspect_file("../../../etc/passwd")
        audit = result.to_audit_log()

        assert "event_id" in audit
        assert "timestamp" in audit
        assert "verdict" in audit
        assert "file_findings" in audit
        assert "paths" in audit


class TestPerformance:
    """Test performance requirements."""

    def test_latency_under_50ms(self):
        """Inspection should complete under 50ms."""
        paths = [
            "/app/data/file.txt",
            "../../../etc/passwd",
            "/home/user/.ssh/id_rsa",
        ]
        for path in paths:
            result = inspect_file(path)
            assert result.verdict.latency_ms < 50


class TestGuardIntegration:
    """Test @guard decorator integration."""

    def test_guard_with_file_access(self):
        """@guard decorator blocks file access violations."""

        @guard(sql=False, file_access=True, on_block="raise")
        def read_file(path: str) -> str:
            return "file contents"

        with pytest.raises(PolicyViolation):
            read_file("../../../etc/passwd")

    def test_guard_allows_safe_paths(self):
        """@guard decorator allows safe file paths."""

        @guard(sql=False, file_access=True, file_mode="blocklist", on_block="raise")
        def read_file(path: str) -> str:
            return "file contents"

        result = read_file("/app/data/file.txt")
        assert result == "file contents"

    def test_guard_with_base_directory(self):
        """@guard decorator respects base_directory."""
        with tempfile.TemporaryDirectory() as tmpdir:

            @guard(
                sql=False,
                file_access=True,
                file_base_directory=tmpdir,
                on_block="raise",
            )
            def read_file(path: str) -> str:
                return "file contents"

            # Path outside base should fail
            with pytest.raises(PolicyViolation):
                read_file("/etc/passwd")


class TestSymlinkProtection:
    """Test symlink attack prevention."""

    @pytest.mark.skipif(os.name == "nt", reason="Symlinks require admin on Windows")
    def test_symlink_to_sensitive_blocked(self):
        """Symlinks to sensitive files blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)
            sensitive = Path("/etc/passwd")
            link = base / "link"

            try:
                link.symlink_to(sensitive)
            except (OSError, PermissionError):
                pytest.skip("Cannot create symlink")

            inspector = FileInspector(
                base_directory=str(base),
                follow_symlinks=False,
            )
            result = inspector.inspect(str(link))
            # Should block because symlink points outside base
            assert not result.is_safe


class TestFileInspectorConfig:
    """Test FileInspector configuration."""

    def test_default_config(self):
        """Default configuration is sensible."""
        inspector = FileInspector()
        assert inspector.config.mode == FileMode.ALLOWLIST
        assert inspector.config.block_cloud_metadata is True
        assert inspector.config.follow_symlinks is False
        assert inspector.config.fail_closed is True

    def test_string_mode_conversion(self):
        """String mode is converted to enum."""
        inspector = FileInspector(mode="strict")
        assert inspector.config.mode == FileMode.STRICT

    def test_custom_config(self):
        """Custom configuration is applied."""
        inspector = FileInspector(
            mode="blocklist",
            base_directory="/app",
            blocked_paths={"/app/secrets"},
            max_file_size=1024,
        )
        assert inspector.config.mode == FileMode.BLOCKLIST
        assert inspector.config.base_directory == "/app"
        assert "/app/secrets" in inspector.config.blocked_paths
        assert inspector.config.max_file_size == 1024
