"""
Warden Inspectors - Specialized security analyzers.

Each inspector focuses on one type of threat:
- SQLInspector: AST-based SQL injection detection
- PIIInspector: PII detection and redaction
- FileInspector: File access security (path traversal, sensitive files)
- ShellInspector: Shell command security (dangerous commands, injection)
- ContextInspector: Identity and tenancy verification (coming soon)
"""

from warden.core.inspectors.file import (
    FileInspector,
    FileMatch,
    FileMode,
    FileResult,
    FileViolationType,
    check_file,
    inspect_file,
)
from warden.core.inspectors.pii import (
    PIIInspector,
    PIIMatch,
    PIIResult,
    PIIStrategy,
    PIIType,
    check_pii,
    inspect_pii,
    redact_pii,
)
from warden.core.inspectors.shell import (
    ShellInspector,
    ShellMatch,
    ShellMode,
    ShellResult,
    ShellViolationType,
    check_shell,
    inspect_shell,
)
from warden.core.inspectors.sql import SQLInspector, SQLMode, check_sql, inspect_sql

__all__ = [
    # SQL Inspector
    "SQLInspector",
    "SQLMode",
    "check_sql",
    "inspect_sql",
    # PII Inspector
    "PIIInspector",
    "PIIType",
    "PIIStrategy",
    "PIIMatch",
    "PIIResult",
    "check_pii",
    "inspect_pii",
    "redact_pii",
    # File Inspector
    "FileInspector",
    "FileMode",
    "FileViolationType",
    "FileMatch",
    "FileResult",
    "check_file",
    "inspect_file",
    # Shell Inspector
    "ShellInspector",
    "ShellMode",
    "ShellViolationType",
    "ShellMatch",
    "ShellResult",
    "check_shell",
    "inspect_shell",
]
