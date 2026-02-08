"""
Warden Inspectors - Specialized security analyzers.

Each inspector focuses on one type of threat:
- SQLInspector: AST-based SQL injection detection
- PIIInspector: PII detection and redaction
- FileInspector: File access security (path traversal, sensitive files)
- ShellInspector: Shell command security (dangerous commands, injection)
- RAGInspector: RAG document security (ABAC, content filtering)
- APIInspector: API call security (SSRF, data exfiltration)
- IdentityInspector: Identity-based access control (RBAC, ABAC)
"""

from warden.core.inspectors.api import (
    APIInspector,
    APIMatch,
    APIMode,
    APIRequest,
    APIResult,
    APIViolationType,
    check_api_call,
    inspect_api_call,
)
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
    CustomDetector,
    DetectorMatch,
    FunctionDetector,
    PIIInspector,
    PIIMatch,
    PIIResult,
    PIIStrategy,
    PIIType,
    RegexDetector,
    check_pii,
    create_function_detector,
    create_regex_detector,
    inspect_pii,
    redact_pii,
)
from warden.core.inspectors.rag import (
    RAGContext,
    RAGDocument,
    RAGInspector,
    RAGMatch,
    RAGMode,
    RAGResult,
    RAGViolationType,
    check_rag_documents,
    filter_rag_documents,
    inspect_rag_documents,
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
from warden.core.inspectors.identity import (
    IdentityContext,
    IdentityInspector,
    IdentityMatch,
    IdentityMode,
    IdentityResult,
    IdentityViolationType,
    check_identity,
    create_identity_context,
    inspect_identity,
)
from warden.core.inspectors.sql import SQLInspector, SQLMode, check_sql, inspect_sql

__all__ = [
    # API Inspector
    "APIInspector",
    "APIMode",
    "APIViolationType",
    "APIRequest",
    "APIMatch",
    "APIResult",
    "check_api_call",
    "inspect_api_call",
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
    # PII Custom Detectors
    "CustomDetector",
    "DetectorMatch",
    "RegexDetector",
    "FunctionDetector",
    "create_regex_detector",
    "create_function_detector",
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
    # RAG Inspector
    "RAGInspector",
    "RAGMode",
    "RAGViolationType",
    "RAGDocument",
    "RAGContext",
    "RAGMatch",
    "RAGResult",
    "check_rag_documents",
    "inspect_rag_documents",
    "filter_rag_documents",
    # Identity Inspector
    "IdentityInspector",
    "IdentityMode",
    "IdentityViolationType",
    "IdentityContext",
    "IdentityMatch",
    "IdentityResult",
    "check_identity",
    "inspect_identity",
    "create_identity_context",
]
