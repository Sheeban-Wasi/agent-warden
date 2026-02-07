# ruff: noqa: I001
"""
RAG Inspector - Enterprise-grade RAG document security guard.

Filters retrieved documents before they reach the LLM using ABAC
(Attribute-Based Access Control) at the retrieval layer. Works with
ANY vector database without requiring adapters.

Security Layers:
1. Collection Access Control - Allow/block collections
2. Document Metadata Filtering - Classification, department, tenant
3. Content Security Scanning - PII, secrets, prompt injection
4. Output Constraints - Max documents, max length

Attack Vectors Addressed:
- Semantic Exfiltration (queries retrieving sensitive docs via similarity)
- Prompt Injection in Content (malicious instructions in retrieved docs)
- Cross-Tenant Leakage (multi-tenant systems sharing indices)
- Classification Bypass (accessing docs above clearance level)
- Confused Deputy Attacks (agent tricked into accessing restricted resources)
- Horizontal Movement (agent escaping workspace scope)

Example:
    from warden.core.inspectors.rag import RAGInspector, check_rag_documents

    # Quick filter
    safe_docs = check_rag_documents(
        documents,
        allowed_collections=["public_docs"],
        classification_max="internal",
    )

    # Full inspection with ABAC context
    inspector = RAGInspector(
        allowed_collections={"public_docs"},
        classification_max="internal",
        scan_pii=True,
    )
    context = RAGContext(agent_id="analytics-bot", tenant_id="acme-corp")
    result = inspector.inspect(documents, context)
    result.allowed_documents  # Safe to pass to LLM
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict
from warden.core.inspectors.pii import PIIInspector, PIIStrategy


# =============================================================================
# ENUMS
# =============================================================================


class RAGMode(Enum):
    """Operating mode for RAG Guard."""

    STRICT = "strict"  # Block on any violation, fail closed
    FILTERED = "filtered"  # Filter out violating docs, pass allowed ones
    MONITOR = "monitor"  # Log only, don't block


class RAGViolationType(Enum):
    """Types of RAG access violations."""

    # Access Control Violations
    COLLECTION_BLOCKED = "collection_blocked"
    COLLECTION_NOT_ALLOWED = "collection_not_allowed"
    CLASSIFICATION_DENIED = "classification_denied"
    METADATA_FILTER_FAILED = "metadata_filter_failed"
    DOCUMENT_EXPIRED = "document_expired"

    # Identity & Tenant Violations
    TENANT_MISMATCH = "tenant_mismatch"
    AGENT_SCOPE_EXCEEDED = "agent_scope_exceeded"
    WORKSPACE_BOUNDARY_CROSSED = "workspace_boundary"

    # Content Security Violations
    PII_DETECTED = "pii_detected"
    SECRET_DETECTED = "secret_detected"
    PROMPT_INJECTION = "prompt_injection"
    CONTENT_BLOCKED = "content_blocked"

    # Structural Violations
    MISSING_REQUIRED_METADATA = "missing_required_metadata"
    MAX_DOCUMENTS_EXCEEDED = "max_documents_exceeded"
    MAX_LENGTH_EXCEEDED = "max_length_exceeded"
    EMPTY_DOCUMENT = "empty_document"

    # Behavioral Anomalies (monitor/alert, not block by default)
    CLASSIFICATION_ESCALATION = "classification_escalation"
    CROSS_DEPARTMENT_SPIKE = "cross_department_spike"
    VOLUME_ANOMALY = "volume_anomaly"


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class RAGDocument:
    """
    Standard document format for RAG Guard.

    Works with any vector DB - user converts their format to this.

    Attributes:
        content: The document text content
        metadata: Document metadata (collection, classification, etc.)
    """

    content: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RAGDocument:
        """Create from dict (common vector DB return format)."""
        content = d.get("content") or d.get("text") or d.get("page_content", "")
        metadata = d.get("metadata", {})
        # If metadata fields are at top level, include them
        for key in ["collection", "classification", "department", "tenant_id", "id"]:
            if key in d and key not in metadata:
                metadata[key] = d[key]
        return cls(content=content, metadata=metadata)

    @classmethod
    def from_langchain(cls, doc: Any) -> RAGDocument:
        """Create from LangChain Document."""
        return cls(content=doc.page_content, metadata=doc.metadata)

    def to_dict(self) -> dict[str, Any]:
        """Convert back to dict format."""
        return {"content": self.content, "metadata": self.metadata}


@dataclass
class RAGContext:
    """
    ABAC context for access control decisions.

    Contains the "Subject" and "Environment" attributes for ABAC evaluation.
    Passed to inspect() to enable identity-centric controls.

    This prevents horizontal movement - an agent cannot access resources
    outside its designated scope, even if semantically similar documents exist.
    """

    # Subject attributes (WHO is requesting)
    agent_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    session_id: str | None = None

    # Clearance & permissions
    clearance: str = "public"
    departments: set[str] | None = None
    roles: set[str] | None = None

    # Workspace isolation (prevents horizontal movement)
    workspace: str | None = None
    allowed_collections: set[str] | None = None

    # Environment attributes
    timestamp: str | None = None
    request_id: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RAGContext:
        """Create from dict."""
        return cls(
            agent_id=d.get("agent_id"),
            user_id=d.get("user_id"),
            tenant_id=d.get("tenant_id"),
            session_id=d.get("session_id"),
            clearance=d.get("clearance", "public"),
            departments=set(d["departments"]) if d.get("departments") else None,
            roles=set(d["roles"]) if d.get("roles") else None,
            workspace=d.get("workspace"),
            allowed_collections=(
                set(d["allowed_collections"]) if d.get("allowed_collections") else None
            ),
            timestamp=d.get("timestamp"),
            request_id=d.get("request_id"),
        )


@dataclass
class RAGMatch:
    """A single violation found in a document."""

    violation_type: RAGViolationType
    document_id: str | None
    field: str | None
    expected: Any
    actual: Any
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict for audit logging."""
        return {
            "violation_type": self.violation_type.value,
            "document_id": self.document_id,
            "field": self.field,
            "expected": str(self.expected) if self.expected else None,
            "actual": str(self.actual) if self.actual else None,
            "message": self.message,
        }


@dataclass
class RAGResult:
    """
    Result of RAG document inspection.

    Contains allowed/blocked documents and full audit trail.

    Attributes:
        verdict: The security verdict (PASS or BLOCK)
        allowed_documents: Documents safe to pass to LLM
        blocked_documents: Documents filtered out
        findings: List of violations found
    """

    verdict: Verdict
    allowed_documents: list[RAGDocument]
    blocked_documents: list[RAGDocument]
    findings: list[RAGMatch] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if any documents are allowed."""
        return len(self.allowed_documents) > 0 or len(self.blocked_documents) == 0

    @property
    def all_blocked(self) -> bool:
        """Check if all documents were blocked."""
        return len(self.allowed_documents) == 0 and len(self.blocked_documents) > 0

    @property
    def violation_types(self) -> set[RAGViolationType]:
        """Get set of violation types found."""
        return {f.violation_type for f in self.findings}

    def to_audit_log(self) -> dict[str, Any]:
        """Convert to audit log format."""
        log = self.verdict.to_audit_log()
        log["rag_findings"] = [f.to_dict() for f in self.findings]
        log["documents_allowed"] = len(self.allowed_documents)
        log["documents_blocked"] = len(self.blocked_documents)
        return log


# =============================================================================
# CONSTANTS
# =============================================================================

# Classification hierarchy (lower is less sensitive)
DEFAULT_CLASSIFICATION_LEVELS: dict[str, int] = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "top_secret": 4,
}

# Default secret patterns to detect in content
DEFAULT_SECRET_PATTERNS: list[str] = [
    r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w-]{20,}",
    r"(?i)api[_-]?secret\s*[=:]\s*['\"]?[\w-]{20,}",
    r"Bearer\s+[\w\-_.]+",
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
    r"-----BEGIN\s+CERTIFICATE-----",
    r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{6,}",
    r"(?i)secret\s*[=:]\s*['\"]?[^\s'\"]{6,}",
    r"(?i)token\s*[=:]\s*['\"]?[\w\-_.]{20,}",
    r"(?i)aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['\"]?[A-Z0-9]{16,}",
    r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['\"]?[\w/+=]{30,}",
]

# Default prompt injection patterns to detect in content
DEFAULT_PROMPT_INJECTION_PATTERNS: list[str] = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions?",
    r"(?i)ignore\s+(all\s+)?prior\s+instructions?",
    r"(?i)disregard\s+(all\s+)?(previous|prior|above)",
    r"(?i)you\s+are\s+now\s+(in\s+)?\w+\s+mode",
    r"(?i)new\s+instructions?:",
    r"\[SYSTEM\]",
    r"\[ADMIN\]",
    r"(?i)system\s+prompt",
    r"(?i)forget\s+(everything|all|your\s+instructions?)",
    r"(?i)override\s+(previous\s+)?instructions?",
    r"(?i)jailbreak",
    r"(?i)DAN\s+mode",
    r"(?i)pretend\s+you\s+are",
    r"(?i)act\s+as\s+if\s+you",
]


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class ContentSecurityConfig:
    """Configuration for content security scanning."""

    # PII settings
    pii_enabled: bool = True
    pii_strategy: str = "redact"
    pii_types: list[str] | None = None

    # Secret detection
    secrets_enabled: bool = True
    secret_patterns: list[str] | None = None

    # Prompt injection detection
    prompt_injection_enabled: bool = True
    prompt_injection_patterns: list[str] | None = None


@dataclass
class RAGInspectorConfig:
    """Configuration for the RAG Inspector."""

    mode: RAGMode = RAGMode.FILTERED
    allowed_collections: set[str] | None = None
    blocked_collections: set[str] | None = None
    document_filters: list[dict[str, Any]] | None = None
    classification_hierarchy: dict[str, int] | None = None
    classification_max: str | None = None
    content_security: ContentSecurityConfig = field(
        default_factory=ContentSecurityConfig
    )
    max_documents: int = 20
    max_total_length: int = 100000
    require_metadata: list[str] | None = None
    fail_closed: bool = True


# =============================================================================
# RAG INSPECTOR
# =============================================================================


class RAGInspector:
    """
    RAG document security inspector.

    Filters retrieved documents based on:
    - Collection access control
    - Document metadata (classification, department, etc.)
    - Content security (PII, secrets, prompt injection)
    - Output constraints

    Works with ANY vector database - user converts results to RAGDocument format.

    Example:
        >>> inspector = RAGInspector(
        ...     allowed_collections={"public_docs"},
        ...     classification_max="internal",
        ...     scan_pii=True,
        ... )
        >>> result = inspector.inspect(documents)
        >>> result.allowed_documents  # Safe to pass to LLM
        >>> result.blocked_documents  # Filtered out
    """

    INSPECTOR_NAME = "rag_inspector"

    def __init__(
        self,
        mode: RAGMode | str = RAGMode.FILTERED,
        allowed_collections: set[str] | None = None,
        blocked_collections: set[str] | None = None,
        document_filters: list[dict[str, Any]] | None = None,
        classification_hierarchy: dict[str, int] | list[str] | None = None,
        classification_max: str | None = None,
        scan_pii: bool = True,
        pii_strategy: str = "redact",
        pii_types: list[str] | None = None,
        scan_secrets: bool = True,
        secret_patterns: list[str] | None = None,
        scan_prompt_injection: bool = True,
        prompt_injection_patterns: list[str] | None = None,
        max_documents: int = 20,
        max_total_length: int = 100000,
        require_metadata: list[str] | None = None,
        fail_closed: bool = True,
    ) -> None:
        # Convert string mode to enum
        if isinstance(mode, str):
            mode = RAGMode(mode)

        # Convert classification hierarchy from list to dict if needed
        if isinstance(classification_hierarchy, list):
            classification_hierarchy = {
                level: i for i, level in enumerate(classification_hierarchy)
            }

        # Build config
        content_security = ContentSecurityConfig(
            pii_enabled=scan_pii,
            pii_strategy=pii_strategy,
            pii_types=pii_types,
            secrets_enabled=scan_secrets,
            secret_patterns=secret_patterns,
            prompt_injection_enabled=scan_prompt_injection,
            prompt_injection_patterns=prompt_injection_patterns,
        )

        self.config = RAGInspectorConfig(
            mode=mode,
            allowed_collections=allowed_collections,
            blocked_collections=blocked_collections,
            document_filters=document_filters,
            classification_hierarchy=classification_hierarchy,
            classification_max=classification_max,
            content_security=content_security,
            max_documents=max_documents,
            max_total_length=max_total_length,
            require_metadata=require_metadata,
            fail_closed=fail_closed,
        )

        # Initialize PII inspector if enabled
        self._pii_inspector: PIIInspector | None = None
        if scan_pii:
            strategy = PIIStrategy(pii_strategy)
            self._pii_inspector = PIIInspector(
                strategy=strategy,
                detect_types=pii_types,
            )

        # Compile secret patterns
        self._secret_patterns: list[re.Pattern[str]] = []
        if scan_secrets:
            patterns = secret_patterns or DEFAULT_SECRET_PATTERNS
            self._secret_patterns = [re.compile(p) for p in patterns]

        # Compile prompt injection patterns
        self._prompt_injection_patterns: list[re.Pattern[str]] = []
        if scan_prompt_injection:
            patterns = prompt_injection_patterns or DEFAULT_PROMPT_INJECTION_PATTERNS
            self._prompt_injection_patterns = [re.compile(p) for p in patterns]

    def inspect(
        self,
        documents: list[dict[str, Any]] | list[RAGDocument],
        context: RAGContext | dict[str, Any] | None = None,
    ) -> RAGResult:
        """
        Inspect and filter retrieved documents.

        Args:
            documents: Retrieved documents (dicts or RAGDocument objects)
            context: Optional ABAC context for dynamic filtering

        Returns:
            RAGResult with allowed/blocked documents and audit trail
        """
        start_time = time.perf_counter()

        # Convert context if needed
        if isinstance(context, dict):
            context = RAGContext.from_dict(context)

        # Convert documents to RAGDocument format
        docs = self._normalize_documents(documents)

        # Handle empty input
        if not docs:
            return RAGResult(
                verdict=create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason="No documents to inspect",
                    latency_ms=self._elapsed_ms(start_time),
                ),
                allowed_documents=[],
                blocked_documents=[],
                findings=[],
            )

        allowed: list[RAGDocument] = []
        blocked: list[RAGDocument] = []
        all_findings: list[RAGMatch] = []

        # Process each document through security layers
        for doc in docs:
            doc_findings: list[RAGMatch] = []
            doc_blocked = False
            processed_doc = doc

            # Layer 1: Collection Access Control
            finding = self._check_collection(doc, context)
            if finding:
                doc_findings.append(finding)
                doc_blocked = True

            # Layer 2: Document Metadata Filtering (if not already blocked)
            if not doc_blocked:
                findings = self._check_metadata(doc, context)
                if findings:
                    doc_findings.extend(findings)
                    doc_blocked = True

            # Layer 3: Required Metadata Check
            if not doc_blocked:
                finding = self._check_required_metadata(doc)
                if finding:
                    doc_findings.append(finding)
                    doc_blocked = True

            # Layer 4: Content Security Scanning (if not blocked)
            if not doc_blocked:
                processed_doc, findings = self._scan_content(doc)
                if findings:
                    doc_findings.extend(findings)
                    # For content issues, check if we should block or just transform
                    for f in findings:
                        if f.violation_type in {
                            RAGViolationType.SECRET_DETECTED,
                            RAGViolationType.PROMPT_INJECTION,
                        }:
                            doc_blocked = True
                            break
                        if f.violation_type == RAGViolationType.PII_DETECTED:
                            if self.config.content_security.pii_strategy == "block":
                                doc_blocked = True
                                break

            # Add to appropriate list
            if doc_blocked:
                blocked.append(doc)
            else:
                allowed.append(processed_doc)

            all_findings.extend(doc_findings)

        # Layer 5: Output Constraints
        if allowed:
            allowed, constraint_findings = self._apply_output_constraints(allowed)
            all_findings.extend(constraint_findings)

        # Build verdict
        if self.config.mode == RAGMode.STRICT and blocked:
            # Strict mode: block if any violations
            verdict = create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Documents blocked: {len(blocked)} violation(s)",
                rule="strict_mode_violation",
                details={
                    "blocked_count": len(blocked),
                    "violation_types": list({f.violation_type.value for f in all_findings}),
                },
                latency_ms=self._elapsed_ms(start_time),
            )
        elif self.config.mode == RAGMode.MONITOR:
            # Monitor mode: always pass, just log
            verdict = create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Monitor mode: {len(all_findings)} finding(s) logged",
                latency_ms=self._elapsed_ms(start_time),
            )
            # In monitor mode, don't actually block
            allowed = self._normalize_documents(documents)
            blocked = []
        else:
            # Filtered mode: pass with allowed docs
            if allowed:
                verdict = create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Passed {len(allowed)} document(s), blocked {len(blocked)}",
                    latency_ms=self._elapsed_ms(start_time),
                )
            else:
                verdict = create_block_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason="All documents blocked",
                    rule="all_documents_blocked",
                    details={
                        "blocked_count": len(blocked),
                        "violation_types": list({f.violation_type.value for f in all_findings}),
                    },
                    latency_ms=self._elapsed_ms(start_time),
                )

        return RAGResult(
            verdict=verdict,
            allowed_documents=allowed,
            blocked_documents=blocked,
            findings=all_findings,
        )

    def _normalize_documents(
        self, documents: list[dict[str, Any]] | list[RAGDocument]
    ) -> list[RAGDocument]:
        """Convert documents to RAGDocument format."""
        result: list[RAGDocument] = []
        for doc in documents:
            if isinstance(doc, RAGDocument):
                result.append(doc)
            else:
                result.append(RAGDocument.from_dict(doc))
        return result

    def _check_collection(
        self, doc: RAGDocument, context: RAGContext | None
    ) -> RAGMatch | None:
        """Layer 1: Check collection access control."""
        collection = doc.metadata.get("collection")

        # Check blocked collections
        if self.config.blocked_collections and collection in self.config.blocked_collections:
            return RAGMatch(
                violation_type=RAGViolationType.COLLECTION_BLOCKED,
                document_id=doc.metadata.get("id"),
                field="collection",
                expected=f"not in {self.config.blocked_collections}",
                actual=collection,
                message=f"Collection '{collection}' is blocked",
            )

        # Check allowed collections (allowlist mode)
        if self.config.allowed_collections:
            if collection not in self.config.allowed_collections:
                return RAGMatch(
                    violation_type=RAGViolationType.COLLECTION_NOT_ALLOWED,
                    document_id=doc.metadata.get("id"),
                    field="collection",
                    expected=f"in {self.config.allowed_collections}",
                    actual=collection,
                    message=f"Collection '{collection}' not in allowed list",
                )

        # Check context-based collection access
        if context and context.allowed_collections:
            if collection not in context.allowed_collections:
                return RAGMatch(
                    violation_type=RAGViolationType.WORKSPACE_BOUNDARY_CROSSED,
                    document_id=doc.metadata.get("id"),
                    field="collection",
                    expected=f"in workspace {context.workspace}",
                    actual=collection,
                    message=f"Collection '{collection}' outside agent workspace",
                )

        return None

    def _check_metadata(
        self, doc: RAGDocument, context: RAGContext | None
    ) -> list[RAGMatch]:
        """Layer 2: Check document metadata filters."""
        findings: list[RAGMatch] = []

        # Check classification level
        if self.config.classification_max:
            doc_classification = doc.metadata.get("classification", "public")
            hierarchy = self.config.classification_hierarchy or DEFAULT_CLASSIFICATION_LEVELS
            doc_level = hierarchy.get(doc_classification, 999)
            max_level = hierarchy.get(self.config.classification_max, 0)

            if doc_level > max_level:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.CLASSIFICATION_DENIED,
                        document_id=doc.metadata.get("id"),
                        field="classification",
                        expected=f"<= {self.config.classification_max}",
                        actual=doc_classification,
                        message=f"Classification '{doc_classification}' exceeds max '{self.config.classification_max}'",
                    )
                )

        # Check context clearance
        if context and context.clearance:
            doc_classification = doc.metadata.get("classification", "public")
            hierarchy = self.config.classification_hierarchy or DEFAULT_CLASSIFICATION_LEVELS
            doc_level = hierarchy.get(doc_classification, 999)
            clearance_level = hierarchy.get(context.clearance, 0)

            if doc_level > clearance_level:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.CLASSIFICATION_DENIED,
                        document_id=doc.metadata.get("id"),
                        field="classification",
                        expected=f"<= {context.clearance} (user clearance)",
                        actual=doc_classification,
                        message=f"Document classification exceeds user clearance",
                    )
                )

        # Check tenant isolation
        if context and context.tenant_id:
            doc_tenant = doc.metadata.get("tenant_id")
            if doc_tenant and doc_tenant != context.tenant_id:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.TENANT_MISMATCH,
                        document_id=doc.metadata.get("id"),
                        field="tenant_id",
                        expected=context.tenant_id,
                        actual=doc_tenant,
                        message="Cross-tenant document access blocked",
                    )
                )

        # Check department access
        if context and context.departments:
            doc_department = doc.metadata.get("department")
            if doc_department and doc_department not in context.departments:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.AGENT_SCOPE_EXCEEDED,
                        document_id=doc.metadata.get("id"),
                        field="department",
                        expected=f"in {context.departments}",
                        actual=doc_department,
                        message="Document outside agent department scope",
                    )
                )

        # Check document expiry
        expires_at = doc.metadata.get("expires_at")
        if expires_at:
            try:
                if isinstance(expires_at, str):
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                else:
                    expiry = expires_at
                if expiry < datetime.now(timezone.utc):
                    findings.append(
                        RAGMatch(
                            violation_type=RAGViolationType.DOCUMENT_EXPIRED,
                            document_id=doc.metadata.get("id"),
                            field="expires_at",
                            expected="not expired",
                            actual=expires_at,
                            message="Document has expired",
                        )
                    )
            except (ValueError, TypeError):
                pass  # Invalid date format, ignore

        # Check custom document filters
        if self.config.document_filters:
            for filter_config in self.config.document_filters:
                field_name = filter_config.get("field")
                if not field_name:
                    continue

                doc_value = doc.metadata.get(field_name)

                # Check allowed values
                if "allowed" in filter_config:
                    allowed = filter_config["allowed"]
                    if doc_value not in allowed:
                        findings.append(
                            RAGMatch(
                                violation_type=RAGViolationType.METADATA_FILTER_FAILED,
                                document_id=doc.metadata.get("id"),
                                field=field_name,
                                expected=f"in {allowed}",
                                actual=doc_value,
                                message=f"Field '{field_name}' value not in allowed list",
                            )
                        )

                # Check blocked values
                if "blocked" in filter_config:
                    blocked = filter_config["blocked"]
                    if doc_value in blocked:
                        findings.append(
                            RAGMatch(
                                violation_type=RAGViolationType.METADATA_FILTER_FAILED,
                                document_id=doc.metadata.get("id"),
                                field=field_name,
                                expected=f"not in {blocked}",
                                actual=doc_value,
                                message=f"Field '{field_name}' value is blocked",
                            )
                        )

                # Check equals value (with context variable support)
                if "equals" in filter_config:
                    expected_value = filter_config["equals"]
                    # Support template variables like {{user.tenant_id}}
                    if context and isinstance(expected_value, str) and "{{" in expected_value:
                        expected_value = self._resolve_template(expected_value, context)
                    if doc_value != expected_value:
                        findings.append(
                            RAGMatch(
                                violation_type=RAGViolationType.METADATA_FILTER_FAILED,
                                document_id=doc.metadata.get("id"),
                                field=field_name,
                                expected=expected_value,
                                actual=doc_value,
                                message=f"Field '{field_name}' does not match expected value",
                            )
                        )

        return findings

    def _check_required_metadata(self, doc: RAGDocument) -> RAGMatch | None:
        """Check that required metadata fields are present."""
        if not self.config.require_metadata:
            return None

        for field in self.config.require_metadata:
            if field not in doc.metadata or doc.metadata[field] is None:
                return RAGMatch(
                    violation_type=RAGViolationType.MISSING_REQUIRED_METADATA,
                    document_id=doc.metadata.get("id"),
                    field=field,
                    expected="present",
                    actual="missing",
                    message=f"Required metadata field '{field}' is missing",
                )

        return None

    def _scan_content(
        self, doc: RAGDocument
    ) -> tuple[RAGDocument, list[RAGMatch]]:
        """Layer 3: Scan content for security issues."""
        findings: list[RAGMatch] = []
        content = doc.content

        if not content or not content.strip():
            return doc, findings

        # Check for prompt injection patterns
        if self.config.content_security.prompt_injection_enabled:
            for pattern in self._prompt_injection_patterns:
                if pattern.search(content):
                    findings.append(
                        RAGMatch(
                            violation_type=RAGViolationType.PROMPT_INJECTION,
                            document_id=doc.metadata.get("id"),
                            field="content",
                            expected="no prompt injection",
                            actual=pattern.pattern[:50],
                            message="Prompt injection pattern detected in document content",
                        )
                    )
                    # Prompt injection is critical - return immediately
                    return doc, findings

        # Check for secrets
        if self.config.content_security.secrets_enabled:
            for pattern in self._secret_patterns:
                match = pattern.search(content)
                if match:
                    findings.append(
                        RAGMatch(
                            violation_type=RAGViolationType.SECRET_DETECTED,
                            document_id=doc.metadata.get("id"),
                            field="content",
                            expected="no secrets",
                            actual="[SECRET REDACTED]",
                            message="Secret/credential detected in document content",
                        )
                    )
                    # Secrets are critical - return immediately
                    return doc, findings

        # Check for PII
        if self._pii_inspector:
            pii_result = self._pii_inspector.inspect(content)
            if pii_result.has_pii:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.PII_DETECTED,
                        document_id=doc.metadata.get("id"),
                        field="content",
                        expected="no PII",
                        actual=f"{len(pii_result.findings)} PII instance(s)",
                        message=f"PII detected: {', '.join(t.value for t in pii_result.pii_types_found)}",
                    )
                )
                # Apply PII strategy - if redact/mask/hash, transform content
                if self.config.content_security.pii_strategy != "block":
                    content = pii_result.sanitized_text

        # Return potentially transformed document
        if content != doc.content:
            return RAGDocument(content=content, metadata=doc.metadata), findings
        return doc, findings

    def _apply_output_constraints(
        self, docs: list[RAGDocument]
    ) -> tuple[list[RAGDocument], list[RAGMatch]]:
        """Layer 4: Apply output constraints."""
        findings: list[RAGMatch] = []
        result = docs

        # Limit document count
        if len(result) > self.config.max_documents:
            findings.append(
                RAGMatch(
                    violation_type=RAGViolationType.MAX_DOCUMENTS_EXCEEDED,
                    document_id=None,
                    field="count",
                    expected=f"<= {self.config.max_documents}",
                    actual=len(result),
                    message=f"Document count {len(result)} exceeds max {self.config.max_documents}",
                )
            )
            result = result[: self.config.max_documents]

        # Limit total content length
        total_length = 0
        filtered: list[RAGDocument] = []
        for doc in result:
            doc_length = len(doc.content)
            if total_length + doc_length > self.config.max_total_length:
                findings.append(
                    RAGMatch(
                        violation_type=RAGViolationType.MAX_LENGTH_EXCEEDED,
                        document_id=doc.metadata.get("id"),
                        field="total_length",
                        expected=f"<= {self.config.max_total_length}",
                        actual=total_length + doc_length,
                        message="Total content length would exceed maximum",
                    )
                )
                break
            filtered.append(doc)
            total_length += doc_length

        return filtered, findings

    def _resolve_template(self, template: str, context: RAGContext) -> str:
        """Resolve template variables like {{user.tenant_id}}."""
        result = template

        # Map of template variables to context values
        mappings = {
            "{{user.tenant_id}}": context.tenant_id,
            "{{user.user_id}}": context.user_id,
            "{{agent.id}}": context.agent_id,
            "{{agent.agent_id}}": context.agent_id,
            "{{session.id}}": context.session_id,
            "{{context.clearance}}": context.clearance,
            "{{context.workspace}}": context.workspace,
        }

        for var, value in mappings.items():
            if value is not None:
                result = result.replace(var, str(value))

        return result

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def check_rag_documents(
    documents: list[dict[str, Any]],
    allowed_collections: list[str] | None = None,
    blocked_collections: list[str] | None = None,
    classification_max: str = "internal",
    tenant_id: str | None = None,
) -> list[dict[str, Any]]:
    """
    Quick filter of RAG documents.

    Returns only the allowed documents as dicts.

    Args:
        documents: List of document dicts
        allowed_collections: Collections to allow (allowlist mode)
        blocked_collections: Collections to block
        classification_max: Maximum classification level allowed
        tenant_id: Tenant ID for isolation

    Returns:
        List of allowed documents as dicts

    Example:
        safe_docs = check_rag_documents(
            results,
            allowed_collections=["public_docs"],
            classification_max="internal",
        )
    """
    inspector = RAGInspector(
        mode="filtered",
        allowed_collections=set(allowed_collections) if allowed_collections else None,
        blocked_collections=set(blocked_collections) if blocked_collections else None,
        classification_max=classification_max,
    )
    context = RAGContext(tenant_id=tenant_id) if tenant_id else None
    result = inspector.inspect(documents, context)
    return [doc.to_dict() for doc in result.allowed_documents]


def inspect_rag_documents(
    documents: list[dict[str, Any]],
    context: dict[str, Any] | RAGContext | None = None,
    **kwargs: Any,
) -> RAGResult:
    """
    Full inspection with audit trail.

    Args:
        documents: List of document dicts
        context: ABAC context for access control
        **kwargs: Additional RAGInspector configuration

    Returns:
        RAGResult with allowed/blocked documents and findings

    Example:
        result = inspect_rag_documents(
            documents,
            context={"agent_id": "bot", "tenant_id": "acme"},
            allowed_collections=["public"],
            scan_pii=True,
        )
        print(f"Allowed: {len(result.allowed_documents)}")
        print(f"Blocked: {len(result.blocked_documents)}")
    """
    inspector = RAGInspector(**kwargs)
    return inspector.inspect(documents, context)


def filter_rag_documents(
    documents: list[dict[str, Any]],
    agent_id: str | None = None,
    tenant_id: str | None = None,
    clearance: str = "internal",
    allowed_collections: set[str] | None = None,
    scan_pii: bool = True,
    pii_strategy: str = "redact",
) -> list[dict[str, Any]]:
    """
    Filter RAG documents with common enterprise settings.

    Convenience function for typical enterprise use case.

    Args:
        documents: Retrieved documents
        agent_id: Agent making the request
        tenant_id: Tenant for isolation
        clearance: User's clearance level
        allowed_collections: Collections agent can access
        scan_pii: Whether to scan for PII
        pii_strategy: How to handle PII (block, redact, mask, monitor)

    Returns:
        List of safe document dicts

    Example:
        safe_docs = filter_rag_documents(
            vectordb.search(query),
            agent_id="support-bot",
            tenant_id="acme-corp",
            clearance="internal",
        )
    """
    inspector = RAGInspector(
        mode="filtered",
        allowed_collections=allowed_collections,
        classification_max=clearance,
        scan_pii=scan_pii,
        pii_strategy=pii_strategy,
    )
    context = RAGContext(
        agent_id=agent_id,
        tenant_id=tenant_id,
        clearance=clearance,
        allowed_collections=allowed_collections,
    )
    result = inspector.inspect(documents, context)
    return [doc.to_dict() for doc in result.allowed_documents]
