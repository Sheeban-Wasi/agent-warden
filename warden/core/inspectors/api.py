# ruff: noqa: I001
"""
API Call Inspector - Prevent data exfiltration and SSRF attacks.

Inspects HTTP requests before they're sent, blocking dangerous patterns
and sanitizing sensitive data.

Security Layers:
1. SSRF Protection - Block private IPs, localhost, cloud metadata endpoints
2. Domain Access Control - Allowlist/blocklist domains
3. Method Restrictions - Control HTTP methods
4. Data Security - Scan URL/body/headers for PII and secrets
5. Protocol Security - Require HTTPS

Attack Vectors Addressed:
- Data Exfiltration (agent sending PII to attacker-controlled endpoints)
- SSRF (Server-Side Request Forgery to internal networks)
- Credential Theft (cloud metadata API access)
- Unauthorized API Calls (calling APIs outside allowed scope)

Example:
    from warden.core.inspectors.api import APIInspector, check_api_call

    # Quick check
    is_safe = check_api_call("https://api.openai.com/v1/chat", allowed_domains=["api.openai.com"])

    # Full inspection
    inspector = APIInspector(
        allowed_domains={"api.openai.com"},
        block_private_ips=True,
        scan_pii=True,
    )
    result = inspector.inspect("https://api.openai.com/v1/chat")
"""

from __future__ import annotations

import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from warden.core.inspectors.pii import PIIInspector, PIIStrategy
from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict


# =============================================================================
# ENUMS
# =============================================================================


class APIMode(Enum):
    """Operating mode for API Call Guard."""

    RESTRICTED = "restricted"  # Only GET/HEAD to allowed domains, HTTPS required
    ALLOWLIST = "allowlist"    # Only allowed domains/methods
    BLOCKLIST = "blocklist"    # Block specific domains, allow rest
    MONITOR = "monitor"        # Log only, don't block


class APIViolationType(Enum):
    """Types of API call violations."""

    # Domain/Endpoint Violations
    DOMAIN_NOT_ALLOWED = "domain_not_allowed"
    DOMAIN_BLOCKED = "domain_blocked"
    ENDPOINT_BLOCKED = "endpoint_blocked"

    # SSRF Violations
    SSRF_PRIVATE_IP = "ssrf_private_ip"
    SSRF_LOCALHOST = "ssrf_localhost"
    SSRF_METADATA = "ssrf_metadata"
    SSRF_INTERNAL_DOMAIN = "ssrf_internal_domain"

    # Data Security Violations
    PII_IN_URL = "pii_in_url"
    PII_IN_BODY = "pii_in_body"
    PII_IN_HEADERS = "pii_in_headers"
    SECRET_IN_URL = "secret_in_url"
    SECRET_IN_BODY = "secret_in_body"
    SECRET_IN_HEADERS = "secret_in_headers"

    # Method Violations
    METHOD_NOT_ALLOWED = "method_not_allowed"
    DANGEROUS_METHOD = "dangerous_method"

    # Protocol Violations
    INSECURE_PROTOCOL = "insecure_protocol"
    INVALID_URL = "invalid_url"


# =============================================================================
# CONSTANTS
# =============================================================================

# Private IP ranges (RFC 1918 + special)
PRIVATE_IP_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # Class A private
    ipaddress.ip_network("172.16.0.0/12"),    # Class B private
    ipaddress.ip_network("192.168.0.0/16"),   # Class C private
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local (includes AWS metadata!)
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
]

# IPv6 private ranges
PRIVATE_IPV6_NETWORKS = [
    ipaddress.ip_network("::1/128"),          # Loopback
    ipaddress.ip_network("fc00::/7"),         # Unique local
    ipaddress.ip_network("fe80::/10"),        # Link-local
]

# Cloud metadata endpoints (CRITICAL to block)
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",             # AWS/GCP/Azure instance metadata
    "metadata.google.internal",     # GCP
    "metadata.azure.com",           # Azure
    "169.254.170.2",               # AWS ECS task metadata
}

# Internal domain patterns
INTERNAL_DOMAIN_PATTERNS = [
    re.compile(r"\.internal$", re.IGNORECASE),
    re.compile(r"\.local$", re.IGNORECASE),
    re.compile(r"\.localhost$", re.IGNORECASE),
    re.compile(r"\.corp$", re.IGNORECASE),
    re.compile(r"\.lan$", re.IGNORECASE),
    re.compile(r"\.intranet$", re.IGNORECASE),
    re.compile(r"\.private$", re.IGNORECASE),
]

# Safe HTTP methods (read-only)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Write HTTP methods
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Secret patterns in request data
SECRET_PATTERNS = [
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*['\"]?[\w-]{20,}"),
    re.compile(r"(?i)secret[_-]?key\s*[=:]\s*['\"]?[\w-]{20,}"),
    re.compile(r"(?i)access[_-]?token\s*[=:]\s*['\"]?[\w-]{20,}"),
    re.compile(r"(?i)bearer\s+[\w-]{20,}"),
    re.compile(r"(?i)authorization\s*[=:]\s*['\"]?[\w-]{20,}"),
    re.compile(r"(?i)password\s*[=:]\s*['\"]?[^\s'\"]{8,}"),
    re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # OpenAI API key
    re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),
    re.compile(r"-----BEGIN\s+CERTIFICATE-----"),
]


# =============================================================================
# DATA CLASSES
# =============================================================================


@dataclass
class APIRequest:
    """
    Standard HTTP request format for API Guard.

    Works with any HTTP client - user converts their format to this.
    """

    url: str
    method: str = "GET"
    headers: dict[str, str] | None = None
    body: str | bytes | dict | None = None
    params: dict[str, str] | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> APIRequest:
        """Create from dict."""
        return cls(
            url=d.get("url", ""),
            method=d.get("method", "GET").upper(),
            headers=d.get("headers"),
            body=d.get("body") or d.get("data") or d.get("json"),
            params=d.get("params"),
        )

    @classmethod
    def from_url(cls, url: str, method: str = "GET") -> APIRequest:
        """Create from URL string."""
        return cls(url=url, method=method.upper())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dict."""
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "params": self.params,
        }


@dataclass
class APIMatch:
    """A single API security violation."""

    violation_type: APIViolationType
    message: str
    location: str = ""  # url, body, headers
    matched_value: str = ""
    confidence: float = 1.0

    @property
    def description(self) -> str:
        """Human-readable description."""
        return f"{self.violation_type.value}: {self.message}"


@dataclass
class APIResult:
    """Result of API call inspection."""

    verdict: Verdict
    original_request: APIRequest
    findings: list[APIMatch] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Quick check if request is allowed."""
        return not self.verdict.blocked

    @property
    def blocked(self) -> bool:
        """Check if request is blocked."""
        return self.verdict.blocked

    @property
    def violation_types(self) -> set[APIViolationType]:
        """Get all violation types found."""
        return {f.violation_type for f in self.findings}

    def to_audit_log(self) -> dict[str, Any]:
        """Generate audit log entry."""
        log = self.verdict.to_audit_log()
        log["api_request"] = {
            "url": self.original_request.url,
            "method": self.original_request.method,
        }
        log["api_findings"] = [
            {
                "violation_type": f.violation_type.value,
                "message": f.message,
                "location": f.location,
            }
            for f in self.findings
        ]
        return log


# =============================================================================
# CONFIGURATION
# =============================================================================


@dataclass
class APIInspectorConfig:
    """Configuration for the API Inspector."""

    mode: APIMode = APIMode.ALLOWLIST
    allowed_domains: frozenset[str] = field(default_factory=frozenset)
    blocked_domains: frozenset[str] = field(default_factory=frozenset)
    allowed_methods: frozenset[str] = field(default_factory=frozenset)
    blocked_methods: frozenset[str] = field(default_factory=frozenset)
    blocked_endpoints: frozenset[str] = field(default_factory=frozenset)
    block_private_ips: bool = True
    block_metadata_endpoints: bool = True
    block_internal_domains: bool = True
    require_https: bool = False
    scan_pii: bool = True
    pii_strategy: str = "block"
    scan_secrets: bool = True
    max_body_size: int = 1_000_000
    fail_closed: bool = True


# =============================================================================
# API INSPECTOR
# =============================================================================


class APIInspector:
    """
    API call security inspector.

    Prevents data exfiltration and SSRF attacks by inspecting
    HTTP requests before they're sent.

    Example:
        >>> inspector = APIInspector(
        ...     allowed_domains={"api.openai.com"},
        ...     scan_pii=True,
        ... )
        >>> result = inspector.inspect("https://api.openai.com/v1/chat")
        >>> if result.blocked:
        ...     raise SecurityError(result.verdict.reason)
    """

    INSPECTOR_NAME = "api_inspector"

    def __init__(
        self,
        mode: APIMode | str = APIMode.ALLOWLIST,
        allowed_domains: set[str] | None = None,
        blocked_domains: set[str] | None = None,
        allowed_methods: set[str] | None = None,
        blocked_methods: set[str] | None = None,
        blocked_endpoints: set[str] | None = None,
        block_private_ips: bool = True,
        block_metadata_endpoints: bool = True,
        block_internal_domains: bool = True,
        require_https: bool = False,
        scan_pii: bool = True,
        pii_strategy: str = "block",
        scan_secrets: bool = True,
        max_body_size: int = 1_000_000,
        fail_closed: bool = True,
    ) -> None:
        # Convert string mode to enum
        if isinstance(mode, str):
            mode = APIMode(mode)

        # In restricted mode, enforce stricter defaults
        if mode == APIMode.RESTRICTED:
            require_https = True
            if allowed_methods is None:
                allowed_methods = SAFE_METHODS.copy()

        self.config = APIInspectorConfig(
            mode=mode,
            allowed_domains=frozenset(allowed_domains) if allowed_domains else frozenset(),
            blocked_domains=frozenset(blocked_domains) if blocked_domains else frozenset(),
            allowed_methods=frozenset(m.upper() for m in allowed_methods) if allowed_methods else frozenset(),
            blocked_methods=frozenset(m.upper() for m in blocked_methods) if blocked_methods else frozenset(),
            blocked_endpoints=frozenset(blocked_endpoints) if blocked_endpoints else frozenset(),
            block_private_ips=block_private_ips,
            block_metadata_endpoints=block_metadata_endpoints,
            block_internal_domains=block_internal_domains,
            require_https=require_https,
            scan_pii=scan_pii,
            pii_strategy=pii_strategy,
            scan_secrets=scan_secrets,
            max_body_size=max_body_size,
            fail_closed=fail_closed,
        )

        # Initialize PII inspector if needed
        self._pii_inspector: PIIInspector | None = None
        if scan_pii:
            strategy = PIIStrategy.BLOCK if pii_strategy == "block" else PIIStrategy.REDACT
            self._pii_inspector = PIIInspector(strategy=strategy)

    def inspect(
        self,
        request: APIRequest | dict[str, Any] | str,
    ) -> APIResult:
        """
        Inspect an API request for security violations.

        Args:
            request: APIRequest, dict, or URL string

        Returns:
            APIResult with verdict and findings
        """
        start_time = time.perf_counter()

        # Normalize request
        api_request = self._normalize_request(request)
        findings: list[APIMatch] = []

        # Layer 1: Validate URL
        url_findings = self._check_url(api_request.url)
        findings.extend(url_findings)

        # Layer 2: Check method
        method_finding = self._check_method(api_request.method)
        if method_finding:
            findings.append(method_finding)

        # Layer 3: Check domain access
        domain_finding = self._check_domain(api_request.url)
        if domain_finding:
            findings.append(domain_finding)

        # Layer 4: SSRF protection
        ssrf_findings = self._check_ssrf(api_request.url)
        findings.extend(ssrf_findings)

        # Layer 5: Protocol security
        protocol_finding = self._check_protocol(api_request.url)
        if protocol_finding:
            findings.append(protocol_finding)

        # Layer 6: Data security (PII/secrets)
        data_findings = self._check_data_security(api_request)
        findings.extend(data_findings)

        # Determine verdict based on mode
        latency_ms = self._elapsed_ms(start_time)

        if self.config.mode == APIMode.MONITOR:
            # Monitor mode: log but don't block
            verdict = create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Monitor mode: {len(findings)} violations logged",
                latency_ms=latency_ms,
            )
        elif findings:
            # Has violations - block
            primary = findings[0]
            verdict = create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=primary.message,
                rule=primary.violation_type.value,
                latency_ms=latency_ms,
            )
        else:
            # No violations - pass
            verdict = create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason="API call allowed",
                latency_ms=latency_ms,
            )

        return APIResult(
            verdict=verdict,
            original_request=api_request,
            findings=findings,
        )

    def _normalize_request(
        self, request: APIRequest | dict[str, Any] | str
    ) -> APIRequest:
        """Normalize input to APIRequest."""
        if isinstance(request, str):
            return APIRequest.from_url(request)
        elif isinstance(request, dict):
            return APIRequest.from_dict(request)
        return request

    def _check_url(self, url: str) -> list[APIMatch]:
        """Validate URL format."""
        findings = []

        if not url:
            findings.append(APIMatch(
                violation_type=APIViolationType.INVALID_URL,
                message="Empty URL",
                location="url",
            ))
            return findings

        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                findings.append(APIMatch(
                    violation_type=APIViolationType.INVALID_URL,
                    message="URL missing scheme (http/https)",
                    location="url",
                    matched_value=url,
                ))
            if not parsed.netloc:
                findings.append(APIMatch(
                    violation_type=APIViolationType.INVALID_URL,
                    message="URL missing host",
                    location="url",
                    matched_value=url,
                ))
        except Exception:
            findings.append(APIMatch(
                violation_type=APIViolationType.INVALID_URL,
                message="Invalid URL format",
                location="url",
                matched_value=url,
            ))

        return findings

    def _check_method(self, method: str) -> APIMatch | None:
        """Check if HTTP method is allowed."""
        method = method.upper()

        # Check blocked methods
        if method in self.config.blocked_methods:
            return APIMatch(
                violation_type=APIViolationType.METHOD_NOT_ALLOWED,
                message=f"HTTP method '{method}' is blocked",
                location="method",
                matched_value=method,
            )

        # Check allowed methods (if configured)
        if self.config.allowed_methods:
            if method not in self.config.allowed_methods:
                return APIMatch(
                    violation_type=APIViolationType.METHOD_NOT_ALLOWED,
                    message=f"HTTP method '{method}' not in allowed list",
                    location="method",
                    matched_value=method,
                )

        # Restricted mode: only safe methods
        if self.config.mode == APIMode.RESTRICTED:
            if method not in SAFE_METHODS:
                return APIMatch(
                    violation_type=APIViolationType.DANGEROUS_METHOD,
                    message=f"Restricted mode: '{method}' not allowed (only GET/HEAD/OPTIONS)",
                    location="method",
                    matched_value=method,
                )

        return None

    def _check_domain(self, url: str) -> APIMatch | None:
        """Check if domain is allowed."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port if present
            if ":" in domain:
                domain = domain.split(":")[0]
        except Exception:
            return None

        if not domain:
            return None

        # Check blocked domains
        if domain in self.config.blocked_domains:
            return APIMatch(
                violation_type=APIViolationType.DOMAIN_BLOCKED,
                message=f"Domain '{domain}' is blocked",
                location="url",
                matched_value=domain,
            )

        # Check wildcard blocked domains
        for blocked in self.config.blocked_domains:
            if blocked.startswith("*."):
                suffix = blocked[1:]  # Remove *
                if domain.endswith(suffix):
                    return APIMatch(
                        violation_type=APIViolationType.DOMAIN_BLOCKED,
                        message=f"Domain '{domain}' matches blocked pattern '{blocked}'",
                        location="url",
                        matched_value=domain,
                    )

        # Allowlist mode: check if domain is in allowed list
        if self.config.mode in (APIMode.ALLOWLIST, APIMode.RESTRICTED):
            if self.config.allowed_domains:
                # Check exact match
                if domain in self.config.allowed_domains:
                    return None

                # Check wildcard match
                for allowed in self.config.allowed_domains:
                    if allowed.startswith("*."):
                        suffix = allowed[1:]
                        if domain.endswith(suffix):
                            return None

                return APIMatch(
                    violation_type=APIViolationType.DOMAIN_NOT_ALLOWED,
                    message=f"Domain '{domain}' not in allowed list",
                    location="url",
                    matched_value=domain,
                )

        return None

    def _check_ssrf(self, url: str) -> list[APIMatch]:
        """Check for SSRF vulnerabilities."""
        findings = []

        try:
            parsed = urlparse(url)
            host = parsed.netloc.lower()

            # Remove port if present
            if ":" in host:
                host = host.split(":")[0]
        except Exception:
            return findings

        if not host:
            return findings

        # Check cloud metadata endpoints
        if self.config.block_metadata_endpoints:
            if host in CLOUD_METADATA_HOSTS:
                findings.append(APIMatch(
                    violation_type=APIViolationType.SSRF_METADATA,
                    message=f"Cloud metadata endpoint blocked: {host}",
                    location="url",
                    matched_value=host,
                ))
                return findings  # Critical - return immediately

        # Check for localhost
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            findings.append(APIMatch(
                violation_type=APIViolationType.SSRF_LOCALHOST,
                message=f"Localhost access blocked: {host}",
                location="url",
                matched_value=host,
            ))
            return findings

        # Check for private IPs
        if self.config.block_private_ips:
            try:
                ip = ipaddress.ip_address(host)

                # Check IPv4 private ranges
                for network in PRIVATE_IP_NETWORKS:
                    if ip in network:
                        findings.append(APIMatch(
                            violation_type=APIViolationType.SSRF_PRIVATE_IP,
                            message=f"Private IP blocked: {host}",
                            location="url",
                            matched_value=host,
                        ))
                        return findings

                # Check IPv6 private ranges
                if isinstance(ip, ipaddress.IPv6Address):
                    for network in PRIVATE_IPV6_NETWORKS:
                        if ip in network:
                            findings.append(APIMatch(
                                violation_type=APIViolationType.SSRF_PRIVATE_IP,
                                message=f"Private IPv6 blocked: {host}",
                                location="url",
                                matched_value=host,
                            ))
                            return findings

            except ValueError:
                # Not an IP address - check for internal domains
                pass

        # Check for internal domain patterns
        if self.config.block_internal_domains:
            for pattern in INTERNAL_DOMAIN_PATTERNS:
                if pattern.search(host):
                    findings.append(APIMatch(
                        violation_type=APIViolationType.SSRF_INTERNAL_DOMAIN,
                        message=f"Internal domain blocked: {host}",
                        location="url",
                        matched_value=host,
                    ))
                    return findings

        return findings

    def _check_protocol(self, url: str) -> APIMatch | None:
        """Check protocol security."""
        if self.config.require_https:
            if url.lower().startswith("http://"):
                return APIMatch(
                    violation_type=APIViolationType.INSECURE_PROTOCOL,
                    message="HTTPS required but HTTP used",
                    location="url",
                    matched_value=url.split("://")[0],
                )
        return None

    def _check_data_security(self, request: APIRequest) -> list[APIMatch]:
        """Check for PII and secrets in request."""
        findings = []

        # Check URL for sensitive data
        url_findings = self._scan_for_sensitive_data(request.url, "url")
        findings.extend(url_findings)

        # Check body for sensitive data
        if request.body:
            body_str = self._body_to_string(request.body)
            if body_str and len(body_str) <= self.config.max_body_size:
                body_findings = self._scan_for_sensitive_data(body_str, "body")
                findings.extend(body_findings)

        # Check headers for sensitive data
        if request.headers:
            headers_str = json.dumps(request.headers)
            header_findings = self._scan_for_sensitive_data(headers_str, "headers")
            findings.extend(header_findings)

        return findings

    def _scan_for_sensitive_data(self, text: str, location: str) -> list[APIMatch]:
        """Scan text for PII and secrets."""
        findings = []

        # Check for PII
        if self._pii_inspector and self.config.scan_pii:
            pii_result = self._pii_inspector.inspect(text)
            if pii_result.has_pii:
                violation_type = {
                    "url": APIViolationType.PII_IN_URL,
                    "body": APIViolationType.PII_IN_BODY,
                    "headers": APIViolationType.PII_IN_HEADERS,
                }.get(location, APIViolationType.PII_IN_BODY)

                pii_types = [t.value for t in pii_result.pii_types_found]
                findings.append(APIMatch(
                    violation_type=violation_type,
                    message=f"PII detected in {location}: {', '.join(pii_types)}",
                    location=location,
                    matched_value=f"[{len(pii_result.findings)} PII items]",
                ))

        # Check for secrets
        if self.config.scan_secrets:
            for pattern in SECRET_PATTERNS:
                match = pattern.search(text)
                if match:
                    violation_type = {
                        "url": APIViolationType.SECRET_IN_URL,
                        "body": APIViolationType.SECRET_IN_BODY,
                        "headers": APIViolationType.SECRET_IN_HEADERS,
                    }.get(location, APIViolationType.SECRET_IN_BODY)

                    findings.append(APIMatch(
                        violation_type=violation_type,
                        message=f"Secret/credential detected in {location}",
                        location=location,
                        matched_value="[REDACTED]",
                    ))
                    break  # One secret finding is enough

        return findings

    def _body_to_string(self, body: str | bytes | dict | None) -> str:
        """Convert body to string for scanning."""
        if body is None:
            return ""
        if isinstance(body, str):
            return body
        if isinstance(body, bytes):
            try:
                return body.decode("utf-8")
            except UnicodeDecodeError:
                return ""
        if isinstance(body, dict):
            return json.dumps(body)
        return str(body)

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def check_api_call(
    url: str,
    method: str = "GET",
    body: str | dict | None = None,
    allowed_domains: list[str] | None = None,
    blocked_domains: list[str] | None = None,
    block_private_ips: bool = True,
) -> bool:
    """
    Quick check if an API call is safe.

    Returns True if the API call is allowed, False if blocked.

    Example:
        >>> check_api_call("https://api.openai.com/v1/chat")
        True
        >>> check_api_call("http://169.254.169.254/latest/meta-data/")
        False
    """
    inspector = APIInspector(
        mode=APIMode.BLOCKLIST if not allowed_domains else APIMode.ALLOWLIST,
        allowed_domains=set(allowed_domains) if allowed_domains else None,
        blocked_domains=set(blocked_domains) if blocked_domains else None,
        block_private_ips=block_private_ips,
        scan_pii=False,  # Quick check, no PII scan
        scan_secrets=False,
    )

    request = APIRequest(url=url, method=method, body=body)
    result = inspector.inspect(request)
    return result.is_safe


def inspect_api_call(
    url: str,
    method: str = "GET",
    body: str | dict | None = None,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> APIResult:
    """
    Full inspection of an API call with audit trail.

    Example:
        >>> result = inspect_api_call("https://api.openai.com/v1/chat")
        >>> if result.blocked:
        ...     print(result.verdict.reason)
    """
    inspector = APIInspector(**kwargs)
    request = APIRequest(url=url, method=method, body=body, headers=headers)
    return inspector.inspect(request)
