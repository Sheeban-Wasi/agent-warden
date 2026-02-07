"""
Tests for the API Call Inspector.

These tests verify that the API Inspector correctly:
- Blocks SSRF attempts (private IPs, localhost, cloud metadata)
- Enforces domain allowlist/blocklist
- Checks HTTP methods
- Detects PII and secrets in requests
- Enforces HTTPS requirements
"""

import pytest

from warden import (
    APIInspector,
    APIMode,
    APIRequest,
    APIResult,
    APIViolationType,
    check_api_call,
    inspect_api_call,
)


# =============================================================================
# SSRF PROTECTION TESTS
# =============================================================================


class TestSSRFProtection:
    """Test SSRF attack prevention."""

    def test_blocks_localhost(self):
        """Block requests to localhost."""
        inspector = APIInspector()

        result = inspector.inspect("http://localhost/admin")
        assert result.blocked
        assert APIViolationType.SSRF_LOCALHOST in result.violation_types

    def test_blocks_127_0_0_1(self):
        """Block requests to 127.0.0.1."""
        inspector = APIInspector()

        result = inspector.inspect("http://127.0.0.1/admin")
        assert result.blocked
        assert APIViolationType.SSRF_LOCALHOST in result.violation_types

    def test_blocks_aws_metadata(self):
        """Block AWS metadata endpoint."""
        inspector = APIInspector()

        result = inspector.inspect("http://169.254.169.254/latest/meta-data/")
        assert result.blocked
        assert APIViolationType.SSRF_METADATA in result.violation_types

    def test_blocks_gcp_metadata(self):
        """Block GCP metadata endpoint."""
        inspector = APIInspector()

        result = inspector.inspect("http://metadata.google.internal/computeMetadata/v1/")
        assert result.blocked
        assert APIViolationType.SSRF_METADATA in result.violation_types

    def test_blocks_private_ip_10_x(self):
        """Block 10.x.x.x private IPs."""
        inspector = APIInspector()

        result = inspector.inspect("http://10.0.0.1/internal-api")
        assert result.blocked
        assert APIViolationType.SSRF_PRIVATE_IP in result.violation_types

    def test_blocks_private_ip_172_16(self):
        """Block 172.16.x.x private IPs."""
        inspector = APIInspector()

        result = inspector.inspect("http://172.16.0.1/internal-api")
        assert result.blocked
        assert APIViolationType.SSRF_PRIVATE_IP in result.violation_types

    def test_blocks_private_ip_192_168(self):
        """Block 192.168.x.x private IPs."""
        inspector = APIInspector()

        result = inspector.inspect("http://192.168.1.1/router-admin")
        assert result.blocked
        assert APIViolationType.SSRF_PRIVATE_IP in result.violation_types

    def test_blocks_internal_domain(self):
        """Block .internal domains."""
        inspector = APIInspector()

        result = inspector.inspect("http://api.company.internal/secrets")
        assert result.blocked
        assert APIViolationType.SSRF_INTERNAL_DOMAIN in result.violation_types

    def test_blocks_local_domain(self):
        """Block .local domains."""
        inspector = APIInspector()

        result = inspector.inspect("http://server.local/api")
        assert result.blocked
        assert APIViolationType.SSRF_INTERNAL_DOMAIN in result.violation_types

    def test_allows_public_ip(self):
        """Allow requests to public IPs."""
        inspector = APIInspector(mode="blocklist", scan_pii=False)

        result = inspector.inspect("http://8.8.8.8/api")
        assert result.is_safe

    def test_can_disable_private_ip_blocking(self):
        """Can disable private IP blocking."""
        inspector = APIInspector(block_private_ips=False, mode="blocklist")

        result = inspector.inspect("http://10.0.0.1/internal")
        # Won't block for private IP, but might for other reasons
        assert APIViolationType.SSRF_PRIVATE_IP not in result.violation_types


# =============================================================================
# DOMAIN ACCESS CONTROL TESTS
# =============================================================================


class TestDomainAccessControl:
    """Test domain allowlist/blocklist."""

    def test_allowlist_allows_domain(self):
        """Allowlist mode allows specified domains."""
        inspector = APIInspector(
            mode="allowlist",
            allowed_domains={"api.openai.com"},
        )

        result = inspector.inspect("https://api.openai.com/v1/chat")
        assert result.is_safe

    def test_allowlist_blocks_unknown_domain(self):
        """Allowlist mode blocks domains not in list."""
        inspector = APIInspector(
            mode="allowlist",
            allowed_domains={"api.openai.com"},
        )

        result = inspector.inspect("https://evil.com/exfiltrate")
        assert result.blocked
        assert APIViolationType.DOMAIN_NOT_ALLOWED in result.violation_types

    def test_blocklist_blocks_domain(self):
        """Blocklist mode blocks specified domains."""
        inspector = APIInspector(
            mode="blocklist",
            blocked_domains={"evil.com", "malware.com"},
        )

        result = inspector.inspect("https://evil.com/attack")
        assert result.blocked
        assert APIViolationType.DOMAIN_BLOCKED in result.violation_types

    def test_blocklist_allows_other_domains(self):
        """Blocklist mode allows non-blocked domains."""
        inspector = APIInspector(
            mode="blocklist",
            blocked_domains={"evil.com"},
        )

        result = inspector.inspect("https://api.openai.com/v1/chat")
        assert result.is_safe

    def test_wildcard_blocklist(self):
        """Block wildcard domain patterns."""
        inspector = APIInspector(
            mode="blocklist",
            blocked_domains={"*.malware.com"},
        )

        result = inspector.inspect("https://api.malware.com/exfil")
        assert result.blocked
        assert APIViolationType.DOMAIN_BLOCKED in result.violation_types

    def test_wildcard_allowlist(self):
        """Allow wildcard domain patterns."""
        inspector = APIInspector(
            mode="allowlist",
            allowed_domains={"*.openai.com"},
        )

        result = inspector.inspect("https://api.openai.com/v1/chat")
        assert result.is_safe

    def test_domain_with_port(self):
        """Handle domains with ports."""
        inspector = APIInspector(
            mode="allowlist",
            allowed_domains={"api.example.com"},
        )

        result = inspector.inspect("https://api.example.com:8443/api")
        assert result.is_safe


# =============================================================================
# HTTP METHOD TESTS
# =============================================================================


class TestMethodControl:
    """Test HTTP method restrictions."""

    def test_restricted_mode_allows_get(self):
        """Restricted mode allows GET."""
        inspector = APIInspector(
            mode="restricted",
            allowed_domains={"api.example.com"},
        )

        request = APIRequest(url="https://api.example.com/data", method="GET")
        result = inspector.inspect(request)
        assert result.is_safe

    def test_restricted_mode_blocks_post(self):
        """Restricted mode blocks POST."""
        inspector = APIInspector(
            mode="restricted",
            allowed_domains={"api.example.com"},
        )

        request = APIRequest(url="https://api.example.com/data", method="POST")
        result = inspector.inspect(request)
        assert result.blocked
        # POST is blocked because it's not in the allowed methods (GET/HEAD/OPTIONS)
        assert APIViolationType.METHOD_NOT_ALLOWED in result.violation_types

    def test_restricted_mode_blocks_delete(self):
        """Restricted mode blocks DELETE."""
        inspector = APIInspector(
            mode="restricted",
            allowed_domains={"api.example.com"},
        )

        request = APIRequest(url="https://api.example.com/data", method="DELETE")
        result = inspector.inspect(request)
        assert result.blocked

    def test_allowed_methods_list(self):
        """Only allow specified methods."""
        inspector = APIInspector(
            mode="blocklist",
            allowed_methods={"GET", "POST"},
        )

        # GET allowed
        result = inspector.inspect(APIRequest(url="https://example.com/api", method="GET"))
        assert result.is_safe

        # DELETE blocked
        result = inspector.inspect(APIRequest(url="https://example.com/api", method="DELETE"))
        assert result.blocked
        assert APIViolationType.METHOD_NOT_ALLOWED in result.violation_types

    def test_blocked_methods_list(self):
        """Block specific methods."""
        inspector = APIInspector(
            mode="blocklist",
            blocked_methods={"DELETE", "PATCH"},
        )

        # GET allowed
        result = inspector.inspect(APIRequest(url="https://example.com/api", method="GET"))
        assert result.is_safe

        # DELETE blocked
        result = inspector.inspect(APIRequest(url="https://example.com/api", method="DELETE"))
        assert result.blocked


# =============================================================================
# PROTOCOL SECURITY TESTS
# =============================================================================


class TestProtocolSecurity:
    """Test HTTPS enforcement."""

    def test_require_https_blocks_http(self):
        """Block HTTP when HTTPS required."""
        inspector = APIInspector(
            mode="blocklist",
            require_https=True,
        )

        result = inspector.inspect("http://api.example.com/data")
        assert result.blocked
        assert APIViolationType.INSECURE_PROTOCOL in result.violation_types

    def test_require_https_allows_https(self):
        """Allow HTTPS when required."""
        inspector = APIInspector(
            mode="blocklist",
            require_https=True,
        )

        result = inspector.inspect("https://api.example.com/data")
        assert result.is_safe

    def test_restricted_mode_requires_https(self):
        """Restricted mode automatically requires HTTPS."""
        inspector = APIInspector(
            mode="restricted",
            allowed_domains={"api.example.com"},
        )

        result = inspector.inspect("http://api.example.com/data")
        assert result.blocked
        assert APIViolationType.INSECURE_PROTOCOL in result.violation_types


# =============================================================================
# DATA SECURITY TESTS
# =============================================================================


class TestDataSecurity:
    """Test PII and secret detection in requests."""

    def test_detects_pii_in_url(self):
        """Detect PII in URL query parameters."""
        inspector = APIInspector(mode="blocklist", scan_pii=True)

        result = inspector.inspect("https://api.example.com/search?email=john@example.com")
        assert result.blocked
        assert APIViolationType.PII_IN_URL in result.violation_types

    def test_detects_pii_in_body(self):
        """Detect PII in request body."""
        inspector = APIInspector(mode="blocklist", scan_pii=True)

        request = APIRequest(
            url="https://api.example.com/submit",
            method="POST",
            body={"ssn": "123-45-6789", "name": "John"},
        )
        result = inspector.inspect(request)
        assert result.blocked
        assert APIViolationType.PII_IN_BODY in result.violation_types

    def test_detects_secret_in_url(self):
        """Detect API keys in URL."""
        inspector = APIInspector(mode="blocklist", scan_secrets=True)

        result = inspector.inspect("https://api.example.com/data?api_key=sk-1234567890abcdefghijklmnop")
        assert result.blocked
        assert APIViolationType.SECRET_IN_URL in result.violation_types

    def test_detects_secret_in_body(self):
        """Detect secrets in request body."""
        inspector = APIInspector(mode="blocklist", scan_secrets=True)

        request = APIRequest(
            url="https://api.example.com/submit",
            method="POST",
            body="password: supersecretpassword123",
        )
        result = inspector.inspect(request)
        assert result.blocked
        assert APIViolationType.SECRET_IN_BODY in result.violation_types

    def test_detects_bearer_token(self):
        """Detect Bearer tokens."""
        inspector = APIInspector(mode="blocklist", scan_secrets=True)

        request = APIRequest(
            url="https://api.example.com/data",
            body="Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        )
        result = inspector.inspect(request)
        assert result.blocked

    def test_can_disable_pii_scan(self):
        """Can disable PII scanning."""
        inspector = APIInspector(mode="blocklist", scan_pii=False)

        result = inspector.inspect("https://api.example.com/search?email=john@example.com")
        assert APIViolationType.PII_IN_URL not in result.violation_types


# =============================================================================
# URL VALIDATION TESTS
# =============================================================================


class TestURLValidation:
    """Test URL format validation."""

    def test_rejects_empty_url(self):
        """Reject empty URL."""
        inspector = APIInspector()

        result = inspector.inspect("")
        assert result.blocked
        assert APIViolationType.INVALID_URL in result.violation_types

    def test_rejects_url_without_scheme(self):
        """Reject URL without scheme."""
        inspector = APIInspector()

        result = inspector.inspect("api.example.com/data")
        assert result.blocked
        assert APIViolationType.INVALID_URL in result.violation_types

    def test_rejects_url_without_host(self):
        """Reject URL without host."""
        inspector = APIInspector()

        result = inspector.inspect("http:///path")
        assert result.blocked
        assert APIViolationType.INVALID_URL in result.violation_types


# =============================================================================
# MODE TESTS
# =============================================================================


class TestModes:
    """Test different operating modes."""

    def test_monitor_mode_logs_but_allows(self):
        """Monitor mode logs violations but allows request."""
        inspector = APIInspector(mode="monitor")

        # Would normally be blocked for SSRF
        result = inspector.inspect("http://169.254.169.254/meta-data/")

        assert result.is_safe  # Monitor mode allows
        assert len(result.findings) > 0  # But logs violations

    def test_restricted_mode_is_strictest(self):
        """Restricted mode applies all restrictions."""
        inspector = APIInspector(
            mode="restricted",
            allowed_domains={"api.example.com"},
        )

        # HTTP blocked
        result = inspector.inspect("http://api.example.com/data")
        assert result.blocked

        # POST blocked
        result = inspector.inspect(APIRequest(
            url="https://api.example.com/data",
            method="POST",
        ))
        assert result.blocked


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Test check_api_call and inspect_api_call."""

    def test_check_api_call_returns_bool(self):
        """check_api_call returns True/False."""
        # Safe request
        assert check_api_call("https://api.example.com/data") is True

        # SSRF attempt
        assert check_api_call("http://169.254.169.254/meta-data/") is False

    def test_check_api_call_with_allowed_domains(self):
        """check_api_call with domain allowlist."""
        assert check_api_call(
            "https://api.openai.com/v1/chat",
            allowed_domains=["api.openai.com"],
        ) is True

        assert check_api_call(
            "https://evil.com/exfil",
            allowed_domains=["api.openai.com"],
        ) is False

    def test_inspect_api_call_returns_result(self):
        """inspect_api_call returns full APIResult."""
        result = inspect_api_call("https://api.example.com/data")

        assert isinstance(result, APIResult)
        assert result.is_safe

    def test_inspect_api_call_with_body(self):
        """inspect_api_call with request body."""
        result = inspect_api_call(
            url="https://api.example.com/submit",
            method="POST",
            body={"data": "test"},
        )

        assert isinstance(result, APIResult)


# =============================================================================
# API REQUEST TESTS
# =============================================================================


class TestAPIRequest:
    """Test APIRequest dataclass."""

    def test_from_dict(self):
        """Create APIRequest from dict."""
        request = APIRequest.from_dict({
            "url": "https://api.example.com/data",
            "method": "post",
            "body": {"key": "value"},
        })

        assert request.url == "https://api.example.com/data"
        assert request.method == "POST"
        assert request.body == {"key": "value"}

    def test_from_url(self):
        """Create APIRequest from URL string."""
        request = APIRequest.from_url("https://api.example.com/data")

        assert request.url == "https://api.example.com/data"
        assert request.method == "GET"

    def test_to_dict(self):
        """Convert APIRequest to dict."""
        request = APIRequest(
            url="https://api.example.com/data",
            method="POST",
            body={"key": "value"},
        )

        d = request.to_dict()
        assert d["url"] == "https://api.example.com/data"
        assert d["method"] == "POST"
        assert d["body"] == {"key": "value"}


# =============================================================================
# AUDIT LOG TESTS
# =============================================================================


class TestAuditLog:
    """Test audit logging functionality."""

    def test_result_has_audit_log(self):
        """APIResult generates audit log."""
        inspector = APIInspector()
        result = inspector.inspect("https://api.example.com/data")

        log = result.to_audit_log()

        assert "timestamp" in log
        assert "verdict" in log
        assert "api_request" in log
        assert log["api_request"]["url"] == "https://api.example.com/data"

    def test_blocked_result_includes_findings(self):
        """Blocked result includes findings in audit log."""
        inspector = APIInspector()
        result = inspector.inspect("http://169.254.169.254/meta-data/")

        log = result.to_audit_log()

        assert "api_findings" in log
        assert len(log["api_findings"]) > 0


# =============================================================================
# EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_handles_bytes_body(self):
        """Handle bytes body."""
        inspector = APIInspector(mode="blocklist")

        request = APIRequest(
            url="https://api.example.com/upload",
            method="POST",
            body=b"binary data here",
        )
        result = inspector.inspect(request)
        # Should not crash
        assert isinstance(result, APIResult)

    def test_handles_none_body(self):
        """Handle None body."""
        inspector = APIInspector(mode="blocklist")

        request = APIRequest(
            url="https://api.example.com/data",
            body=None,
        )
        result = inspector.inspect(request)
        assert isinstance(result, APIResult)

    def test_handles_large_body_gracefully(self):
        """Don't scan excessively large bodies."""
        inspector = APIInspector(mode="blocklist", max_body_size=100)

        request = APIRequest(
            url="https://api.example.com/upload",
            method="POST",
            body="x" * 1000,  # Larger than max
        )
        result = inspector.inspect(request)
        # Should complete without error
        assert isinstance(result, APIResult)

    def test_inspector_accepts_string_input(self):
        """Inspector accepts URL string directly."""
        inspector = APIInspector(mode="blocklist")

        result = inspector.inspect("https://api.example.com/data")
        assert isinstance(result, APIResult)

    def test_inspector_accepts_dict_input(self):
        """Inspector accepts dict input."""
        inspector = APIInspector(mode="blocklist")

        result = inspector.inspect({
            "url": "https://api.example.com/data",
            "method": "GET",
        })
        assert isinstance(result, APIResult)
