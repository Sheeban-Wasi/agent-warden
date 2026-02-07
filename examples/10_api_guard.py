#!/usr/bin/env python3
"""
Example 10: API Call Guard - Prevent data exfiltration and SSRF attacks.

This example demonstrates how to protect your AI agent's HTTP calls from:
- Data exfiltration (sending PII/secrets to attacker endpoints)
- SSRF attacks (accessing internal networks, cloud metadata)
- Unauthorized API calls (calling APIs outside allowed scope)

Key Features:
- Domain allowlist/blocklist
- SSRF protection (private IPs, localhost, cloud metadata)
- PII and secret detection in requests
- HTTP method restrictions
- HTTPS enforcement

Run with:
    python examples/10_api_guard.py
"""

from warden import (
    APIInspector,
    APIMode,
    APIRequest,
    check_api_call,
    inspect_api_call,
)


def divider(title: str) -> None:
    """Print a section divider."""
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}\n")


# =============================================================================
# SAMPLE SCENARIOS
# =============================================================================


def example_ssrf_protection():
    """Example 1: SSRF Attack Prevention."""
    divider("Example 1: SSRF Attack Prevention")

    inspector = APIInspector()

    # Test various SSRF attack vectors
    test_urls = [
        ("http://169.254.169.254/latest/meta-data/", "AWS metadata endpoint"),
        ("http://localhost/admin", "Localhost access"),
        ("http://127.0.0.1:8080/internal", "Loopback IP"),
        ("http://10.0.0.1/internal-api", "Private IP (10.x)"),
        ("http://192.168.1.1/router", "Private IP (192.168.x)"),
        ("http://api.company.internal/secrets", "Internal domain"),
        ("https://api.example.com/public", "Public API (allowed)"),
    ]

    for url, description in test_urls:
        result = inspector.inspect(url)
        status = "BLOCKED" if result.blocked else "ALLOWED"
        print(f"  [{status}] {description}")
        print(f"           URL: {url}")
        if result.blocked:
            print(f"           Reason: {result.verdict.reason}")
        print()


def example_domain_allowlist():
    """Example 2: Domain Allowlist."""
    divider("Example 2: Domain Allowlist")

    # Only allow specific API domains
    inspector = APIInspector(
        mode="allowlist",
        allowed_domains={
            "api.openai.com",
            "api.anthropic.com",
            "*.googleapis.com",  # Wildcard
        },
    )

    test_urls = [
        "https://api.openai.com/v1/chat/completions",
        "https://api.anthropic.com/v1/messages",
        "https://storage.googleapis.com/bucket/file",
        "https://evil.com/exfiltrate",
        "https://random-api.com/data",
    ]

    print("Allowed domains: api.openai.com, api.anthropic.com, *.googleapis.com\n")

    for url in test_urls:
        result = inspector.inspect(url)
        status = "ALLOWED" if result.is_safe else "BLOCKED"
        print(f"  [{status}] {url}")


def example_domain_blocklist():
    """Example 3: Domain Blocklist."""
    divider("Example 3: Domain Blocklist")

    # Block known malicious domains
    inspector = APIInspector(
        mode="blocklist",
        blocked_domains={
            "evil.com",
            "*.malware.com",
            "attacker.io",
        },
        scan_pii=False,  # Disable PII scan for this demo
    )

    test_urls = [
        "https://api.example.com/data",
        "https://evil.com/collect",
        "https://api.malware.com/exfil",
        "https://legitimate-api.com/endpoint",
    ]

    print("Blocked domains: evil.com, *.malware.com, attacker.io\n")

    for url in test_urls:
        result = inspector.inspect(url)
        status = "ALLOWED" if result.is_safe else "BLOCKED"
        print(f"  [{status}] {url}")


def example_data_exfiltration_prevention():
    """Example 4: Data Exfiltration Prevention."""
    divider("Example 4: Data Exfiltration Prevention")

    inspector = APIInspector(
        mode="blocklist",
        scan_pii=True,
        scan_secrets=True,
    )

    # Test requests with sensitive data
    test_cases = [
        {
            "url": "https://api.example.com/search?email=john@example.com",
            "method": "GET",
            "description": "PII in URL (email)",
        },
        {
            "url": "https://api.example.com/submit",
            "method": "POST",
            "body": {"ssn": "123-45-6789", "name": "John Doe"},
            "description": "PII in body (SSN)",
        },
        {
            "url": "https://api.example.com/data?api_key=sk-1234567890abcdefghijklmnop",
            "method": "GET",
            "description": "Secret in URL (API key)",
        },
        {
            "url": "https://api.example.com/safe",
            "method": "GET",
            "description": "Safe request (no sensitive data)",
        },
    ]

    for case in test_cases:
        request = APIRequest(
            url=case["url"],
            method=case.get("method", "GET"),
            body=case.get("body"),
        )
        result = inspector.inspect(request)
        status = "BLOCKED" if result.blocked else "ALLOWED"
        print(f"  [{status}] {case['description']}")
        if result.blocked:
            for finding in result.findings:
                print(f"           {finding.violation_type.value}: {finding.message}")
        print()


def example_method_restrictions():
    """Example 5: HTTP Method Restrictions."""
    divider("Example 5: HTTP Method Restrictions")

    # Restricted mode: only GET/HEAD/OPTIONS
    inspector = APIInspector(
        mode="restricted",
        allowed_domains={"api.example.com"},
    )

    methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]

    print("Restricted mode: Only GET/HEAD/OPTIONS allowed\n")

    for method in methods:
        request = APIRequest(
            url="https://api.example.com/resource",
            method=method,
        )
        result = inspector.inspect(request)
        status = "ALLOWED" if result.is_safe else "BLOCKED"
        print(f"  [{status}] {method}")


def example_https_enforcement():
    """Example 6: HTTPS Enforcement."""
    divider("Example 6: HTTPS Enforcement")

    inspector = APIInspector(
        mode="blocklist",
        require_https=True,
        scan_pii=False,
    )

    test_urls = [
        "https://api.example.com/secure",
        "http://api.example.com/insecure",
        "https://another.com/data",
        "http://another.com/data",
    ]

    print("HTTPS required\n")

    for url in test_urls:
        result = inspector.inspect(url)
        status = "ALLOWED" if result.is_safe else "BLOCKED"
        protocol = url.split("://")[0].upper()
        print(f"  [{status}] [{protocol}] {url}")


def example_convenience_functions():
    """Example 7: Convenience Functions."""
    divider("Example 7: Convenience Functions")

    # Quick boolean check
    print("check_api_call() - Quick boolean check:\n")

    is_safe = check_api_call("https://api.openai.com/v1/chat")
    print(f"  api.openai.com: {is_safe}")

    is_safe = check_api_call("http://169.254.169.254/meta-data/")
    print(f"  AWS metadata:   {is_safe}")

    is_safe = check_api_call(
        "https://api.example.com/data",
        allowed_domains=["api.example.com"],
    )
    print(f"  With allowlist: {is_safe}")

    # Full inspection
    print("\ninspect_api_call() - Full inspection:\n")

    result = inspect_api_call(
        url="https://api.example.com/submit",
        method="POST",
        body={"data": "test"},
    )
    print(f"  Verdict: {result.verdict.verdict.value}")
    print(f"  Latency: {result.verdict.latency_ms:.3f}ms")


def example_modes():
    """Example 8: Operating Modes."""
    divider("Example 8: Operating Modes")

    # Same URL, different modes
    test_url = "https://unknown-api.com/data"

    modes = [
        ("restricted", {"allowed_domains": {"allowed.com"}}),
        ("allowlist", {"allowed_domains": {"allowed.com"}}),
        ("blocklist", {"blocked_domains": {"blocked.com"}}),
        ("monitor", {}),
    ]

    print(f"Testing URL: {test_url}\n")

    for mode_name, extra_config in modes:
        inspector = APIInspector(
            mode=mode_name,
            scan_pii=False,
            **extra_config,
        )
        result = inspector.inspect(test_url)
        verdict = "ALLOWED" if result.is_safe else "BLOCKED"
        findings = len(result.findings)
        print(f"  {mode_name.upper():12} mode: {verdict} (findings: {findings})")


def example_audit_trail():
    """Example 9: Audit Trail."""
    divider("Example 9: Audit Trail")

    inspector = APIInspector(
        mode="blocklist",
        blocked_domains={"evil.com"},
    )

    result = inspector.inspect("https://evil.com/exfiltrate")

    # Generate audit log
    audit = result.to_audit_log()

    print("Audit Log Entry:")
    print(f"  Event ID:  {audit['event_id']}")
    print(f"  Timestamp: {audit['timestamp']}")
    print(f"  Verdict:   {audit['verdict']}")
    print(f"  Inspector: {audit['inspector']}")
    print(f"  Reason:    {audit.get('reason', 'N/A')}")
    print(f"  Request:")
    print(f"    URL:    {audit['api_request']['url']}")
    print(f"    Method: {audit['api_request']['method']}")

    if audit.get("api_findings"):
        print("  Findings:")
        for f in audit["api_findings"]:
            print(f"    - {f['violation_type']}: {f['message']}")


def main():
    """Run all examples."""
    print("\n" + "=" * 60)
    print("  API Call Guard - Prevent Data Exfiltration & SSRF")
    print("=" * 60)
    print("\nAgent-Warden protects your AI agent's HTTP calls from:")
    print("  - Data exfiltration (PII/secrets to external servers)")
    print("  - SSRF attacks (internal networks, cloud metadata)")
    print("  - Unauthorized API calls (outside allowed scope)")

    example_ssrf_protection()
    example_domain_allowlist()
    example_domain_blocklist()
    example_data_exfiltration_prevention()
    example_method_restrictions()
    example_https_enforcement()
    example_convenience_functions()
    example_modes()
    example_audit_trail()

    divider("Summary")
    print("API Call Guard provides comprehensive HTTP security:")
    print()
    print("  1. SSRF Protection     - Block internal IPs, metadata endpoints")
    print("  2. Domain Control      - Allowlist/blocklist domains")
    print("  3. Data Security       - Scan for PII and secrets")
    print("  4. Method Restrictions - Control HTTP methods")
    print("  5. Protocol Security   - Enforce HTTPS")
    print()
    print("For more information, see the documentation and tests.")


if __name__ == "__main__":
    main()
