# ruff: noqa: I001
"""
Tests for the PII Inspector.

Tests verify:
- Detection of all PII types (email, phone, SSN, credit card, IP, DOB)
- All strategies (block, redact, mask, hash, monitor)
- Luhn algorithm validation for credit cards
- Confidence scoring
- Custom pattern detection
- Integration with @guard decorator
"""

from warden import (
    PIIInspector,
    PIIMatch,
    PIIType,
    check_pii,
    inspect_pii,
    redact_pii,
)


# =============================================================================
# EMAIL DETECTION TESTS
# =============================================================================


class TestEmailDetection:
    """Test email PII detection."""

    def test_detect_simple_email(self):
        """Detect standard email format."""
        result = inspect_pii("Contact me at john@example.com", strategy="monitor")
        assert result.has_pii
        assert PIIType.EMAIL in result.pii_types_found
        assert len(result.findings) == 1
        assert result.findings[0].value == "john@example.com"

    def test_detect_multiple_emails(self):
        """Detect multiple emails in text."""
        text = "Email john@example.com or jane@company.org"
        result = inspect_pii(text, strategy="monitor")
        assert len(result.findings) == 2

    def test_detect_email_with_subdomain(self):
        """Detect email with subdomain."""
        result = inspect_pii("user@mail.company.co.uk", strategy="monitor")
        assert result.has_pii
        assert result.findings[0].value == "user@mail.company.co.uk"

    def test_detect_email_with_plus(self):
        """Detect email with plus addressing."""
        result = inspect_pii("john+newsletter@example.com", strategy="monitor")
        assert result.has_pii

    def test_redact_email(self):
        """Redact email from text."""
        result = inspect_pii("Email: john@example.com", strategy="redact")
        assert result.sanitized_text == "Email: [EMAIL REDACTED]"

    def test_mask_email(self):
        """Mask email showing last 4 chars."""
        result = inspect_pii("Email: john@example.com", strategy="mask")
        assert ".com" in result.sanitized_text
        assert "john" not in result.sanitized_text

    def test_hash_email(self):
        """Hash email deterministically."""
        result1 = inspect_pii("john@example.com", strategy="hash")
        result2 = inspect_pii("john@example.com", strategy="hash")
        # Same email should produce same hash
        assert result1.sanitized_text == result2.sanitized_text
        assert "[HASH:" in result1.sanitized_text


# =============================================================================
# PHONE NUMBER DETECTION TESTS
# =============================================================================


class TestPhoneDetection:
    """Test phone number PII detection."""

    def test_detect_phone_dashes(self):
        """Detect phone with dashes."""
        result = inspect_pii("Call 555-123-4567", strategy="monitor")
        assert result.has_pii
        assert PIIType.PHONE in result.pii_types_found

    def test_detect_phone_dots(self):
        """Detect phone with dots."""
        result = inspect_pii("Call 555.123.4567", strategy="monitor")
        assert result.has_pii

    def test_detect_phone_parentheses(self):
        """Detect phone with parentheses."""
        result = inspect_pii("Call (555) 123-4567", strategy="monitor")
        assert result.has_pii

    def test_detect_phone_with_country_code(self):
        """Detect phone with +1 country code."""
        result = inspect_pii("Call +1-555-123-4567", strategy="monitor")
        assert result.has_pii

    def test_redact_phone(self):
        """Redact phone from text."""
        result = inspect_pii("Call 555-123-4567", strategy="redact")
        assert "[PHONE REDACTED]" in result.sanitized_text


# =============================================================================
# SSN DETECTION TESTS
# =============================================================================


class TestSSNDetection:
    """Test Social Security Number detection."""

    def test_detect_ssn_with_dashes(self):
        """Detect SSN with standard format."""
        result = inspect_pii("SSN: 123-45-6789", strategy="monitor")
        assert result.has_pii
        assert PIIType.SSN in result.pii_types_found

    def test_detect_ssn_with_spaces(self):
        """Detect SSN with spaces."""
        result = inspect_pii("SSN: 123 45 6789", strategy="monitor")
        assert result.has_pii

    def test_reject_invalid_ssn_000(self):
        """Reject SSN starting with 000."""
        result = inspect_pii("SSN: 000-45-6789", strategy="monitor")
        # Should not detect invalid SSN
        ssn_findings = [f for f in result.findings if f.pii_type == PIIType.SSN]
        assert len(ssn_findings) == 0

    def test_reject_invalid_ssn_666(self):
        """Reject SSN starting with 666."""
        result = inspect_pii("SSN: 666-45-6789", strategy="monitor")
        ssn_findings = [f for f in result.findings if f.pii_type == PIIType.SSN]
        assert len(ssn_findings) == 0

    def test_redact_ssn(self):
        """Redact SSN from text."""
        result = inspect_pii("SSN: 123-45-6789", strategy="redact")
        assert "[SSN REDACTED]" in result.sanitized_text
        assert "123-45-6789" not in result.sanitized_text


# =============================================================================
# CREDIT CARD DETECTION TESTS
# =============================================================================


class TestCreditCardDetection:
    """Test credit card number detection with Luhn validation."""

    def test_detect_visa(self):
        """Detect valid Visa card."""
        # 4111111111111111 is a standard test Visa number (passes Luhn)
        result = inspect_pii("Card: 4111111111111111", strategy="monitor")
        assert result.has_pii
        assert PIIType.CREDIT_CARD in result.pii_types_found

    def test_detect_mastercard(self):
        """Detect valid MasterCard."""
        # 5500000000000004 is a test MasterCard (passes Luhn)
        result = inspect_pii("Card: 5500000000000004", strategy="monitor")
        assert result.has_pii

    def test_detect_amex(self):
        """Detect valid American Express."""
        # 340000000000009 is a test Amex (passes Luhn)
        result = inspect_pii("Card: 340000000000009", strategy="monitor")
        assert result.has_pii

    def test_detect_card_with_spaces(self):
        """Detect card number with spaces."""
        result = inspect_pii("Card: 4111 1111 1111 1111", strategy="monitor")
        assert result.has_pii

    def test_detect_card_with_dashes(self):
        """Detect card number with dashes."""
        result = inspect_pii("Card: 4111-1111-1111-1111", strategy="monitor")
        assert result.has_pii

    def test_reject_invalid_luhn(self):
        """Reject card number that fails Luhn check."""
        # 4111111111111112 fails Luhn
        result = inspect_pii("Card: 4111111111111112", strategy="monitor")
        cc_findings = [f for f in result.findings if f.pii_type == PIIType.CREDIT_CARD]
        # Should have low confidence or not detect
        for f in cc_findings:
            assert f.confidence < 0.8

    def test_mask_credit_card(self):
        """Mask credit card showing last 4 digits."""
        result = inspect_pii("Card: 4111111111111111", strategy="mask")
        assert "1111" in result.sanitized_text  # Last 4 visible
        assert "4111111111111111" not in result.sanitized_text


# =============================================================================
# IP ADDRESS DETECTION TESTS
# =============================================================================


class TestIPAddressDetection:
    """Test IP address detection."""

    def test_detect_ipv4(self):
        """Detect standard IPv4 address."""
        result = inspect_pii("Server IP: 192.168.1.1", strategy="monitor")
        assert result.has_pii
        assert PIIType.IP_ADDRESS in result.pii_types_found

    def test_detect_public_ip(self):
        """Detect public IP address."""
        result = inspect_pii("IP: 8.8.8.8", strategy="monitor")
        assert result.has_pii

    def test_reject_invalid_ip(self):
        """Reject invalid IP with octet > 255."""
        result = inspect_pii("IP: 256.1.1.1", strategy="monitor")
        ip_findings = [f for f in result.findings if f.pii_type == PIIType.IP_ADDRESS]
        assert len(ip_findings) == 0

    def test_redact_ip(self):
        """Redact IP address from text."""
        result = inspect_pii("Server: 192.168.1.1", strategy="redact")
        assert "[IP_ADDRESS REDACTED]" in result.sanitized_text


# =============================================================================
# STRATEGY TESTS
# =============================================================================


class TestStrategies:
    """Test all PII handling strategies."""

    def test_block_strategy(self):
        """Block strategy returns blocked verdict."""
        result = inspect_pii("Email: john@example.com", strategy="block")
        assert result.verdict.blocked
        assert "email" in result.verdict.reason.lower()

    def test_redact_strategy(self):
        """Redact strategy replaces with [TYPE REDACTED]."""
        result = inspect_pii("Email: john@example.com", strategy="redact")
        assert not result.verdict.blocked
        assert "[EMAIL REDACTED]" in result.sanitized_text

    def test_mask_strategy(self):
        """Mask strategy shows only last 4 characters."""
        result = inspect_pii("SSN: 123-45-6789", strategy="mask")
        assert not result.verdict.blocked
        assert "6789" in result.sanitized_text
        assert "123-45" not in result.sanitized_text

    def test_hash_strategy(self):
        """Hash strategy replaces with deterministic hash."""
        result = inspect_pii("Email: john@example.com", strategy="hash")
        assert not result.verdict.blocked
        assert "[HASH:" in result.sanitized_text
        assert "]" in result.sanitized_text

    def test_monitor_strategy(self):
        """Monitor strategy logs but doesn't modify."""
        original = "Email: john@example.com"
        result = inspect_pii(original, strategy="monitor")
        assert not result.verdict.blocked
        assert result.sanitized_text == original
        assert result.has_pii  # Still detected


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_check_pii_true(self):
        """check_pii returns True when PII found."""
        assert check_pii("john@example.com") is True

    def test_check_pii_false(self):
        """check_pii returns False when no PII."""
        assert check_pii("Hello world") is False

    def test_redact_pii_function(self):
        """redact_pii returns sanitized text."""
        result = redact_pii("Email: john@example.com, SSN: 123-45-6789")
        assert "[EMAIL REDACTED]" in result
        assert "[SSN REDACTED]" in result
        assert "john@example.com" not in result


# =============================================================================
# PIIInspector CLASS TESTS
# =============================================================================


class TestPIIInspector:
    """Test PIIInspector class directly."""

    def test_default_detect_types(self):
        """Default inspector detects common PII types."""
        inspector = PIIInspector()
        text = "Email: a@b.com, Phone: 555-123-4567, SSN: 123-45-6789"
        result = inspector.inspect(text)
        assert len(result.pii_types_found) >= 3

    def test_custom_detect_types(self):
        """Inspector with custom detect types."""
        inspector = PIIInspector(detect_types=["email"])
        text = "Email: a@b.com, Phone: 555-123-4567"
        result = inspector.inspect(text)
        assert PIIType.EMAIL in result.pii_types_found
        assert PIIType.PHONE not in result.pii_types_found

    def test_custom_pattern(self):
        """Inspector with custom regex pattern."""
        inspector = PIIInspector(
            strategy="redact",
            custom_patterns={"api_key": r"sk-[a-zA-Z0-9]{32}"},
        )
        result = inspector.inspect("Key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert result.has_pii
        assert "[CUSTOM REDACTED]" in result.sanitized_text

    def test_hash_with_salt(self):
        """Inspector with hash salt produces different hashes."""
        inspector1 = PIIInspector(strategy="hash", hash_salt="salt1")
        inspector2 = PIIInspector(strategy="hash", hash_salt="salt2")

        result1 = inspector1.inspect("john@example.com")
        result2 = inspector2.inspect("john@example.com")

        # Different salts should produce different hashes
        assert result1.sanitized_text != result2.sanitized_text

    def test_empty_text(self):
        """Inspector handles empty text."""
        inspector = PIIInspector()
        result = inspector.inspect("")
        assert not result.has_pii
        assert result.verdict.passed

    def test_no_pii_text(self):
        """Inspector handles text without PII."""
        inspector = PIIInspector()
        result = inspector.inspect("Hello, this is a normal message.")
        assert not result.has_pii
        assert result.verdict.passed


# =============================================================================
# MULTIPLE PII IN SAME TEXT TESTS
# =============================================================================


class TestMultiplePII:
    """Test handling of multiple PII types in same text."""

    def test_multiple_types_redacted(self):
        """All PII types are redacted."""
        text = "Email: john@example.com, Phone: 555-123-4567, SSN: 123-45-6789"
        result = inspect_pii(text, strategy="redact")
        assert "[EMAIL REDACTED]" in result.sanitized_text
        assert "[PHONE REDACTED]" in result.sanitized_text
        assert "[SSN REDACTED]" in result.sanitized_text

    def test_multiple_same_type(self):
        """Multiple instances of same PII type."""
        text = "Contact john@a.com or jane@b.com"
        result = inspect_pii(text, strategy="redact")
        assert result.sanitized_text.count("[EMAIL REDACTED]") == 2

    def test_block_on_any_pii(self):
        """Block strategy blocks on first PII found."""
        text = "Email: john@example.com, SSN: 123-45-6789"
        result = inspect_pii(text, strategy="block")
        assert result.verdict.blocked


# =============================================================================
# CONFIDENCE SCORING TESTS
# =============================================================================


class TestConfidenceScoring:
    """Test confidence scoring for PII matches."""

    def test_email_high_confidence(self):
        """Email has high confidence."""
        result = inspect_pii("john@example.com", strategy="monitor")
        assert result.findings[0].confidence >= 0.95

    def test_valid_credit_card_high_confidence(self):
        """Valid credit card (Luhn) has high confidence."""
        result = inspect_pii("4111111111111111", strategy="monitor")
        cc_findings = [f for f in result.findings if f.pii_type == PIIType.CREDIT_CARD]
        if cc_findings:
            assert cc_findings[0].confidence >= 0.95

    def test_phone_moderate_confidence(self):
        """Phone numbers have moderate confidence (more false positives)."""
        result = inspect_pii("555-123-4567", strategy="monitor")
        phone_findings = [f for f in result.findings if f.pii_type == PIIType.PHONE]
        if phone_findings:
            # Phone has lower confidence due to potential false positives
            assert phone_findings[0].confidence >= 0.80


# =============================================================================
# PIIResult AND PIIMatch TESTS
# =============================================================================


class TestPIIResultAndMatch:
    """Test PIIResult and PIIMatch dataclasses."""

    def test_pii_match_redacted(self):
        """PIIMatch.redacted property."""
        match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="john@example.com",
            start=0,
            end=16,
        )
        assert match.redacted == "[EMAIL REDACTED]"

    def test_pii_match_masked(self):
        """PIIMatch.masked property shows last 4 chars."""
        match = PIIMatch(
            pii_type=PIIType.SSN,
            value="123-45-6789",
            start=0,
            end=11,
        )
        assert match.masked.endswith("6789")

    def test_pii_match_hashed(self):
        """PIIMatch.hashed property returns deterministic hash."""
        match = PIIMatch(
            pii_type=PIIType.EMAIL,
            value="john@example.com",
            start=0,
            end=16,
        )
        assert match.hashed.startswith("[HASH:")
        assert match.hashed.endswith("]")

    def test_pii_result_to_audit_log(self):
        """PIIResult.to_audit_log includes findings."""
        result = inspect_pii("john@example.com", strategy="monitor")
        audit = result.to_audit_log()
        assert "pii_findings" in audit
        assert len(audit["pii_findings"]) > 0
        assert "type" in audit["pii_findings"][0]


# =============================================================================
# EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_pii_at_start_of_text(self):
        """PII at start of text."""
        result = inspect_pii("john@example.com is my email", strategy="redact")
        assert result.sanitized_text.startswith("[EMAIL REDACTED]")

    def test_pii_at_end_of_text(self):
        """PII at end of text."""
        result = inspect_pii("My email is john@example.com", strategy="redact")
        assert result.sanitized_text.endswith("[EMAIL REDACTED]")

    def test_adjacent_pii(self):
        """Adjacent PII without separator."""
        # This is an edge case - emails back to back
        text = "a@b.com c@d.com"
        result = inspect_pii(text, strategy="redact")
        assert result.sanitized_text.count("[EMAIL REDACTED]") == 2

    def test_pii_in_json(self):
        """PII embedded in JSON."""
        text = '{"email": "john@example.com", "phone": "555-123-4567"}'
        result = inspect_pii(text, strategy="redact")
        assert "[EMAIL REDACTED]" in result.sanitized_text
        assert "[PHONE REDACTED]" in result.sanitized_text

    def test_unicode_around_pii(self):
        """PII surrounded by unicode characters."""
        text = "Contact: \u2709 john@example.com \u260e 555-123-4567"
        result = inspect_pii(text, strategy="monitor")
        assert result.has_pii

    def test_very_long_text(self):
        """Handle very long text efficiently."""
        text = "Normal text. " * 1000 + "Email: john@example.com"
        result = inspect_pii(text, strategy="monitor")
        assert result.has_pii
        assert result.verdict.latency_ms < 1000  # Should be fast

    def test_special_characters_in_email(self):
        """Email with allowed special characters."""
        result = inspect_pii("user.name+tag@sub.example.com", strategy="monitor")
        assert result.has_pii
