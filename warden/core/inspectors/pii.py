"""
PII Inspector - Detect and handle Personally Identifiable Information.

Detects common PII types (email, SSN, credit cards, phone numbers, IP addresses)
and applies configurable strategies: block, redact, mask, or hash.

This provides compliance support for HIPAA, GDPR, SOC2, and PCI-DSS requirements.

Example:
    from warden.core.inspectors.pii import PIIInspector, check_pii

    # Quick check
    if check_pii("Call me at 555-123-4567"):
        print("Contains PII!")

    # Full inspection with redaction
    inspector = PIIInspector(strategy="redact")
    result = inspector.inspect("My email is john@example.com")
    print(result.sanitized_text)  # "My email is [EMAIL REDACTED]"
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict


class PIIType(Enum):
    """Types of PII that can be detected."""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    DRIVER_LICENSE = "driver_license"
    BANK_ACCOUNT = "bank_account"
    CUSTOM = "custom"


class PIIStrategy(Enum):
    """How to handle detected PII."""

    BLOCK = "block"  # Block the request entirely
    REDACT = "redact"  # Replace with [TYPE REDACTED]
    MASK = "mask"  # Show last 4 characters only
    HASH = "hash"  # Replace with deterministic hash
    MONITOR = "monitor"  # Log only, don't block or modify


@dataclass
class PIIMatch:
    """A single PII match found in text."""

    pii_type: PIIType
    value: str
    start: int
    end: int
    confidence: float = 1.0

    @property
    def redacted(self) -> str:
        """Get redacted version."""
        return f"[{self.pii_type.value.upper()} REDACTED]"

    @property
    def masked(self) -> str:
        """Get masked version (show last 4 chars)."""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        return "*" * (len(self.value) - 4) + self.value[-4:]

    @property
    def hashed(self) -> str:
        """Get deterministic hash of value."""
        hash_val = hashlib.sha256(self.value.encode()).hexdigest()[:12]
        return f"[HASH:{hash_val}]"


@dataclass
class PIIResult:
    """
    Result of PII inspection.

    Contains both the verdict and the sanitized text (if applicable).

    Attributes:
        verdict: The security verdict (PASS or BLOCK)
        original_text: The original text that was inspected
        sanitized_text: Text with PII handled according to strategy
        findings: List of PII matches found
    """

    verdict: Verdict
    original_text: str
    sanitized_text: str
    findings: list[PIIMatch] = field(default_factory=list)

    @property
    def has_pii(self) -> bool:
        """Check if any PII was found."""
        return len(self.findings) > 0

    @property
    def pii_types_found(self) -> set[PIIType]:
        """Get set of PII types found."""
        return {f.pii_type for f in self.findings}

    def to_audit_log(self) -> dict:
        """Convert to audit log format."""
        log = self.verdict.to_audit_log()
        log["pii_findings"] = [
            {
                "type": f.pii_type.value,
                "position": {"start": f.start, "end": f.end},
                "confidence": f.confidence,
            }
            for f in self.findings
        ]
        return log


# =============================================================================
# PII DETECTION PATTERNS
# =============================================================================

# Compile regex patterns for performance
PII_PATTERNS: dict[PIIType, re.Pattern] = {
    # Email: standard email pattern
    PIIType.EMAIL: re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        re.IGNORECASE,
    ),
    # Phone: US formats (xxx-xxx-xxxx, (xxx) xxx-xxxx, xxx.xxx.xxxx, etc.)
    PIIType.PHONE: re.compile(
        r"\b(?:\+?1[-.\s]?)?"  # Optional +1 country code
        r"(?:\(?\d{3}\)?[-.\s]?)"  # Area code
        r"\d{3}[-.\s]?"  # Exchange
        r"\d{4}\b",  # Subscriber
    ),
    # SSN: xxx-xx-xxxx format
    PIIType.SSN: re.compile(
        r"\b(?!000|666|9\d{2})\d{3}"  # Area (not 000, 666, or 9xx)
        r"[-\s]?"
        r"(?!00)\d{2}"  # Group (not 00)
        r"[-\s]?"
        r"(?!0000)\d{4}\b",  # Serial (not 0000)
    ),
    # Credit Card: major card formats (Visa, MC, Amex, Discover)
    PIIType.CREDIT_CARD: re.compile(
        r"\b(?:"
        r"4[0-9]{12}(?:[0-9]{3})?"  # Visa
        r"|5[1-5][0-9]{14}"  # MasterCard
        r"|3[47][0-9]{13}"  # Amex
        r"|6(?:011|5[0-9]{2})[0-9]{12}"  # Discover
        r"|(?:\d{4}[-\s]?){3}\d{4}"  # Any 16-digit with separators
        r")\b",
    ),
    # IP Address: IPv4 format
    PIIType.IP_ADDRESS: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    ),
    # Date of Birth: common formats (MM/DD/YYYY, YYYY-MM-DD, etc.)
    PIIType.DATE_OF_BIRTH: re.compile(
        r"\b(?:"
        r"(?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])[/\-.](?:19|20)\d{2}"  # MM/DD/YYYY
        r"|(?:19|20)\d{2}[/\-.](?:0?[1-9]|1[0-2])[/\-.](?:0?[1-9]|[12]\d|3[01])"  # YYYY-MM-DD
        r")\b",
    ),
}

# =============================================================================
# PII INSPECTOR
# =============================================================================


@dataclass
class PIIInspectorConfig:
    """Configuration for the PII Inspector."""

    strategy: PIIStrategy = PIIStrategy.BLOCK
    detect_types: frozenset[PIIType] = field(
        default_factory=lambda: frozenset(
            {
                PIIType.EMAIL,
                PIIType.PHONE,
                PIIType.SSN,
                PIIType.CREDIT_CARD,
                PIIType.IP_ADDRESS,
            }
        )
    )
    custom_patterns: dict[str, re.Pattern] = field(default_factory=dict)
    min_confidence: float = 0.8
    hash_salt: str = ""  # Optional salt for hashing


class PIIInspector:
    """
    PII detection and handling inspector.

    Scans text for personally identifiable information and applies
    the configured strategy (block, redact, mask, hash, or monitor).

    Args:
        strategy: How to handle detected PII (default: block)
        detect_types: Which PII types to detect (default: all common types)
        custom_patterns: Additional regex patterns to detect
        hash_salt: Optional salt for deterministic hashing

    Example:
        # Block on any PII
        inspector = PIIInspector(strategy="block")
        result = inspector.inspect("My SSN is 123-45-6789")
        if result.verdict.blocked:
            print("PII detected and blocked!")

        # Redact PII and continue
        inspector = PIIInspector(strategy="redact")
        result = inspector.inspect("Email: john@example.com")
        print(result.sanitized_text)  # "Email: [EMAIL REDACTED]"
    """

    INSPECTOR_NAME = "pii_inspector"

    def __init__(
        self,
        strategy: PIIStrategy | str = PIIStrategy.BLOCK,
        detect_types: set[PIIType] | frozenset[PIIType] | list[str] | None = None,
        custom_patterns: dict[str, str | re.Pattern] | None = None,
        hash_salt: str = "",
        min_confidence: float = 0.8,
    ) -> None:
        # Convert string strategy to enum
        if isinstance(strategy, str):
            strategy = PIIStrategy(strategy)

        # Convert detect_types
        if detect_types is None:
            detect_set = frozenset(
                {
                    PIIType.EMAIL,
                    PIIType.PHONE,
                    PIIType.SSN,
                    PIIType.CREDIT_CARD,
                    PIIType.IP_ADDRESS,
                }
            )
        elif isinstance(detect_types, (set, frozenset)):
            detect_set = frozenset(detect_types)
        else:
            # List of strings
            detect_set = frozenset(PIIType(t) for t in detect_types)

        # Compile custom patterns
        compiled_patterns: dict[str, re.Pattern] = {}
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                if isinstance(pattern, str):
                    compiled_patterns[name] = re.compile(pattern)
                else:
                    compiled_patterns[name] = pattern

        self.config = PIIInspectorConfig(
            strategy=strategy,
            detect_types=detect_set,
            custom_patterns=compiled_patterns,
            min_confidence=min_confidence,
            hash_salt=hash_salt,
        )

    def inspect(self, text: str) -> PIIResult:
        """
        Inspect text for PII and apply the configured strategy.

        Args:
            text: The text to inspect

        Returns:
            PIIResult with verdict, sanitized text, and findings
        """
        start_time = time.perf_counter()

        if not text:
            return PIIResult(
                verdict=create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason="Empty text",
                    latency_ms=self._elapsed_ms(start_time),
                ),
                original_text=text,
                sanitized_text=text,
                findings=[],
            )

        # Find all PII matches
        findings = self._find_pii(text)

        if not findings:
            return PIIResult(
                verdict=create_pass_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason="No PII detected",
                    latency_ms=self._elapsed_ms(start_time),
                ),
                original_text=text,
                sanitized_text=text,
                findings=[],
            )

        # Apply strategy
        if self.config.strategy == PIIStrategy.BLOCK:
            return self._handle_block(text, findings, start_time)
        elif self.config.strategy == PIIStrategy.MONITOR:
            return self._handle_monitor(text, findings, start_time)
        else:
            return self._handle_transform(text, findings, start_time)

    def _find_pii(self, text: str) -> list[PIIMatch]:
        """Find all PII in the text."""
        findings: list[PIIMatch] = []

        # Check built-in patterns
        for pii_type in self.config.detect_types:
            if pii_type in PII_PATTERNS:
                pattern = PII_PATTERNS[pii_type]
                for match in pattern.finditer(text):
                    # Validate match (reduce false positives)
                    if self._validate_match(pii_type, match.group()):
                        findings.append(
                            PIIMatch(
                                pii_type=pii_type,
                                value=match.group(),
                                start=match.start(),
                                end=match.end(),
                                confidence=self._calculate_confidence(
                                    pii_type, match.group()
                                ),
                            )
                        )

        # Check custom patterns
        for _name, pattern in self.config.custom_patterns.items():
            for match in pattern.finditer(text):
                findings.append(
                    PIIMatch(
                        pii_type=PIIType.CUSTOM,
                        value=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=1.0,
                    )
                )

        # Filter by confidence
        findings = [f for f in findings if f.confidence >= self.config.min_confidence]

        # Sort by position (for proper replacement)
        findings.sort(key=lambda f: f.start)

        return findings

    def _validate_match(self, pii_type: PIIType, value: str) -> bool:
        """Validate a potential PII match to reduce false positives."""
        if pii_type == PIIType.CREDIT_CARD:
            # Luhn algorithm check
            return self._luhn_check(re.sub(r"[\s-]", "", value))
        elif pii_type == PIIType.SSN:
            # Basic SSN validation (already handled in regex, but double-check)
            digits = re.sub(r"[\s-]", "", value)
            return len(digits) == 9 and digits.isdigit()
        elif pii_type == PIIType.IP_ADDRESS:
            # Validate IP octets
            parts = value.split(".")
            return all(0 <= int(p) <= 255 for p in parts)
        return True

    def _luhn_check(self, card_number: str) -> bool:
        """Validate credit card number using Luhn algorithm."""
        if not card_number.isdigit():
            return False

        digits = [int(d) for d in card_number]
        checksum = 0

        for i, digit in enumerate(reversed(digits)):
            if i % 2 == 1:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0

    def _calculate_confidence(self, pii_type: PIIType, value: str) -> float:
        """Calculate confidence score for a match."""
        # Higher confidence for validated patterns
        if pii_type == PIIType.CREDIT_CARD:
            if self._luhn_check(re.sub(r"[\s-]", "", value)):
                return 0.99
            return 0.5
        elif pii_type == PIIType.SSN:
            return 0.95
        elif pii_type == PIIType.EMAIL:
            return 0.99
        elif pii_type == PIIType.PHONE:
            # Phone can have false positives (random numbers)
            return 0.85
        elif pii_type == PIIType.IP_ADDRESS:
            return 0.90
        return 0.80

    def _handle_block(
        self, text: str, findings: list[PIIMatch], start_time: float
    ) -> PIIResult:
        """Handle BLOCK strategy - reject request entirely."""
        pii_types = {f.pii_type.value for f in findings}
        return PIIResult(
            verdict=create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"PII detected: {', '.join(sorted(pii_types))}",
                rule="pii_detected",
                details={
                    "pii_types": list(pii_types),
                    "count": len(findings),
                },
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_text=text,
            sanitized_text=text,  # Not sanitized since blocked
            findings=findings,
        )

    def _handle_monitor(
        self, text: str, findings: list[PIIMatch], start_time: float
    ) -> PIIResult:
        """Handle MONITOR strategy - log but allow."""
        pii_types = {f.pii_type.value for f in findings}
        return PIIResult(
            verdict=create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"PII detected (monitor mode): {', '.join(sorted(pii_types))}",
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_text=text,
            sanitized_text=text,  # Not sanitized in monitor mode
            findings=findings,
        )

    def _handle_transform(
        self, text: str, findings: list[PIIMatch], start_time: float
    ) -> PIIResult:
        """Handle REDACT/MASK/HASH strategies - transform and allow."""
        # Build sanitized text by replacing matches from end to start
        # (to preserve positions)
        sanitized = text
        for finding in reversed(findings):
            if self.config.strategy == PIIStrategy.REDACT:
                replacement = finding.redacted
            elif self.config.strategy == PIIStrategy.MASK:
                replacement = finding.masked
            elif self.config.strategy == PIIStrategy.HASH:
                # Add salt if configured
                if self.config.hash_salt:
                    salted = f"{self.config.hash_salt}{finding.value}"
                    hash_val = hashlib.sha256(salted.encode()).hexdigest()[:12]
                    replacement = f"[HASH:{hash_val}]"
                else:
                    replacement = finding.hashed
            else:
                replacement = finding.value

            sanitized = sanitized[: finding.start] + replacement + sanitized[finding.end :]

        pii_types = {f.pii_type.value for f in findings}
        return PIIResult(
            verdict=create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"PII {self.config.strategy.value}ed: {', '.join(sorted(pii_types))}",
                latency_ms=self._elapsed_ms(start_time),
            ),
            original_text=text,
            sanitized_text=sanitized,
            findings=findings,
        )

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def check_pii(
    text: str,
    detect_types: list[str] | None = None,
) -> bool:
    """
    Quick check if text contains PII.

    Args:
        text: Text to check
        detect_types: PII types to detect (default: all common types)

    Returns:
        True if PII was found, False otherwise

    Example:
        if check_pii("My email is john@example.com"):
            print("Contains PII!")
    """
    inspector = PIIInspector(strategy="monitor", detect_types=detect_types)
    result = inspector.inspect(text)
    return result.has_pii


def inspect_pii(
    text: str,
    strategy: Literal["block", "redact", "mask", "hash", "monitor"] = "block",
    detect_types: list[str] | None = None,
) -> PIIResult:
    """
    Inspect text for PII with full result details.

    Args:
        text: Text to inspect
        strategy: How to handle detected PII
        detect_types: PII types to detect (default: all common types)

    Returns:
        PIIResult with verdict, sanitized text, and findings

    Example:
        result = inspect_pii("Call 555-123-4567", strategy="redact")
        print(result.sanitized_text)  # "Call [PHONE REDACTED]"
    """
    inspector = PIIInspector(strategy=strategy, detect_types=detect_types)
    return inspector.inspect(text)


def redact_pii(
    text: str,
    detect_types: list[str] | None = None,
) -> str:
    """
    Redact all PII from text.

    Convenience function that returns just the sanitized text.

    Args:
        text: Text to redact
        detect_types: PII types to detect (default: all common types)

    Returns:
        Text with PII replaced by [TYPE REDACTED]

    Example:
        clean = redact_pii("Email: john@example.com, SSN: 123-45-6789")
        # "Email: [EMAIL REDACTED], SSN: [SSN REDACTED]"
    """
    inspector = PIIInspector(strategy="redact", detect_types=detect_types)
    result = inspector.inspect(text)
    return result.sanitized_text
