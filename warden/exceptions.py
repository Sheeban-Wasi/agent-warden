"""
Agent-Warden exceptions.

All exceptions inherit from WardenError for easy catching.
Philosophy: "Deny by Default" - when in doubt, block and raise.
"""

from __future__ import annotations

from typing import Any


class WardenError(Exception):
    """
    Base exception for all Agent-Warden errors.

    Catch this to handle any Warden-related error:
        try:
            result = inspector.inspect(query)
        except WardenError as e:
            log_security_event(e)
    """

    pass


class PolicyViolation(WardenError):
    """
    Raised when an action violates a configured policy.

    These are configurable violations that depend on mode/settings:
        - INSERT/UPDATE when mode is 'read-only'
        - Accessing data outside user's allowed scope
        - Writing to unauthorized tables

    Attributes:
        message: Human-readable description
        rule: The policy rule that was violated
        details: Additional context for debugging/audit
        verdict: The full Verdict object (if available)
    """

    def __init__(
        self,
        message: str,
        rule: str | None = None,
        details: dict[str, Any] | None = None,
        verdict: Any = None,  # Avoid circular import, accepts Verdict
    ) -> None:
        super().__init__(message)
        self.message = message
        self.rule = rule or (verdict.rule if verdict else None)
        self.details = details or (verdict.details if verdict else {})
        self.verdict = verdict

    def __str__(self) -> str:
        if self.rule:
            return f"[{self.rule}] {self.message}"
        return self.message


class CriticalViolation(WardenError):
    """
    Raised when an action is categorically forbidden.

    These are ALWAYS blocked regardless of mode or configuration:
        - DROP, TRUNCATE, ALTER, GRANT statements
        - Detected SQL injection attempts
        - Attempts to execute dynamic SQL

    Attributes:
        message: Human-readable description
        threat_type: Category of threat (e.g., "SQL_INJECTION", "SCHEMA_CHANGE")
        details: Additional context for debugging/audit
        verdict: The full Verdict object (if available)
    """

    def __init__(
        self,
        message: str,
        threat_type: str | None = None,
        details: dict[str, Any] | None = None,
        verdict: Any = None,  # Avoid circular import, accepts Verdict
    ) -> None:
        super().__init__(message)
        self.message = message
        self.threat_type = threat_type or (verdict.rule if verdict else "UNKNOWN")
        self.details = details or (verdict.details if verdict else {})
        self.verdict = verdict

    def __str__(self) -> str:
        return f"[CRITICAL:{self.threat_type}] {self.message}"


class ConfigurationError(WardenError):
    """
    Raised when there's an error in policy configuration.

    Examples:
        - Invalid YAML syntax in policy file
        - Unknown inspector type specified
        - Missing required configuration fields
    """

    pass


class ParseError(WardenError):
    """
    Raised when input cannot be parsed.

    Following 'Deny by Default' philosophy:
        - Unparseable SQL queries should be blocked
        - Malformed input is treated as potentially malicious

    Attributes:
        message: Human-readable description
        raw_input: The input that failed to parse
        parse_error: The underlying parse error message
    """

    def __init__(
        self,
        message: str,
        raw_input: str | None = None,
        parse_error: str | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.raw_input = raw_input
        self.parse_error = parse_error

    def __str__(self) -> str:
        if self.parse_error:
            return f"{self.message}: {self.parse_error}"
        return self.message
