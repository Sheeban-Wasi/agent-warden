"""
Verdict types for Warden inspections.

Every inspection returns a Verdict with a decision and audit details.
This is the core data structure that flows through the Hub.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class VerdictType(Enum):
    """
    The outcome of a security inspection.

    PASS: Action is allowed to proceed
    BLOCK: Action is denied
    """

    PASS = "PASS"
    BLOCK = "BLOCK"


@dataclass
class Verdict:
    """
    The result of a Warden security inspection.

    This is the "Compliance Product" - every decision is captured
    in a structured, auditable format that banks and enterprises need.

    Attributes:
        verdict: PASS or BLOCK
        inspector: Which inspector made this decision (e.g., "sql_inspector")
        reason: Human-readable explanation of the decision
        rule: The specific rule that was triggered (if blocked)
        details: Additional context for audit logging
        latency_ms: Time taken for inspection (for performance monitoring)
        event_id: Unique identifier for this inspection (UUID)
        timestamp: When the inspection occurred (ISO 8601)

    Example:
        verdict = Verdict(
            verdict=VerdictType.BLOCK,
            inspector="sql_inspector",
            reason="DROP statement detected",
            rule="critical_node_detected",
            details={"node_type": "Drop", "sql_fragment": "DROP TABLE users"}
        )
        if verdict.blocked:
            raise CriticalViolation(verdict.reason)
    """

    verdict: VerdictType
    inspector: str
    reason: str
    rule: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def passed(self) -> bool:
        """Check if the verdict allows the action."""
        return self.verdict == VerdictType.PASS

    @property
    def blocked(self) -> bool:
        """Check if the verdict blocks the action."""
        return self.verdict == VerdictType.BLOCK

    def to_audit_log(self) -> dict[str, Any]:
        """
        Convert to structured audit log format.

        This is the JSON schema that compliance officers review.
        Every blocked action generates an immutable audit record.

        Returns:
            dict: Structured log entry ready for CloudWatch/SIEM
        """
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "verdict": self.verdict.value,
            "inspector": self.inspector,
            "rule": self.rule,
            "reason": self.reason,
            "details": self.details,
            "latency_ms": round(self.latency_ms, 3),
        }

    def to_agent_response(self) -> str:
        """
        Format as a response string for the AI agent.

        When an action is blocked, the agent receives this message
        so it can self-correct and try a different approach.

        Returns:
            str: Agent-friendly message
        """
        if self.passed:
            return "Action approved by security policy."

        return f"Action blocked by security policy: {self.reason}"


def create_pass_verdict(
    inspector: str,
    reason: str = "Action passed all security checks",
    latency_ms: float = 0.0,
) -> Verdict:
    """
    Factory function to create a PASS verdict.

    Args:
        inspector: Name of the inspector
        reason: Why the action passed
        latency_ms: Inspection time

    Returns:
        Verdict with PASS type
    """
    return Verdict(
        verdict=VerdictType.PASS,
        inspector=inspector,
        reason=reason,
        latency_ms=latency_ms,
    )


def create_block_verdict(
    inspector: str,
    reason: str,
    rule: str,
    details: dict[str, Any] | None = None,
    latency_ms: float = 0.0,
) -> Verdict:
    """
    Factory function to create a BLOCK verdict.

    Args:
        inspector: Name of the inspector
        reason: Why the action was blocked
        rule: The rule that triggered the block
        details: Additional context
        latency_ms: Inspection time

    Returns:
        Verdict with BLOCK type
    """
    return Verdict(
        verdict=VerdictType.BLOCK,
        inspector=inspector,
        reason=reason,
        rule=rule,
        details=details or {},
        latency_ms=latency_ms,
    )
