"""
Human-in-the-Loop (HITL) Approval Guard.

Pauses agent execution for human approval on high-risk actions.

Use cases:
- Approve DELETE/DROP SQL operations
- Approve transactions above a threshold
- Approve sending emails/messages
- Approve file deletions
- Approve API calls to payment gateways

Example:
    >>> from warden.core.hitl import HITLGuard, ApprovalRequest, approval_required
    >>>
    >>> # Simple callback
    >>> def my_approval_callback(request: ApprovalRequest) -> bool:
    ...     print(f"Approve action: {request.action}?")
    ...     return input("y/n: ").lower() == "y"
    >>>
    >>> guard = HITLGuard(callback=my_approval_callback)
    >>> result = guard.request_approval(
    ...     action="DELETE FROM users WHERE id = 5",
    ...     action_type="sql_delete",
    ...     risk_level="high",
    ... )
    >>> if result.approved:
    ...     execute_delete()
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(Enum):
    """Risk level for actions requiring approval."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(Enum):
    """Status of an approval request."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ApprovalRequest:
    """
    Request for human approval.

    Contains all context needed for a human to make an informed decision.
    """

    request_id: str
    """Unique identifier for this request."""

    action: str
    """The action being requested (e.g., SQL query, shell command)."""

    action_type: str
    """Type of action (e.g., 'sql_delete', 'shell_rm', 'api_payment')."""

    risk_level: RiskLevel | str
    """Risk level of this action."""

    tool_name: str = ""
    """Name of the tool/function requesting approval."""

    context: dict[str, Any] = field(default_factory=dict)
    """Additional context for the approver."""

    timestamp: float = field(default_factory=time.time)
    """When the request was created."""

    def __post_init__(self) -> None:
        if isinstance(self.risk_level, str):
            self.risk_level = RiskLevel(self.risk_level)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "action": self.action,
            "action_type": self.action_type,
            "risk_level": self.risk_level.value,
            "tool_name": self.tool_name,
            "context": self.context,
            "timestamp": self.timestamp,
        }


@dataclass
class ApprovalResult:
    """Result of an approval request."""

    request_id: str
    """The request ID this result is for."""

    status: ApprovalStatus
    """Status of the approval."""

    approved: bool
    """Whether the action was approved."""

    approver: str | None = None
    """Who approved/denied (if available)."""

    reason: str | None = None
    """Reason for approval/denial."""

    response_time_seconds: float | None = None
    """How long the approval took."""

    def __bool__(self) -> bool:
        """Return True if approved."""
        return self.approved

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "request_id": self.request_id,
            "status": self.status.value,
            "approved": self.approved,
            "approver": self.approver,
            "reason": self.reason,
            "response_time_seconds": self.response_time_seconds,
        }


# Type aliases for callbacks
SyncApprovalCallback = Callable[[ApprovalRequest], bool]
AsyncApprovalCallback = Callable[[ApprovalRequest], Awaitable[bool]]
ApprovalCallback = SyncApprovalCallback | AsyncApprovalCallback


class HITLGuard:
    """
    Human-in-the-Loop approval guard.

    Requests human approval for high-risk actions before allowing them to proceed.

    Example:
        >>> def cli_approval(request: ApprovalRequest) -> bool:
        ...     print(f"\\nAction: {request.action}")
        ...     print(f"Risk: {request.risk_level.value}")
        ...     return input("Approve? (y/n): ").lower() == "y"
        >>>
        >>> guard = HITLGuard(callback=cli_approval)
        >>>
        >>> # Check if action needs approval
        >>> if guard.requires_approval("DELETE FROM users", "sql"):
        ...     result = guard.request_approval(
        ...         action="DELETE FROM users",
        ...         action_type="sql_delete",
        ...     )
        ...     if not result.approved:
        ...         raise PermissionError("Action denied by human")

    Attributes:
        callback: Function called to request approval.
        trigger_patterns: Patterns that trigger approval.
        default_risk_level: Default risk level for requests.
        timeout_seconds: Timeout for approval (None = no timeout).
        default_on_timeout: What to do on timeout (deny or approve).
    """

    # Common patterns that should trigger HITL
    DEFAULT_SQL_TRIGGERS = {"DELETE", "DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE"}
    DEFAULT_SHELL_TRIGGERS = {"rm", "sudo", "chmod", "chown", "kill", "shutdown", "reboot"}
    DEFAULT_FILE_TRIGGERS = {"delete", "remove", "unlink"}

    def __init__(
        self,
        callback: ApprovalCallback,
        trigger_patterns: dict[str, set[str]] | None = None,
        default_risk_level: RiskLevel | str = RiskLevel.HIGH,
        timeout_seconds: float | None = None,
        default_on_timeout: bool = False,  # Deny on timeout (safe default)
    ) -> None:
        """
        Initialize the HITL guard.

        Args:
            callback: Function to call for approval. Can be sync or async.
                     Receives ApprovalRequest, returns bool (True = approved).
            trigger_patterns: Dict mapping action types to trigger keywords.
                            e.g., {"sql": {"DELETE", "DROP"}, "shell": {"rm", "sudo"}}
            default_risk_level: Default risk level for requests.
            timeout_seconds: Timeout for approval requests (None = no timeout).
            default_on_timeout: Whether to approve (True) or deny (False) on timeout.
        """
        self.callback = callback
        self.default_risk_level = (
            RiskLevel(default_risk_level)
            if isinstance(default_risk_level, str)
            else default_risk_level
        )
        self.timeout_seconds = timeout_seconds
        self.default_on_timeout = default_on_timeout

        # Set up trigger patterns
        self.trigger_patterns = trigger_patterns or {
            "sql": self.DEFAULT_SQL_TRIGGERS,
            "shell": self.DEFAULT_SHELL_TRIGGERS,
            "file": self.DEFAULT_FILE_TRIGGERS,
        }

        # Track pending requests
        self._pending_requests: dict[str, ApprovalRequest] = {}

    def requires_approval(
        self,
        action: str,
        action_type: str,
    ) -> bool:
        """
        Check if an action requires human approval.

        Args:
            action: The action string (e.g., SQL query, shell command).
            action_type: Type of action (e.g., "sql", "shell", "file").

        Returns:
            True if the action matches any trigger patterns.
        """
        triggers = self.trigger_patterns.get(action_type, set())
        if not triggers:
            return False

        action_upper = action.upper()
        return any(trigger.upper() in action_upper for trigger in triggers)

    def request_approval(
        self,
        action: str,
        action_type: str,
        risk_level: RiskLevel | str | None = None,
        tool_name: str = "",
        context: dict[str, Any] | None = None,
    ) -> ApprovalResult:
        """
        Request human approval for an action.

        This is the synchronous version. Use request_approval_async for async contexts.

        Args:
            action: The action being requested.
            action_type: Type of action (e.g., "sql_delete", "shell_rm").
            risk_level: Risk level of this action.
            tool_name: Name of the tool requesting approval.
            context: Additional context for the approver.

        Returns:
            ApprovalResult with the decision.
        """
        request = self._create_request(action, action_type, risk_level, tool_name, context)

        start_time = time.time()

        try:
            # Check if callback is async
            if asyncio.iscoroutinefunction(self.callback):
                # Run async callback in event loop
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # Can't use asyncio.run in running loop
                        # This shouldn't happen in sync context, but handle it
                        import concurrent.futures

                        with concurrent.futures.ThreadPoolExecutor() as pool:
                            future = pool.submit(
                                asyncio.run, self._call_async_callback(request)
                            )
                            approved = future.result(timeout=self.timeout_seconds)
                    else:
                        approved = loop.run_until_complete(
                            self._call_async_callback(request)
                        )
                except RuntimeError:
                    approved = asyncio.run(self._call_async_callback(request))
            else:
                # Sync callback
                approved = self.callback(request)

            response_time = time.time() - start_time

            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
                approved=approved,
                response_time_seconds=response_time,
            )

        except TimeoutError:
            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.TIMEOUT,
                approved=self.default_on_timeout,
                reason="Approval request timed out",
                response_time_seconds=self.timeout_seconds,
            )
        except Exception as e:
            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.ERROR,
                approved=False,
                reason=f"Error during approval: {e}",
                response_time_seconds=time.time() - start_time,
            )
        finally:
            # Clean up pending request
            self._pending_requests.pop(request.request_id, None)

    async def request_approval_async(
        self,
        action: str,
        action_type: str,
        risk_level: RiskLevel | str | None = None,
        tool_name: str = "",
        context: dict[str, Any] | None = None,
    ) -> ApprovalResult:
        """
        Request human approval for an action (async version).

        Args:
            action: The action being requested.
            action_type: Type of action.
            risk_level: Risk level of this action.
            tool_name: Name of the tool requesting approval.
            context: Additional context for the approver.

        Returns:
            ApprovalResult with the decision.
        """
        request = self._create_request(action, action_type, risk_level, tool_name, context)

        start_time = time.time()

        try:
            if asyncio.iscoroutinefunction(self.callback):
                if self.timeout_seconds:
                    approved = await asyncio.wait_for(
                        self.callback(request),
                        timeout=self.timeout_seconds,
                    )
                else:
                    approved = await self.callback(request)
            else:
                # Run sync callback
                approved = self.callback(request)

            response_time = time.time() - start_time

            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.APPROVED if approved else ApprovalStatus.DENIED,
                approved=approved,
                response_time_seconds=response_time,
            )

        except asyncio.TimeoutError:
            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.TIMEOUT,
                approved=self.default_on_timeout,
                reason="Approval request timed out",
                response_time_seconds=self.timeout_seconds,
            )
        except Exception as e:
            return ApprovalResult(
                request_id=request.request_id,
                status=ApprovalStatus.ERROR,
                approved=False,
                reason=f"Error during approval: {e}",
                response_time_seconds=time.time() - start_time,
            )
        finally:
            self._pending_requests.pop(request.request_id, None)

    async def _call_async_callback(self, request: ApprovalRequest) -> bool:
        """Call async callback with optional timeout."""
        if self.timeout_seconds:
            return await asyncio.wait_for(
                self.callback(request),
                timeout=self.timeout_seconds,
            )
        return await self.callback(request)

    def _create_request(
        self,
        action: str,
        action_type: str,
        risk_level: RiskLevel | str | None,
        tool_name: str,
        context: dict[str, Any] | None,
    ) -> ApprovalRequest:
        """Create an approval request."""
        request = ApprovalRequest(
            request_id=str(uuid.uuid4()),
            action=action,
            action_type=action_type,
            risk_level=risk_level or self.default_risk_level,
            tool_name=tool_name,
            context=context or {},
        )
        self._pending_requests[request.request_id] = request
        return request

    def get_pending_requests(self) -> list[ApprovalRequest]:
        """Get all pending approval requests."""
        return list(self._pending_requests.values())


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_cli_approval_callback(
    prompt_format: str = "\n[HITL] Approve action?\n  Action: {action}\n  Type: {action_type}\n  Risk: {risk_level}\n  (y/n): ",
) -> SyncApprovalCallback:
    """
    Create a CLI-based approval callback.

    This is useful for development and testing.

    Args:
        prompt_format: Format string for the prompt.

    Returns:
        Callback function for CLI approval.

    Example:
        >>> callback = create_cli_approval_callback()
        >>> guard = HITLGuard(callback=callback)
    """

    def cli_callback(request: ApprovalRequest) -> bool:
        prompt = prompt_format.format(
            action=request.action,
            action_type=request.action_type,
            risk_level=request.risk_level.value,
            tool_name=request.tool_name,
            **request.context,
        )
        response = input(prompt).strip().lower()
        return response in ("y", "yes", "approve", "1", "true")

    return cli_callback


def create_auto_deny_callback(
    log_fn: Callable[[ApprovalRequest], None] | None = None,
) -> SyncApprovalCallback:
    """
    Create a callback that automatically denies all requests.

    Useful for testing or strict environments.

    Args:
        log_fn: Optional function to log denied requests.

    Returns:
        Callback function that always denies.
    """

    def auto_deny(request: ApprovalRequest) -> bool:
        if log_fn:
            log_fn(request)
        return False

    return auto_deny


def create_auto_approve_callback(
    log_fn: Callable[[ApprovalRequest], None] | None = None,
) -> SyncApprovalCallback:
    """
    Create a callback that automatically approves all requests.

    WARNING: Only use this for testing! Not safe for production.

    Args:
        log_fn: Optional function to log approved requests.

    Returns:
        Callback function that always approves.
    """

    def auto_approve(request: ApprovalRequest) -> bool:
        if log_fn:
            log_fn(request)
        return True

    return auto_approve


def approval_required(
    action: str,
    action_type: str = "unknown",
    triggers: dict[str, set[str]] | None = None,
) -> bool:
    """
    Quick check if an action requires approval.

    Uses default trigger patterns if none provided.

    Args:
        action: The action string.
        action_type: Type of action.
        triggers: Optional custom triggers.

    Returns:
        True if approval is required.

    Example:
        >>> approval_required("DELETE FROM users", "sql")
        True
        >>> approval_required("SELECT * FROM users", "sql")
        False
    """
    default_triggers = triggers or {
        "sql": HITLGuard.DEFAULT_SQL_TRIGGERS,
        "shell": HITLGuard.DEFAULT_SHELL_TRIGGERS,
        "file": HITLGuard.DEFAULT_FILE_TRIGGERS,
    }

    pattern_set = default_triggers.get(action_type, set())
    action_upper = action.upper()
    return any(trigger.upper() in action_upper for trigger in pattern_set)
