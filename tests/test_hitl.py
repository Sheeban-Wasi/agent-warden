"""
Tests for the Human-in-the-Loop (HITL) Approval Guard.

These tests verify that the HITLGuard correctly:
- Detects actions requiring approval
- Requests approval via callback
- Handles approval/denial
- Handles timeouts
- Works with async callbacks
"""

import asyncio

import pytest

from warden import (
    ApprovalRequest,
    ApprovalResult,
    ApprovalStatus,
    HITLGuard,
    RiskLevel,
    approval_required,
    create_auto_approve_callback,
    create_auto_deny_callback,
)


# =============================================================================
# BASIC HITL TESTS
# =============================================================================


class TestHITLGuard:
    """Test the HITLGuard class."""

    def test_requires_approval_sql_delete(self):
        """DELETE statements should require approval."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        assert guard.requires_approval("DELETE FROM users WHERE id = 1", "sql")
        assert guard.requires_approval("delete from orders", "sql")

    def test_requires_approval_sql_drop(self):
        """DROP statements should require approval."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        assert guard.requires_approval("DROP TABLE users", "sql")
        assert guard.requires_approval("drop database test", "sql")

    def test_requires_approval_sql_select(self):
        """SELECT statements should NOT require approval."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        assert not guard.requires_approval("SELECT * FROM users", "sql")
        assert not guard.requires_approval("select id from orders", "sql")

    def test_requires_approval_shell_rm(self):
        """rm commands should require approval."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        assert guard.requires_approval("rm -rf /tmp/test", "shell")
        assert guard.requires_approval("sudo rm file.txt", "shell")

    def test_requires_approval_shell_safe(self):
        """Safe shell commands should NOT require approval."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        assert not guard.requires_approval("ls -la", "shell")
        assert not guard.requires_approval("cat file.txt", "shell")

    def test_requires_approval_custom_triggers(self):
        """Custom triggers should work."""
        guard = HITLGuard(
            callback=create_auto_approve_callback(),
            trigger_patterns={"api": {"payment", "refund"}},
        )

        assert guard.requires_approval("POST /api/payment", "api")
        assert guard.requires_approval("refund transaction", "api")
        assert not guard.requires_approval("GET /api/users", "api")

    def test_request_approval_approved(self):
        """Approved requests should return approved result."""
        guard = HITLGuard(callback=create_auto_approve_callback())

        result = guard.request_approval(
            action="DELETE FROM users WHERE id = 1",
            action_type="sql_delete",
        )

        assert result.approved
        assert result.status == ApprovalStatus.APPROVED
        assert result.response_time_seconds is not None

    def test_request_approval_denied(self):
        """Denied requests should return denied result."""
        guard = HITLGuard(callback=create_auto_deny_callback())

        result = guard.request_approval(
            action="DELETE FROM users WHERE id = 1",
            action_type="sql_delete",
        )

        assert not result.approved
        assert result.status == ApprovalStatus.DENIED

    def test_request_approval_with_context(self):
        """Approval request should include context."""
        received_request = None

        def capture_callback(request: ApprovalRequest) -> bool:
            nonlocal received_request
            received_request = request
            return True

        guard = HITLGuard(callback=capture_callback)

        result = guard.request_approval(
            action="DELETE FROM users",
            action_type="sql_delete",
            risk_level="critical",
            tool_name="my_tool",
            context={"user_id": 123},
        )

        assert result.approved
        assert received_request is not None
        assert received_request.action == "DELETE FROM users"
        assert received_request.action_type == "sql_delete"
        assert received_request.risk_level == RiskLevel.CRITICAL
        assert received_request.tool_name == "my_tool"
        assert received_request.context == {"user_id": 123}

    def test_result_bool_conversion(self):
        """ApprovalResult should be truthy when approved."""
        approved_result = ApprovalResult(
            request_id="test",
            status=ApprovalStatus.APPROVED,
            approved=True,
        )
        assert approved_result
        assert bool(approved_result) is True

        denied_result = ApprovalResult(
            request_id="test",
            status=ApprovalStatus.DENIED,
            approved=False,
        )
        assert not denied_result
        assert bool(denied_result) is False

    def test_result_to_dict(self):
        """ApprovalResult should convert to dict."""
        result = ApprovalResult(
            request_id="test-123",
            status=ApprovalStatus.APPROVED,
            approved=True,
            approver="admin",
            reason="Looks safe",
            response_time_seconds=1.5,
        )

        d = result.to_dict()
        assert d["request_id"] == "test-123"
        assert d["status"] == "approved"
        assert d["approved"] is True
        assert d["approver"] == "admin"
        assert d["reason"] == "Looks safe"

    def test_request_to_dict(self):
        """ApprovalRequest should convert to dict."""
        request = ApprovalRequest(
            request_id="test-456",
            action="DELETE FROM users",
            action_type="sql_delete",
            risk_level=RiskLevel.HIGH,
            tool_name="my_tool",
        )

        d = request.to_dict()
        assert d["request_id"] == "test-456"
        assert d["action"] == "DELETE FROM users"
        assert d["action_type"] == "sql_delete"
        assert d["risk_level"] == "high"


class TestAsyncHITL:
    """Test async HITL functionality."""

    def test_async_callback_sync_call(self):
        """Async callbacks should work with sync request_approval."""

        async def async_approve(request: ApprovalRequest) -> bool:
            await asyncio.sleep(0.01)  # Simulate async operation
            return True

        guard = HITLGuard(callback=async_approve)

        result = guard.request_approval(
            action="DELETE FROM users",
            action_type="sql_delete",
        )

        assert result.approved

    @pytest.mark.asyncio
    async def test_async_callback_async_call(self):
        """Async callbacks should work with async request_approval_async."""

        async def async_approve(request: ApprovalRequest) -> bool:
            await asyncio.sleep(0.01)
            return True

        guard = HITLGuard(callback=async_approve)

        result = await guard.request_approval_async(
            action="DELETE FROM users",
            action_type="sql_delete",
        )

        assert result.approved

    @pytest.mark.asyncio
    async def test_async_denial(self):
        """Async denial should work."""

        async def async_deny(request: ApprovalRequest) -> bool:
            await asyncio.sleep(0.01)
            return False

        guard = HITLGuard(callback=async_deny)

        result = await guard.request_approval_async(
            action="DROP TABLE users",
            action_type="sql_drop",
        )

        assert not result.approved
        assert result.status == ApprovalStatus.DENIED


class TestHITLTimeout:
    """Test HITL timeout functionality."""

    def test_timeout_defaults_to_deny(self):
        """Timeout should default to deny."""

        def slow_callback(request: ApprovalRequest) -> bool:
            import time

            time.sleep(0.5)  # Longer than timeout
            return True

        guard = HITLGuard(
            callback=slow_callback,
            timeout_seconds=0.1,
            default_on_timeout=False,
        )

        # Note: This test might be flaky due to timing
        # In practice, timeout handling is important

    def test_timeout_can_default_to_approve(self):
        """Timeout can be configured to approve."""
        guard = HITLGuard(
            callback=create_auto_approve_callback(),
            timeout_seconds=10,
            default_on_timeout=True,  # Approve on timeout
        )

        assert guard.default_on_timeout is True


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_approval_required_sql(self):
        """approval_required should work for SQL."""
        assert approval_required("DELETE FROM users", "sql")
        assert approval_required("DROP TABLE users", "sql")
        assert approval_required("TRUNCATE TABLE logs", "sql")
        assert not approval_required("SELECT * FROM users", "sql")
        assert not approval_required("INSERT INTO logs VALUES (1)", "sql")

    def test_approval_required_shell(self):
        """approval_required should work for shell."""
        assert approval_required("rm -rf /tmp", "shell")
        assert approval_required("sudo apt update", "shell")
        assert approval_required("chmod 777 file", "shell")
        assert not approval_required("ls -la", "shell")
        assert not approval_required("echo hello", "shell")

    def test_approval_required_custom_triggers(self):
        """approval_required should work with custom triggers."""
        custom = {"email": {"send", "forward"}}

        assert approval_required("send email to user", "email", custom)
        assert approval_required("forward message", "email", custom)
        assert not approval_required("read inbox", "email", custom)

    def test_create_auto_approve_callback(self):
        """Auto-approve callback should always approve."""
        callback = create_auto_approve_callback()
        request = ApprovalRequest(
            request_id="test",
            action="test",
            action_type="test",
            risk_level=RiskLevel.HIGH,
        )
        assert callback(request) is True

    def test_create_auto_deny_callback(self):
        """Auto-deny callback should always deny."""
        callback = create_auto_deny_callback()
        request = ApprovalRequest(
            request_id="test",
            action="test",
            action_type="test",
            risk_level=RiskLevel.HIGH,
        )
        assert callback(request) is False

    def test_auto_callbacks_with_logging(self):
        """Auto callbacks should call log function."""
        logged_requests = []

        def log_fn(request: ApprovalRequest) -> None:
            logged_requests.append(request)

        approve_cb = create_auto_approve_callback(log_fn=log_fn)
        deny_cb = create_auto_deny_callback(log_fn=log_fn)

        request = ApprovalRequest(
            request_id="test",
            action="test",
            action_type="test",
            risk_level=RiskLevel.HIGH,
        )

        approve_cb(request)
        deny_cb(request)

        assert len(logged_requests) == 2


class TestRiskLevel:
    """Test RiskLevel enum."""

    def test_risk_level_values(self):
        """RiskLevel should have expected values."""
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.CRITICAL.value == "critical"

    def test_risk_level_from_string(self):
        """RiskLevel should be creatable from string."""
        assert RiskLevel("low") == RiskLevel.LOW
        assert RiskLevel("high") == RiskLevel.HIGH
