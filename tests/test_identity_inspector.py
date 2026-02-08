"""
Tests for the Identity/Context Inspector.

These tests verify that the IdentityInspector correctly:
- Enforces agent allowlists/blocklists
- Enforces tenant allowlists/blocklists
- Checks required scopes
- Checks required roles
- Checks required permissions
- Validates attribute requirements
- Works in different modes (strict, permissive, monitor)
"""

import pytest

from warden.core.inspectors.identity import (
    IdentityContext,
    IdentityInspector,
    IdentityMatch,
    IdentityMode,
    IdentityResult,
    IdentityViolationType,
    check_identity,
    create_identity_context,
    inspect_identity,
)


# =============================================================================
# IDENTITY CONTEXT TESTS
# =============================================================================


class TestIdentityContext:
    """Test IdentityContext dataclass."""

    def test_default_context(self):
        """Default context should have empty collections."""
        ctx = IdentityContext()
        assert ctx.agent_id is None
        assert ctx.user_id is None
        assert ctx.tenant_id is None
        assert ctx.scopes == set()
        assert ctx.roles == set()
        assert ctx.permissions == set()

    def test_context_with_values(self):
        """Context should store provided values."""
        ctx = IdentityContext(
            agent_id="test-agent",
            user_id="user-123",
            tenant_id="acme-corp",
            scopes={"read:data", "write:data"},
            roles={"analyst"},
            permissions={"view_reports"},
        )
        assert ctx.agent_id == "test-agent"
        assert ctx.user_id == "user-123"
        assert ctx.tenant_id == "acme-corp"
        assert ctx.scopes == {"read:data", "write:data"}

    def test_has_scope(self):
        """has_scope should check for specific scope."""
        ctx = IdentityContext(scopes={"read:data", "write:data"})
        assert ctx.has_scope("read:data")
        assert ctx.has_scope("write:data")
        assert not ctx.has_scope("delete:data")

    def test_has_all_scopes(self):
        """has_all_scopes should check for all scopes."""
        ctx = IdentityContext(scopes={"read:data", "write:data", "admin"})
        assert ctx.has_all_scopes({"read:data", "write:data"})
        assert not ctx.has_all_scopes({"read:data", "delete:data"})

    def test_has_any_scope(self):
        """has_any_scope should check for any scope."""
        ctx = IdentityContext(scopes={"read:data"})
        assert ctx.has_any_scope({"read:data", "write:data"})
        assert not ctx.has_any_scope({"delete:data", "admin"})

    def test_has_role(self):
        """has_role should check for specific role."""
        ctx = IdentityContext(roles={"admin", "analyst"})
        assert ctx.has_role("admin")
        assert not ctx.has_role("superuser")

    def test_has_permission(self):
        """has_permission should check for specific permission."""
        ctx = IdentityContext(permissions={"view_reports", "edit_data"})
        assert ctx.has_permission("view_reports")
        assert not ctx.has_permission("delete_all")

    def test_get_attribute(self):
        """get_attribute should return attribute values."""
        ctx = IdentityContext(attributes={"department": "engineering", "level": 5})
        assert ctx.get_attribute("department") == "engineering"
        assert ctx.get_attribute("level") == 5
        assert ctx.get_attribute("missing") is None
        assert ctx.get_attribute("missing", "default") == "default"

    def test_to_dict(self):
        """to_dict should convert context to dictionary."""
        ctx = IdentityContext(
            agent_id="test-agent",
            scopes={"read:data"},
            roles={"analyst"},
        )
        d = ctx.to_dict()
        assert d["agent_id"] == "test-agent"
        assert "read:data" in d["scopes"]
        assert "analyst" in d["roles"]


# =============================================================================
# AGENT CONTROL TESTS
# =============================================================================


class TestAgentControl:
    """Test agent allowlist/blocklist."""

    def test_allowed_agents_pass(self):
        """Agent in allowlist should pass."""
        inspector = IdentityInspector(allowed_agents={"bot-a", "bot-b"})
        ctx = IdentityContext(agent_id="bot-a")
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_allowed_agents_block(self):
        """Agent not in allowlist should be blocked."""
        inspector = IdentityInspector(allowed_agents={"bot-a", "bot-b"})
        ctx = IdentityContext(agent_id="bot-c")
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.AGENT_NOT_ALLOWED

    def test_blocked_agents(self):
        """Agent in blocklist should be blocked."""
        inspector = IdentityInspector(blocked_agents={"malicious-bot"})
        ctx = IdentityContext(agent_id="malicious-bot")
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.AGENT_BLOCKED

    def test_blocked_takes_precedence(self):
        """Blocklist should take precedence over allowlist."""
        inspector = IdentityInspector(
            allowed_agents={"bot-a", "bot-b"},
            blocked_agents={"bot-a"},
        )
        ctx = IdentityContext(agent_id="bot-a")
        result = inspector.inspect(context=ctx)
        assert not result.allowed

    def test_no_agent_restrictions(self):
        """No agent restrictions should allow any agent."""
        inspector = IdentityInspector()
        ctx = IdentityContext(agent_id="any-bot")
        result = inspector.inspect(context=ctx)
        assert result.allowed


# =============================================================================
# TENANT CONTROL TESTS
# =============================================================================


class TestTenantControl:
    """Test tenant allowlist/blocklist."""

    def test_allowed_tenants_pass(self):
        """Tenant in allowlist should pass."""
        inspector = IdentityInspector(allowed_tenants={"acme-corp", "globex"})
        ctx = IdentityContext(tenant_id="acme-corp")
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_allowed_tenants_block(self):
        """Tenant not in allowlist should be blocked."""
        inspector = IdentityInspector(allowed_tenants={"acme-corp"})
        ctx = IdentityContext(tenant_id="unknown-corp")
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.TENANT_NOT_ALLOWED

    def test_blocked_tenants(self):
        """Tenant in blocklist should be blocked."""
        inspector = IdentityInspector(blocked_tenants={"suspended-corp"})
        ctx = IdentityContext(tenant_id="suspended-corp")
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.TENANT_BLOCKED


# =============================================================================
# SCOPE TESTS
# =============================================================================


class TestScopeRequirements:
    """Test scope requirements."""

    def test_required_scopes_pass(self):
        """Context with required scopes should pass."""
        inspector = IdentityInspector(required_scopes={"read:data", "write:data"})
        ctx = IdentityContext(scopes={"read:data", "write:data", "admin"})
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_required_scopes_missing(self):
        """Context missing required scopes should fail."""
        inspector = IdentityInspector(required_scopes={"read:data", "write:data"})
        ctx = IdentityContext(scopes={"read:data"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.MISSING_SCOPE

    def test_required_any_scope_pass(self):
        """Context with any required scope should pass."""
        inspector = IdentityInspector(required_any_scope={"admin", "superuser"})
        ctx = IdentityContext(scopes={"admin", "read:data"})
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_required_any_scope_missing(self):
        """Context without any required scope should fail."""
        inspector = IdentityInspector(required_any_scope={"admin", "superuser"})
        ctx = IdentityContext(scopes={"read:data", "write:data"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed


# =============================================================================
# ROLE TESTS
# =============================================================================


class TestRoleRequirements:
    """Test role requirements."""

    def test_required_roles_pass(self):
        """Context with required roles should pass."""
        inspector = IdentityInspector(required_roles={"analyst"})
        ctx = IdentityContext(roles={"analyst", "viewer"})
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_required_roles_missing(self):
        """Context missing required roles should fail."""
        inspector = IdentityInspector(required_roles={"admin"})
        ctx = IdentityContext(roles={"viewer"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.MISSING_ROLE

    def test_required_any_role_pass(self):
        """Context with any required role should pass."""
        inspector = IdentityInspector(required_any_role={"admin", "moderator"})
        ctx = IdentityContext(roles={"moderator"})
        result = inspector.inspect(context=ctx)
        assert result.allowed


# =============================================================================
# PERMISSION TESTS
# =============================================================================


class TestPermissionRequirements:
    """Test permission requirements."""

    def test_required_permissions_pass(self):
        """Context with required permissions should pass."""
        inspector = IdentityInspector(required_permissions={"view_reports"})
        ctx = IdentityContext(permissions={"view_reports", "edit_data"})
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_required_permissions_missing(self):
        """Context missing required permissions should fail."""
        inspector = IdentityInspector(required_permissions={"delete_all"})
        ctx = IdentityContext(permissions={"view_reports"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.MISSING_PERMISSION


# =============================================================================
# ATTRIBUTE TESTS
# =============================================================================


class TestAttributeRequirements:
    """Test attribute requirements."""

    def test_required_attributes_pass(self):
        """Context with matching attributes should pass."""
        inspector = IdentityInspector(required_attributes={"department": "engineering"})
        ctx = IdentityContext(attributes={"department": "engineering", "level": 5})
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_required_attributes_mismatch(self):
        """Context with mismatched attributes should fail."""
        inspector = IdentityInspector(required_attributes={"department": "engineering"})
        ctx = IdentityContext(attributes={"department": "sales"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.ATTRIBUTE_MISMATCH

    def test_required_attributes_missing(self):
        """Context without required attribute should fail."""
        inspector = IdentityInspector(required_attributes={"clearance": "secret"})
        ctx = IdentityContext(attributes={})
        result = inspector.inspect(context=ctx)
        assert not result.allowed


# =============================================================================
# CONTEXT REQUIREMENT TESTS
# =============================================================================


class TestContextRequirements:
    """Test context field requirements."""

    def test_require_agent_id_pass(self):
        """Context with agent_id should pass when required."""
        inspector = IdentityInspector(require_agent_id=True)
        ctx = IdentityContext(agent_id="my-agent")
        result = inspector.inspect(context=ctx)
        assert result.allowed

    def test_require_agent_id_missing(self):
        """Context without agent_id should fail when required."""
        inspector = IdentityInspector(require_agent_id=True)
        ctx = IdentityContext()
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.violations[0].violation_type == IdentityViolationType.CONTEXT_REQUIRED

    def test_require_tenant_id_missing(self):
        """Context without tenant_id should fail when required."""
        inspector = IdentityInspector(require_tenant_id=True)
        ctx = IdentityContext()
        result = inspector.inspect(context=ctx)
        assert not result.allowed

    def test_require_user_id_missing(self):
        """Context without user_id should fail when required."""
        inspector = IdentityInspector(require_user_id=True)
        ctx = IdentityContext()
        result = inspector.inspect(context=ctx)
        assert not result.allowed

    def test_no_context_when_required(self):
        """No context when fields required should fail."""
        inspector = IdentityInspector(require_agent_id=True)
        result = inspector.inspect(context=None)
        assert not result.allowed


# =============================================================================
# MODE TESTS
# =============================================================================


class TestModes:
    """Test different inspection modes."""

    def test_strict_mode_blocks(self):
        """Strict mode should block on violations."""
        inspector = IdentityInspector(
            mode=IdentityMode.STRICT,
            required_scopes={"admin"},
        )
        ctx = IdentityContext(scopes={"user"})
        result = inspector.inspect(context=ctx)
        assert not result.allowed
        assert result.mode == IdentityMode.STRICT

    def test_monitor_mode_allows(self):
        """Monitor mode should allow but record violations."""
        inspector = IdentityInspector(
            mode=IdentityMode.MONITOR,
            required_scopes={"admin"},
        )
        ctx = IdentityContext(scopes={"user"})
        result = inspector.inspect(context=ctx)
        assert result.allowed  # Allowed in monitor mode
        assert len(result.violations) > 0  # But violations recorded
        assert result.mode == IdentityMode.MONITOR

    def test_mode_from_string(self):
        """Mode can be specified as string."""
        inspector = IdentityInspector(mode="monitor")
        assert inspector.mode == IdentityMode.MONITOR


# =============================================================================
# CONVENIENCE FUNCTION TESTS
# =============================================================================


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_check_identity(self):
        """check_identity should return bool."""
        ctx = IdentityContext(agent_id="bot-a", scopes={"read:data"})

        assert check_identity(ctx, allowed_agents={"bot-a"})
        assert not check_identity(ctx, allowed_agents={"bot-b"})
        assert check_identity(ctx, required_scopes={"read:data"})
        assert not check_identity(ctx, required_scopes={"admin"})

    def test_inspect_identity(self):
        """inspect_identity should return full result."""
        ctx = IdentityContext(agent_id="bot-a")
        result = inspect_identity(ctx, blocked_agents={"bot-a"})
        assert isinstance(result, IdentityResult)
        assert not result.allowed

    def test_create_identity_context(self):
        """create_identity_context should create context."""
        ctx = create_identity_context(
            agent_id="test-bot",
            tenant_id="acme",
            scopes=["read:data", "write:data"],
            roles=["analyst"],
            department="engineering",
        )
        assert ctx.agent_id == "test-bot"
        assert ctx.tenant_id == "acme"
        assert ctx.scopes == {"read:data", "write:data"}
        assert ctx.roles == {"analyst"}
        assert ctx.attributes["department"] == "engineering"


# =============================================================================
# RESULT TESTS
# =============================================================================


class TestIdentityResult:
    """Test IdentityResult."""

    def test_blocked_property(self):
        """blocked should be inverse of allowed."""
        allowed_result = IdentityResult(allowed=True)
        assert not allowed_result.blocked

        blocked_result = IdentityResult(allowed=False)
        assert blocked_result.blocked

    def test_to_dict(self):
        """to_dict should include all fields."""
        ctx = IdentityContext(agent_id="test")
        result = IdentityResult(
            allowed=False,
            violations=[
                IdentityMatch(
                    violation_type=IdentityViolationType.MISSING_SCOPE,
                    message="Missing scope",
                    required={"admin"},
                    actual={"user"},
                )
            ],
            context=ctx,
            mode=IdentityMode.STRICT,
        )
        d = result.to_dict()
        assert d["allowed"] is False
        assert d["blocked"] is True
        assert d["mode"] == "strict"
        assert len(d["violations"]) == 1


# =============================================================================
# COMPLEX SCENARIO TESTS
# =============================================================================


class TestComplexScenarios:
    """Test complex multi-requirement scenarios."""

    def test_multi_tenant_agent_isolation(self):
        """Agents should be isolated by tenant."""
        inspector = IdentityInspector(
            allowed_agents={"analytics-bot"},
            allowed_tenants={"acme-corp"},
            required_scopes={"read:reports"},
        )

        # Correct agent, tenant, and scope - allowed
        ctx = IdentityContext(
            agent_id="analytics-bot",
            tenant_id="acme-corp",
            scopes={"read:reports", "read:data"},
        )
        assert inspector.inspect(context=ctx).allowed

        # Wrong tenant - blocked
        ctx = IdentityContext(
            agent_id="analytics-bot",
            tenant_id="other-corp",
            scopes={"read:reports"},
        )
        result = inspector.inspect(context=ctx)
        assert not result.allowed

    def test_rbac_with_scopes(self):
        """Combine role and scope requirements."""
        inspector = IdentityInspector(
            required_roles={"admin"},
            required_scopes={"write:config"},
        )

        # Has both - allowed
        ctx = IdentityContext(
            roles={"admin", "user"},
            scopes={"write:config", "read:data"},
        )
        assert inspector.inspect(context=ctx).allowed

        # Missing role - blocked
        ctx = IdentityContext(
            roles={"user"},
            scopes={"write:config"},
        )
        assert not inspector.inspect(context=ctx).allowed

        # Missing scope - blocked
        ctx = IdentityContext(
            roles={"admin"},
            scopes={"read:data"},
        )
        assert not inspector.inspect(context=ctx).allowed

    def test_no_context_no_requirements(self):
        """No context and no requirements should pass."""
        inspector = IdentityInspector()
        result = inspector.inspect(context=None)
        assert result.allowed
