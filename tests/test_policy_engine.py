"""
Tests for the Policy Engine.

Tests verify:
- YAML parsing and loading
- Default policy application
- Agent-specific policy overrides
- PolicyEngine inspection
- Integration with guards
"""

import pytest

from warden import (
    CriticalViolation,
    Policy,
    PolicyEngine,
    PolicyGuard,
    PolicyViolation,
    create_policy_guard,
)
from warden.core.inspectors.sql import SQLMode

# =============================================================================
# POLICY PARSING TESTS
# =============================================================================


class TestPolicyParsing:
    """Test Policy YAML parsing."""

    def test_parse_minimal_policy(self):
        """Parse minimal valid policy."""
        yaml = """
version: "1.0"
name: "test"
"""
        policy = Policy.from_yaml(yaml)
        assert policy.version == "1.0"
        assert policy.name == "test"
        assert policy.sql.mode == SQLMode.READ_ONLY  # default

    def test_parse_full_policy(self):
        """Parse complete policy with all fields."""
        yaml = """
version: "2.0"
name: "production"
description: "Production security policy"
environment: "prod"

sql:
  mode: safe-write
  allowed_tables:
    - logs
    - events
  blocked_tables:
    - credentials
    - secrets
  max_query_length: 50000
  fail_closed: true
  dialect: postgres

agents:
  analytics:
    description: "Analytics agent"
    enabled: true
    sql:
      mode: read-only
      allowed_tables:
        - reports

limits:
  max_queries_per_minute: 100
  max_queries_per_hour: 5000
"""
        policy = Policy.from_yaml(yaml)

        assert policy.version == "2.0"
        assert policy.name == "production"
        assert policy.environment == "prod"

        # Check SQL policy
        assert policy.sql.mode == SQLMode.SAFE_WRITE
        assert "logs" in policy.sql.allowed_tables
        assert "credentials" in policy.sql.blocked_tables
        assert policy.sql.max_query_length == 50000
        assert policy.sql.dialect == "postgres"

        # Check agent policy
        assert "analytics" in policy.agents
        assert policy.agents["analytics"].sql.mode == SQLMode.READ_ONLY

        # Check limits
        assert policy.limits.max_queries_per_minute == 100

    def test_parse_sql_modes(self):
        """Parse different SQL modes."""
        modes = [
            ("read-only", SQLMode.READ_ONLY),
            ("safe-write", SQLMode.SAFE_WRITE),
            ("strict", SQLMode.STRICT),
            ("monitor", SQLMode.MONITOR),
        ]

        for mode_str, expected_mode in modes:
            yaml = f"""
sql:
  mode: {mode_str}
"""
            policy = Policy.from_yaml(yaml)
            assert policy.sql.mode == expected_mode, f"Failed for mode: {mode_str}"

    def test_load_from_file(self, tmp_path):
        """Load policy from file."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
version: "1.0"
name: "file-test"
sql:
  mode: read-only
""")
        policy = Policy.from_file(policy_file)
        assert policy.name == "file-test"

    def test_file_not_found(self):
        """Raise error for missing file."""
        with pytest.raises(FileNotFoundError):
            Policy.from_file("/nonexistent/policy.yaml")

    def test_policy_to_dict(self):
        """Convert policy back to dict."""
        yaml = """
version: "1.0"
name: "test"
sql:
  mode: read-only
  blocked_tables:
    - secrets
"""
        policy = Policy.from_yaml(yaml)
        data = policy.to_dict()

        assert data["version"] == "1.0"
        assert data["name"] == "test"
        assert data["sql"]["mode"] == "read-only"
        assert "secrets" in data["sql"]["blocked_tables"]


# =============================================================================
# AGENT POLICY TESTS
# =============================================================================


class TestAgentPolicy:
    """Test agent-specific policy handling."""

    def test_get_default_policy(self):
        """Get default policy when no agent specified."""
        yaml = """
sql:
  mode: read-only
  blocked_tables:
    - credentials
"""
        policy = Policy.from_yaml(yaml)
        sql_policy = policy.get_sql_policy_for_agent(None)

        assert sql_policy.mode == SQLMode.READ_ONLY
        assert "credentials" in sql_policy.blocked_tables

    def test_get_agent_policy(self):
        """Get agent-specific policy."""
        yaml = """
sql:
  mode: read-only

agents:
  admin-bot:
    sql:
      mode: safe-write
      allowed_tables:
        - audit_logs
"""
        policy = Policy.from_yaml(yaml)

        # Default policy
        default = policy.get_sql_policy_for_agent(None)
        assert default.mode == SQLMode.READ_ONLY

        # Agent-specific policy
        admin = policy.get_sql_policy_for_agent("admin-bot")
        assert admin.mode == SQLMode.SAFE_WRITE
        assert "audit_logs" in admin.allowed_tables

    def test_unknown_agent_uses_default(self):
        """Unknown agent falls back to default policy."""
        yaml = """
sql:
  mode: read-only

agents:
  known-bot:
    sql:
      mode: safe-write
"""
        policy = Policy.from_yaml(yaml)
        unknown = policy.get_sql_policy_for_agent("unknown-bot")

        assert unknown.mode == SQLMode.READ_ONLY  # falls back to default

    def test_agent_without_sql_uses_default(self):
        """Agent without SQL config uses default SQL policy."""
        yaml = """
sql:
  mode: safe-write

agents:
  simple-bot:
    description: "No SQL override"
"""
        policy = Policy.from_yaml(yaml)
        simple = policy.get_sql_policy_for_agent("simple-bot")

        assert simple.mode == SQLMode.SAFE_WRITE  # uses default


# =============================================================================
# POLICY ENGINE TESTS
# =============================================================================


class TestPolicyEngine:
    """Test PolicyEngine inspection."""

    def test_engine_from_yaml(self):
        """Create engine from YAML string."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        assert engine.policy.sql.mode == SQLMode.READ_ONLY

    def test_engine_from_file(self, tmp_path):
        """Create engine from file."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
sql:
  mode: read-only
""")
        engine = PolicyEngine.from_file(policy_file)
        assert engine.check("SELECT 1")

    def test_inspect_allows_safe_query(self):
        """Engine allows safe queries."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        verdict = engine.inspect("SELECT * FROM users")

        assert not verdict.blocked

    def test_inspect_blocks_dangerous_query(self):
        """Engine blocks dangerous queries."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        verdict = engine.inspect("DROP TABLE users")

        assert verdict.blocked
        assert "critical" in verdict.reason.lower() or "drop" in verdict.reason.lower()

    def test_inspect_with_agent(self):
        """Engine uses agent-specific rules."""
        yaml = """
sql:
  mode: read-only
  blocked_tables:
    - secrets

agents:
  analytics:
    sql:
      mode: read-only
      blocked_tables:
        - users
"""
        engine = PolicyEngine.from_yaml(yaml)

        # Default: can access users
        verdict = engine.inspect("SELECT * FROM users")
        assert not verdict.blocked

        # Analytics: cannot access users
        verdict = engine.inspect("SELECT * FROM users", agent="analytics")
        assert verdict.blocked

    def test_check_shortcut(self):
        """Check method returns boolean."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)

        assert engine.check("SELECT 1") is True
        assert engine.check("DROP TABLE x") is False

    def test_reload_policy(self, tmp_path):
        """Reload policy from file."""
        policy_file = tmp_path / "policy.yaml"

        # Initial policy: read-only
        policy_file.write_text("""
sql:
  mode: read-only
""")
        engine = PolicyEngine.from_file(policy_file)
        assert not engine.check("INSERT INTO logs VALUES (1)")

        # Update policy: safe-write
        policy_file.write_text("""
sql:
  mode: safe-write
  allowed_tables:
    - logs
""")
        engine.reload(policy_file)
        assert engine.check("INSERT INTO logs VALUES (1)")

    def test_get_agent_names(self):
        """Get list of configured agents."""
        yaml = """
agents:
  bot-a:
    description: "Agent A"
  bot-b:
    description: "Agent B"
"""
        engine = PolicyEngine.from_yaml(yaml)
        names = engine.get_agent_names()

        assert "bot-a" in names
        assert "bot-b" in names

    def test_is_agent_enabled(self):
        """Check if agent is enabled."""
        yaml = """
agents:
  active-bot:
    enabled: true
  disabled-bot:
    enabled: false
"""
        engine = PolicyEngine.from_yaml(yaml)

        assert engine.is_agent_enabled("active-bot") is True
        assert engine.is_agent_enabled("disabled-bot") is False
        assert engine.is_agent_enabled("unknown-bot") is True  # default


# =============================================================================
# POLICY GUARD TESTS
# =============================================================================


class TestPolicyGuard:
    """Test PolicyGuard decorator."""

    def test_guard_allows_safe_query(self):
        """Guard allows safe queries."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        guard = PolicyGuard(engine, on_block="return_error")

        @guard
        def query(sql: str) -> dict:
            return {"data": sql}

        result = query("SELECT * FROM users")
        assert result["data"] == "SELECT * FROM users"

    def test_guard_blocks_dangerous_query(self):
        """Guard blocks dangerous queries."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        guard = PolicyGuard(engine, on_block="return_error")

        @guard
        def query(sql: str) -> dict:
            return {"data": sql}

        result = query("DROP TABLE users")
        assert result["blocked"] is True

    def test_guard_with_agent(self):
        """Guard uses agent-specific rules."""
        yaml = """
sql:
  mode: read-only

agents:
  analytics:
    sql:
      mode: read-only
      blocked_tables:
        - users
"""
        engine = PolicyEngine.from_yaml(yaml)

        # Default guard
        default_guard = PolicyGuard(engine, on_block="return_error")

        @default_guard
        def default_query(sql: str) -> dict:
            return {"data": sql}

        # Analytics guard
        analytics_guard = PolicyGuard(engine, agent="analytics", on_block="return_error")

        @analytics_guard
        def analytics_query(sql: str) -> dict:
            return {"data": sql}

        # Default can access users
        result = default_query("SELECT * FROM users")
        assert "data" in result

        # Analytics cannot access users
        result = analytics_query("SELECT * FROM users")
        assert result["blocked"] is True

    def test_guard_raises_exception(self):
        """Guard raises exception when configured."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        guard = PolicyGuard(engine, on_block="raise")

        @guard
        def query(sql: str) -> dict:
            return {"data": sql}

        with pytest.raises((PolicyViolation, CriticalViolation)):
            query("DROP TABLE users")

    def test_create_policy_guard_helper(self):
        """Test create_policy_guard convenience function."""
        yaml = """
sql:
  mode: read-only
"""
        engine = PolicyEngine.from_yaml(yaml)
        guard = create_policy_guard(engine, agent="test-agent", on_block="return_error")

        @guard
        def query(sql: str) -> dict:
            return {"data": sql}

        result = query("SELECT 1")
        assert "data" in result

    def test_guard_from_file_path(self, tmp_path):
        """Create guard directly from file path."""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text("""
sql:
  mode: read-only
""")
        guard = PolicyGuard(str(policy_file), on_block="return_error")

        @guard
        def query(sql: str) -> dict:
            return {"data": sql}

        result = query("SELECT 1")
        assert "data" in result


# =============================================================================
# RATE LIMITS TESTS
# =============================================================================


class TestRateLimits:
    """Test rate limit parsing."""

    def test_parse_rate_limits(self):
        """Parse rate limit configuration."""
        yaml = """
limits:
  max_queries_per_minute: 100
  max_queries_per_hour: 5000
  max_blocked_per_minute: 10
"""
        policy = Policy.from_yaml(yaml)

        assert policy.limits.max_queries_per_minute == 100
        assert policy.limits.max_queries_per_hour == 5000
        assert policy.limits.max_blocked_per_minute == 10

    def test_default_rate_limits(self):
        """Default rate limits when not specified."""
        yaml = """
version: "1.0"
"""
        policy = Policy.from_yaml(yaml)

        assert policy.limits.max_queries_per_minute == 0  # unlimited
        assert policy.limits.max_queries_per_hour == 0
        assert policy.limits.max_blocked_per_minute == 10
