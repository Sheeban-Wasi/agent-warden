"""
Policy Engine for Agent-Warden.

Allows defining security rules in YAML configuration files instead of code.
Supports agent-specific rules, environment-based policies, and hot reload.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from warden.core.inspectors.sql import SQLInspector, SQLMode
from warden.core.verdict import Verdict


@dataclass
class SQLPolicy:
    """SQL-specific policy configuration."""

    mode: SQLMode = SQLMode.READ_ONLY
    allowed_tables: frozenset[str] = field(default_factory=frozenset)
    blocked_tables: frozenset[str] = field(default_factory=frozenset)
    max_query_length: int = 100_000
    fail_closed: bool = True
    dialect: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SQLPolicy:
        """Create SQLPolicy from dictionary."""
        mode_str = data.get("mode", "read-only")
        mode_map = {
            "read-only": SQLMode.READ_ONLY,
            "safe-write": SQLMode.SAFE_WRITE,
            "strict": SQLMode.STRICT,
            "monitor": SQLMode.MONITOR,
        }
        mode = mode_map.get(mode_str, SQLMode.READ_ONLY)

        return cls(
            mode=mode,
            allowed_tables=frozenset(data.get("allowed_tables", [])),
            blocked_tables=frozenset(data.get("blocked_tables", [])),
            max_query_length=data.get("max_query_length", 100_000),
            fail_closed=data.get("fail_closed", True),
            dialect=data.get("dialect"),
        )


@dataclass
class AgentPolicy:
    """Policy for a specific agent."""

    name: str
    sql: SQLPolicy | None = None
    description: str = ""
    enabled: bool = True

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> AgentPolicy:
        """Create AgentPolicy from dictionary."""
        sql_data = data.get("sql")
        sql_policy = SQLPolicy.from_dict(sql_data) if sql_data else None

        return cls(
            name=name,
            sql=sql_policy,
            description=data.get("description", ""),
            enabled=data.get("enabled", True),
        )


@dataclass
class RateLimits:
    """Rate limiting configuration."""

    max_queries_per_minute: int = 0  # 0 = unlimited
    max_queries_per_hour: int = 0
    max_blocked_per_minute: int = 10  # Alert threshold

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RateLimits:
        """Create RateLimits from dictionary."""
        return cls(
            max_queries_per_minute=data.get("max_queries_per_minute", 0),
            max_queries_per_hour=data.get("max_queries_per_hour", 0),
            max_blocked_per_minute=data.get("max_blocked_per_minute", 10),
        )


@dataclass
class Policy:
    """
    Complete security policy configuration.

    A Policy defines:
    - Default SQL rules (applied to all agents)
    - Agent-specific overrides
    - Rate limits
    - Metadata (version, name, description)
    """

    version: str = "1.0"
    name: str = "default"
    description: str = ""
    environment: str = "production"

    # Default SQL policy (applies to all agents unless overridden)
    sql: SQLPolicy = field(default_factory=SQLPolicy)

    # Agent-specific policies (override defaults)
    agents: dict[str, AgentPolicy] = field(default_factory=dict)

    # Rate limits
    limits: RateLimits = field(default_factory=RateLimits)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        """Create Policy from dictionary."""
        # Parse default SQL policy
        sql_data = data.get("sql", {})
        sql_policy = SQLPolicy.from_dict(sql_data)

        # Parse agent-specific policies
        agents_data = data.get("agents", {})
        agents = {
            name: AgentPolicy.from_dict(name, agent_data)
            for name, agent_data in agents_data.items()
        }

        # Parse rate limits
        limits_data = data.get("limits", {})
        limits = RateLimits.from_dict(limits_data)

        return cls(
            version=data.get("version", "1.0"),
            name=data.get("name", "default"),
            description=data.get("description", ""),
            environment=data.get("environment", "production"),
            sql=sql_policy,
            agents=agents,
            limits=limits,
        )

    @classmethod
    def from_yaml(cls, yaml_str: str) -> Policy:
        """Create Policy from YAML string."""
        data = yaml.safe_load(yaml_str)
        return cls.from_dict(data or {})

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        """Load Policy from YAML file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with open(path, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    def get_sql_policy_for_agent(self, agent_name: str | None = None) -> SQLPolicy:
        """
        Get the SQL policy for a specific agent.

        If agent has custom policy, use it. Otherwise, use default.
        """
        if agent_name and agent_name in self.agents:
            agent_policy = self.agents[agent_name]
            if agent_policy.sql:
                return agent_policy.sql

        return self.sql

    def to_dict(self) -> dict[str, Any]:
        """Convert Policy to dictionary."""
        return {
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "environment": self.environment,
            "sql": {
                "mode": self.sql.mode.value,
                "allowed_tables": list(self.sql.allowed_tables),
                "blocked_tables": list(self.sql.blocked_tables),
                "max_query_length": self.sql.max_query_length,
                "fail_closed": self.sql.fail_closed,
                "dialect": self.sql.dialect,
            },
            "agents": {
                name: {
                    "description": agent.description,
                    "enabled": agent.enabled,
                    "sql": {
                        "mode": agent.sql.mode.value,
                        "allowed_tables": list(agent.sql.allowed_tables),
                        "blocked_tables": list(agent.sql.blocked_tables),
                    }
                    if agent.sql
                    else None,
                }
                for name, agent in self.agents.items()
            },
            "limits": {
                "max_queries_per_minute": self.limits.max_queries_per_minute,
                "max_queries_per_hour": self.limits.max_queries_per_hour,
                "max_blocked_per_minute": self.limits.max_blocked_per_minute,
            },
        }


class PolicyEngine:
    """
    Evaluates SQL queries against a security policy.

    The PolicyEngine is the main interface for policy-based inspection.
    It creates SQLInspector instances configured according to the policy.

    Usage:
        policy = Policy.from_file("policy.yaml")
        engine = PolicyEngine(policy)

        # Check query for default agent
        verdict = engine.inspect("SELECT * FROM users")

        # Check query for specific agent
        verdict = engine.inspect("SELECT * FROM reports", agent="analytics-bot")
    """

    def __init__(self, policy: Policy):
        """Initialize PolicyEngine with a policy."""
        self.policy = policy
        self._inspectors: dict[str | None, SQLInspector] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        """Create PolicyEngine from a YAML policy file."""
        policy = Policy.from_file(path)
        return cls(policy)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> PolicyEngine:
        """Create PolicyEngine from a YAML string."""
        policy = Policy.from_yaml(yaml_str)
        return cls(policy)

    @classmethod
    def from_env(cls, env_var: str = "WARDEN_POLICY_FILE") -> PolicyEngine:
        """
        Create PolicyEngine from environment variable.

        Reads the policy file path from the specified environment variable.
        """
        path = os.environ.get(env_var)
        if not path:
            raise ValueError(f"Environment variable {env_var} not set")
        return cls.from_file(path)

    def _get_inspector(self, agent_name: str | None = None) -> SQLInspector:
        """Get or create an SQLInspector for the given agent."""
        if agent_name not in self._inspectors:
            sql_policy = self.policy.get_sql_policy_for_agent(agent_name)
            self._inspectors[agent_name] = SQLInspector(
                mode=sql_policy.mode.value,
                allowed_tables=sql_policy.allowed_tables,
                blocked_tables=sql_policy.blocked_tables,
                max_query_length=sql_policy.max_query_length,
                fail_closed=sql_policy.fail_closed,
                dialect=sql_policy.dialect,
            )
        return self._inspectors[agent_name]

    def inspect(self, query: str, agent: str | None = None) -> Verdict:
        """
        Inspect a SQL query against the policy.

        Args:
            query: The SQL query to inspect
            agent: Optional agent name for agent-specific rules

        Returns:
            Verdict with pass/block result and details
        """
        inspector = self._get_inspector(agent)
        return inspector.inspect(query)

    def check(self, query: str, agent: str | None = None) -> bool:
        """
        Quick check if a query is allowed.

        Args:
            query: The SQL query to check
            agent: Optional agent name for agent-specific rules

        Returns:
            True if query is allowed, False if blocked
        """
        verdict = self.inspect(query, agent)
        return not verdict.blocked

    def reload(self, path: str | Path | None = None) -> None:
        """
        Reload the policy from file.

        This enables hot-reload of policy changes without restart.
        """
        if path:
            self.policy = Policy.from_file(path)
        self._inspectors.clear()  # Clear cached inspectors

    def get_agent_names(self) -> list[str]:
        """Get list of all configured agent names."""
        return list(self.policy.agents.keys())

    def is_agent_enabled(self, agent_name: str) -> bool:
        """Check if an agent is enabled."""
        if agent_name in self.policy.agents:
            return self.policy.agents[agent_name].enabled
        return True  # Default to enabled if not explicitly configured
