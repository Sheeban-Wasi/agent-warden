"""
Context/Identity Inspector.

Provides identity-centric access control for AI agents, enabling:
- Agent identity verification
- Tenant isolation
- Role-based access control (RBAC)
- Attribute-based access control (ABAC)
- Scope/permission enforcement

Example:
    >>> from warden import IdentityInspector, IdentityContext
    >>>
    >>> inspector = IdentityInspector(
    ...     allowed_agents={"analytics-bot", "support-bot"},
    ...     required_scopes={"read:users"},
    ... )
    >>>
    >>> context = IdentityContext(
    ...     agent_id="analytics-bot",
    ...     tenant_id="acme-corp",
    ...     scopes={"read:users", "read:reports"},
    ... )
    >>>
    >>> result = inspector.inspect("some_action", context)
    >>> if result.allowed:
    ...     perform_action()
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IdentityMode(Enum):
    """Identity inspection modes."""

    STRICT = "strict"  # All checks must pass
    PERMISSIVE = "permissive"  # Only explicit blocks are enforced
    MONITOR = "monitor"  # Log only, don't block


class IdentityViolationType(Enum):
    """Types of identity violations."""

    AGENT_NOT_ALLOWED = "agent_not_allowed"
    AGENT_BLOCKED = "agent_blocked"
    TENANT_NOT_ALLOWED = "tenant_not_allowed"
    TENANT_BLOCKED = "tenant_blocked"
    MISSING_SCOPE = "missing_scope"
    MISSING_ROLE = "missing_role"
    MISSING_PERMISSION = "missing_permission"
    ATTRIBUTE_MISMATCH = "attribute_mismatch"
    CONTEXT_REQUIRED = "context_required"


@dataclass
class IdentityContext:
    """
    Identity context for access control decisions.

    This contains information about who is making the request,
    used for authorization decisions.

    Attributes:
        agent_id: Identifier for the AI agent.
        user_id: Identifier for the human user (if any).
        tenant_id: Identifier for the tenant/organization.
        scopes: OAuth-style scopes granted to this identity.
        roles: Roles assigned to this identity.
        permissions: Explicit permissions granted.
        attributes: Additional attributes for ABAC.
        metadata: Extra metadata for logging/auditing.
    """

    agent_id: str | None = None
    user_id: str | None = None
    tenant_id: str | None = None
    scopes: set[str] = field(default_factory=set)
    roles: set[str] = field(default_factory=set)
    permissions: set[str] = field(default_factory=set)
    attributes: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        """Check if identity has a specific scope."""
        return scope in self.scopes

    def has_all_scopes(self, scopes: set[str]) -> bool:
        """Check if identity has all specified scopes."""
        return scopes.issubset(self.scopes)

    def has_any_scope(self, scopes: set[str]) -> bool:
        """Check if identity has any of the specified scopes."""
        return bool(self.scopes & scopes)

    def has_role(self, role: str) -> bool:
        """Check if identity has a specific role."""
        return role in self.roles

    def has_any_role(self, roles: set[str]) -> bool:
        """Check if identity has any of the specified roles."""
        return bool(self.roles & roles)

    def has_permission(self, permission: str) -> bool:
        """Check if identity has a specific permission."""
        return permission in self.permissions

    def get_attribute(self, key: str, default: Any = None) -> Any:
        """Get an attribute value."""
        return self.attributes.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "tenant_id": self.tenant_id,
            "scopes": list(self.scopes),
            "roles": list(self.roles),
            "permissions": list(self.permissions),
            "attributes": self.attributes,
            "metadata": self.metadata,
        }


@dataclass
class IdentityMatch:
    """A single identity violation."""

    violation_type: IdentityViolationType
    message: str
    required: str | set[str] | None = None
    actual: str | set[str] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "violation_type": self.violation_type.value,
            "message": self.message,
            "required": list(self.required) if isinstance(self.required, set) else self.required,
            "actual": list(self.actual) if isinstance(self.actual, set) else self.actual,
        }


@dataclass
class IdentityResult:
    """Result of identity inspection."""

    allowed: bool
    violations: list[IdentityMatch] = field(default_factory=list)
    context: IdentityContext | None = None
    mode: IdentityMode = IdentityMode.STRICT

    @property
    def blocked(self) -> bool:
        """Whether the action is blocked."""
        return not self.allowed

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for logging."""
        return {
            "allowed": self.allowed,
            "blocked": self.blocked,
            "mode": self.mode.value,
            "violations": [v.to_dict() for v in self.violations],
            "context": self.context.to_dict() if self.context else None,
        }


class IdentityInspector:
    """
    Identity-centric access control inspector.

    Enforces who can perform what actions based on identity attributes.

    Example:
        >>> inspector = IdentityInspector(
        ...     allowed_agents={"analytics-bot"},
        ...     required_scopes={"read:data"},
        ...     allowed_tenants={"acme-corp"},
        ... )
        >>>
        >>> context = IdentityContext(
        ...     agent_id="analytics-bot",
        ...     tenant_id="acme-corp",
        ...     scopes={"read:data", "write:data"},
        ... )
        >>>
        >>> result = inspector.inspect("query_database", context)
        >>> assert result.allowed
    """

    INSPECTOR_NAME = "identity_inspector"

    def __init__(
        self,
        mode: IdentityMode | str = IdentityMode.STRICT,
        # Agent control
        allowed_agents: set[str] | None = None,
        blocked_agents: set[str] | None = None,
        # Tenant control
        allowed_tenants: set[str] | None = None,
        blocked_tenants: set[str] | None = None,
        # Scope/Role/Permission requirements
        required_scopes: set[str] | None = None,
        required_any_scope: set[str] | None = None,
        required_roles: set[str] | None = None,
        required_any_role: set[str] | None = None,
        required_permissions: set[str] | None = None,
        # Attribute requirements
        required_attributes: dict[str, Any] | None = None,
        # Context requirements
        require_agent_id: bool = False,
        require_tenant_id: bool = False,
        require_user_id: bool = False,
    ) -> None:
        """
        Initialize the identity inspector.

        Args:
            mode: Inspection mode (strict, permissive, monitor).
            allowed_agents: Only these agents are allowed (allowlist).
            blocked_agents: These agents are blocked (blocklist).
            allowed_tenants: Only these tenants are allowed.
            blocked_tenants: These tenants are blocked.
            required_scopes: All these scopes must be present.
            required_any_scope: At least one of these scopes must be present.
            required_roles: All these roles must be present.
            required_any_role: At least one of these roles must be present.
            required_permissions: All these permissions must be present.
            required_attributes: Attribute key-value pairs that must match.
            require_agent_id: Require agent_id to be set.
            require_tenant_id: Require tenant_id to be set.
            require_user_id: Require user_id to be set.
        """
        self.mode = IdentityMode(mode) if isinstance(mode, str) else mode

        # Agent control
        self.allowed_agents = allowed_agents
        self.blocked_agents = blocked_agents or set()

        # Tenant control
        self.allowed_tenants = allowed_tenants
        self.blocked_tenants = blocked_tenants or set()

        # Scope/Role/Permission requirements
        self.required_scopes = required_scopes or set()
        self.required_any_scope = required_any_scope
        self.required_roles = required_roles or set()
        self.required_any_role = required_any_role
        self.required_permissions = required_permissions or set()

        # Attribute requirements
        self.required_attributes = required_attributes or {}

        # Context requirements
        self.require_agent_id = require_agent_id
        self.require_tenant_id = require_tenant_id
        self.require_user_id = require_user_id

    def inspect(
        self,
        action: str | None = None,
        context: IdentityContext | None = None,
    ) -> IdentityResult:
        """
        Inspect an action against identity context.

        Args:
            action: The action being performed (for logging).
            context: Identity context with agent/user/tenant info.

        Returns:
            IdentityResult with allowed/blocked status and violations.
        """
        violations: list[IdentityMatch] = []

        # If no context provided, check if any context is required
        if context is None:
            if self.require_agent_id or self.require_tenant_id or self.require_user_id:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.CONTEXT_REQUIRED,
                        message="Identity context is required but not provided",
                    )
                )
                return self._create_result(violations, context)
            # No context and no requirements - allow
            return IdentityResult(allowed=True, context=context, mode=self.mode)

        # Check context requirements
        violations.extend(self._check_context_requirements(context))

        # Check agent
        violations.extend(self._check_agent(context))

        # Check tenant
        violations.extend(self._check_tenant(context))

        # Check scopes
        violations.extend(self._check_scopes(context))

        # Check roles
        violations.extend(self._check_roles(context))

        # Check permissions
        violations.extend(self._check_permissions(context))

        # Check attributes
        violations.extend(self._check_attributes(context))

        return self._create_result(violations, context)

    def _create_result(
        self,
        violations: list[IdentityMatch],
        context: IdentityContext | None,
    ) -> IdentityResult:
        """Create result based on violations and mode."""
        if self.mode == IdentityMode.MONITOR:
            # In monitor mode, always allow but include violations
            return IdentityResult(
                allowed=True,
                violations=violations,
                context=context,
                mode=self.mode,
            )

        return IdentityResult(
            allowed=len(violations) == 0,
            violations=violations,
            context=context,
            mode=self.mode,
        )

    def _check_context_requirements(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check if required context fields are present."""
        violations = []

        if self.require_agent_id and not context.agent_id:
            violations.append(
                IdentityMatch(
                    violation_type=IdentityViolationType.CONTEXT_REQUIRED,
                    message="agent_id is required but not provided",
                    required="agent_id",
                )
            )

        if self.require_tenant_id and not context.tenant_id:
            violations.append(
                IdentityMatch(
                    violation_type=IdentityViolationType.CONTEXT_REQUIRED,
                    message="tenant_id is required but not provided",
                    required="tenant_id",
                )
            )

        if self.require_user_id and not context.user_id:
            violations.append(
                IdentityMatch(
                    violation_type=IdentityViolationType.CONTEXT_REQUIRED,
                    message="user_id is required but not provided",
                    required="user_id",
                )
            )

        return violations

    def _check_agent(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check agent allowlist/blocklist."""
        violations = []

        if context.agent_id:
            # Check blocklist first
            if context.agent_id in self.blocked_agents:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.AGENT_BLOCKED,
                        message=f"Agent '{context.agent_id}' is blocked",
                        actual=context.agent_id,
                    )
                )
            # Check allowlist
            elif self.allowed_agents is not None:
                if context.agent_id not in self.allowed_agents:
                    violations.append(
                        IdentityMatch(
                            violation_type=IdentityViolationType.AGENT_NOT_ALLOWED,
                            message=f"Agent '{context.agent_id}' is not in allowed list",
                            required=self.allowed_agents,
                            actual=context.agent_id,
                        )
                    )

        return violations

    def _check_tenant(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check tenant allowlist/blocklist."""
        violations = []

        if context.tenant_id:
            # Check blocklist first
            if context.tenant_id in self.blocked_tenants:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.TENANT_BLOCKED,
                        message=f"Tenant '{context.tenant_id}' is blocked",
                        actual=context.tenant_id,
                    )
                )
            # Check allowlist
            elif self.allowed_tenants is not None:
                if context.tenant_id not in self.allowed_tenants:
                    violations.append(
                        IdentityMatch(
                            violation_type=IdentityViolationType.TENANT_NOT_ALLOWED,
                            message=f"Tenant '{context.tenant_id}' is not in allowed list",
                            required=self.allowed_tenants,
                            actual=context.tenant_id,
                        )
                    )

        return violations

    def _check_scopes(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check required scopes."""
        violations = []

        # Check required scopes (all must be present)
        if self.required_scopes:
            missing = self.required_scopes - context.scopes
            if missing:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.MISSING_SCOPE,
                        message=f"Missing required scopes: {missing}",
                        required=self.required_scopes,
                        actual=context.scopes,
                    )
                )

        # Check required_any_scope (at least one must be present)
        if self.required_any_scope:
            if not context.has_any_scope(self.required_any_scope):
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.MISSING_SCOPE,
                        message=f"At least one of these scopes required: {self.required_any_scope}",
                        required=self.required_any_scope,
                        actual=context.scopes,
                    )
                )

        return violations

    def _check_roles(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check required roles."""
        violations = []

        # Check required roles (all must be present)
        if self.required_roles:
            missing = self.required_roles - context.roles
            if missing:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.MISSING_ROLE,
                        message=f"Missing required roles: {missing}",
                        required=self.required_roles,
                        actual=context.roles,
                    )
                )

        # Check required_any_role (at least one must be present)
        if self.required_any_role:
            if not context.has_any_role(self.required_any_role):
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.MISSING_ROLE,
                        message=f"At least one of these roles required: {self.required_any_role}",
                        required=self.required_any_role,
                        actual=context.roles,
                    )
                )

        return violations

    def _check_permissions(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check required permissions."""
        violations = []

        if self.required_permissions:
            missing = self.required_permissions - context.permissions
            if missing:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.MISSING_PERMISSION,
                        message=f"Missing required permissions: {missing}",
                        required=self.required_permissions,
                        actual=context.permissions,
                    )
                )

        return violations

    def _check_attributes(self, context: IdentityContext) -> list[IdentityMatch]:
        """Check required attribute values."""
        violations = []

        for key, expected_value in self.required_attributes.items():
            actual_value = context.get_attribute(key)
            if actual_value != expected_value:
                violations.append(
                    IdentityMatch(
                        violation_type=IdentityViolationType.ATTRIBUTE_MISMATCH,
                        message=f"Attribute '{key}' mismatch: expected {expected_value}, got {actual_value}",
                        required=str(expected_value),
                        actual=str(actual_value),
                    )
                )

        return violations


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def check_identity(
    context: IdentityContext,
    allowed_agents: set[str] | None = None,
    allowed_tenants: set[str] | None = None,
    required_scopes: set[str] | None = None,
) -> bool:
    """
    Quick check if identity is allowed.

    Args:
        context: Identity context to check.
        allowed_agents: Allowed agent IDs.
        allowed_tenants: Allowed tenant IDs.
        required_scopes: Required scopes.

    Returns:
        True if identity is allowed, False otherwise.
    """
    inspector = IdentityInspector(
        allowed_agents=allowed_agents,
        allowed_tenants=allowed_tenants,
        required_scopes=required_scopes,
    )
    result = inspector.inspect(context=context)
    return result.allowed


def inspect_identity(
    context: IdentityContext,
    **kwargs: Any,
) -> IdentityResult:
    """
    Full identity inspection with detailed result.

    Args:
        context: Identity context to inspect.
        **kwargs: Additional arguments passed to IdentityInspector.

    Returns:
        IdentityResult with allowed/blocked status and violations.
    """
    inspector = IdentityInspector(**kwargs)
    return inspector.inspect(context=context)


def create_identity_context(
    agent_id: str | None = None,
    user_id: str | None = None,
    tenant_id: str | None = None,
    scopes: list[str] | set[str] | None = None,
    roles: list[str] | set[str] | None = None,
    permissions: list[str] | set[str] | None = None,
    **attributes: Any,
) -> IdentityContext:
    """
    Create an identity context with the given attributes.

    Args:
        agent_id: Agent identifier.
        user_id: User identifier.
        tenant_id: Tenant identifier.
        scopes: OAuth-style scopes.
        roles: Assigned roles.
        permissions: Explicit permissions.
        **attributes: Additional attributes.

    Returns:
        IdentityContext instance.
    """
    return IdentityContext(
        agent_id=agent_id,
        user_id=user_id,
        tenant_id=tenant_id,
        scopes=set(scopes) if scopes else set(),
        roles=set(roles) if roles else set(),
        permissions=set(permissions) if permissions else set(),
        attributes=attributes,
    )
