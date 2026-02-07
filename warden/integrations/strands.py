"""
AWS Strands SDK Integration.

Provides the @guard decorator for protecting AI agent tools with Warden inspections.

The @guard decorator intercepts tool inputs, runs security inspections, and blocks
dangerous operations before they reach your database or API.

Example:
    from warden.integrations.strands import guard

    # Simple usage - protect a SQL tool
    @guard(sql=True)
    def execute_query(query: str) -> list[dict]:
        return db.execute(query)

    # With custom configuration
    @guard(
        sql=True,
        mode="read-only",
        on_block="raise",  # or "return_error"
        audit=True,
    )
    def run_sql(query: str) -> list[dict]:
        return db.execute(query)

    # The agent can now safely use this tool:
    result = execute_query("SELECT * FROM users")  # Works
    result = execute_query("DROP TABLE users")     # Blocked!

For AWS Strands SDK:
    from strands import Agent, tool
    from warden.integrations.strands import guard

    @tool
    @guard(sql=True)
    def database_query(query: str) -> str:
        '''Execute a SQL query and return results.'''
        return json.dumps(db.execute(query))

    agent = Agent(tools=[database_query])
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal, ParamSpec, TypeVar, overload

from warden.core.audit import AuditLevel, AuditLogger, LogDestination
from warden.core.inspectors.file import FileInspector
from warden.core.inspectors.pii import PIIInspector
from warden.core.inspectors.rag import RAGContext, RAGInspector
from warden.core.inspectors.shell import ShellInspector
from warden.core.inspectors.sql import SQLInspector
from warden.core.policy import Policy, PolicyEngine
from warden.core.verdict import Verdict
from warden.exceptions import CriticalViolation, PolicyViolation

P = ParamSpec("P")
R = TypeVar("R")


class BlockAction(Enum):
    """Action to take when a guard blocks an operation."""

    RAISE = "raise"  # Raise PolicyViolation exception
    RETURN_ERROR = "return_error"  # Return error dict to agent
    RETURN_NONE = "return_none"  # Return None


@dataclass
class GuardConfig:
    """
    Configuration for the @guard decorator.

    Attributes:
        sql: Enable SQL injection protection
        sql_mode: SQL inspection mode (read-only, safe-write, strict, monitor)
        sql_dialect: SQL dialect for parsing (mysql, postgres, etc.)
        sql_allowed_tables: Tables allowed for writes in safe-write mode
        sql_blocked_tables: Tables that are never allowed

        pii: Enable PII detection
        pii_strategy: How to handle PII (block, redact, mask, hash, monitor)
        pii_detect: List of PII types to detect
        pii_apply_to: Where to apply PII detection (input, output, both)

        on_block: Action when blocked (raise, return_error, return_none)
        error_message: Custom error message template

        audit: Enable audit logging
        audit_logger: Custom audit logger instance
        audit_level: Minimum level to log (all, block, none)
        audit_context: Static context to include in all logs

        param_name: Name of parameter to inspect (default: first string param)
    """

    # SQL inspection settings
    sql: bool = True
    sql_mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only"
    sql_dialect: str | None = None
    sql_allowed_tables: set[str] | None = None
    sql_blocked_tables: set[str] | None = None

    # PII inspection settings
    pii: bool = False
    pii_strategy: Literal["block", "redact", "mask", "hash", "monitor"] = "block"
    pii_detect: list[str] | None = None
    pii_apply_to: Literal["input", "output", "both"] = "input"

    # File access settings
    file_access: bool = False
    file_mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist"
    file_base_directory: str | None = None
    file_allowed_paths: set[str] | None = None
    file_blocked_paths: set[str] | None = None
    file_blocked_extensions: set[str] | None = None

    # Shell command settings
    shell: bool = False
    shell_mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted"
    shell_allowed_commands: set[str] | None = None
    shell_blocked_commands: set[str] | None = None
    shell_blocked_patterns: list[str] | None = None
    shell_allow_operators: bool = False

    # RAG document security settings (applied to output)
    rag: bool = False
    rag_mode: Literal["strict", "filtered", "monitor"] = "filtered"
    rag_allowed_collections: set[str] | None = None
    rag_blocked_collections: set[str] | None = None
    rag_classification_max: str | None = None
    rag_scan_pii: bool = True
    rag_pii_strategy: Literal["block", "redact"] = "redact"
    rag_scan_secrets: bool = True
    rag_scan_prompt_injection: bool = True
    rag_max_documents: int = 20
    rag_context: dict[str, Any] | None = None  # Static ABAC context

    # Block handling
    on_block: Literal["raise", "return_error", "return_none"] = "raise"
    error_message: str = "Operation blocked by security policy: {reason}"

    # Audit logging
    audit: bool = True
    audit_logger: AuditLogger | None = None
    audit_level: Literal["all", "block", "none"] = "all"
    audit_context: dict[str, Any] = field(default_factory=dict)

    # Parameter selection
    param_name: str | None = None  # If None, uses first string parameter


class ToolGuard:
    """
    Reusable guard instance for protecting multiple tools with the same config.

    Example:
        # Create a shared guard
        sql_guard = ToolGuard(
            sql=True,
            mode="read-only",
            audit_logger=my_logger,
        )

        # Apply to multiple tools
        @sql_guard
        def query_users(sql: str): ...

        @sql_guard
        def query_orders(sql: str): ...

        # PII protection
        pii_guard = ToolGuard(
            sql=False,
            pii=True,
            pii_strategy="redact",
        )

        @pii_guard
        def process_text(text: str): ...
    """

    def __init__(
        self,
        sql: bool = True,
        mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
        dialect: str | None = None,
        allowed_tables: set[str] | None = None,
        blocked_tables: set[str] | None = None,
        pii: bool = False,
        pii_strategy: Literal["block", "redact", "mask", "hash", "monitor"] = "block",
        pii_detect: list[str] | None = None,
        pii_apply_to: Literal["input", "output", "both"] = "input",
        file_access: bool = False,
        file_mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist",
        file_base_directory: str | None = None,
        file_allowed_paths: set[str] | None = None,
        file_blocked_paths: set[str] | None = None,
        file_blocked_extensions: set[str] | None = None,
        shell: bool = False,
        shell_mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted",
        shell_allowed_commands: set[str] | None = None,
        shell_blocked_commands: set[str] | None = None,
        shell_blocked_patterns: list[str] | None = None,
        shell_allow_operators: bool = False,
        rag: bool = False,
        rag_mode: Literal["strict", "filtered", "monitor"] = "filtered",
        rag_allowed_collections: set[str] | None = None,
        rag_blocked_collections: set[str] | None = None,
        rag_classification_max: str | None = None,
        rag_scan_pii: bool = True,
        rag_pii_strategy: Literal["block", "redact"] = "redact",
        rag_scan_secrets: bool = True,
        rag_scan_prompt_injection: bool = True,
        rag_max_documents: int = 20,
        rag_context: dict[str, Any] | None = None,
        on_block: Literal["raise", "return_error", "return_none"] = "raise",
        error_message: str = "Operation blocked by security policy: {reason}",
        audit: bool = True,
        audit_logger: AuditLogger | None = None,
        audit_level: Literal["all", "block", "none"] = "all",
        audit_context: dict[str, Any] | None = None,
        param_name: str | None = None,
    ) -> None:
        self.config = GuardConfig(
            sql=sql,
            sql_mode=mode,
            sql_dialect=dialect,
            sql_allowed_tables=allowed_tables,
            sql_blocked_tables=blocked_tables,
            pii=pii,
            pii_strategy=pii_strategy,
            pii_detect=pii_detect,
            pii_apply_to=pii_apply_to,
            file_access=file_access,
            file_mode=file_mode,
            file_base_directory=file_base_directory,
            file_allowed_paths=file_allowed_paths,
            file_blocked_paths=file_blocked_paths,
            file_blocked_extensions=file_blocked_extensions,
            shell=shell,
            shell_mode=shell_mode,
            shell_allowed_commands=shell_allowed_commands,
            shell_blocked_commands=shell_blocked_commands,
            shell_blocked_patterns=shell_blocked_patterns,
            shell_allow_operators=shell_allow_operators,
            rag=rag,
            rag_mode=rag_mode,
            rag_allowed_collections=rag_allowed_collections,
            rag_blocked_collections=rag_blocked_collections,
            rag_classification_max=rag_classification_max,
            rag_scan_pii=rag_scan_pii,
            rag_pii_strategy=rag_pii_strategy,
            rag_scan_secrets=rag_scan_secrets,
            rag_scan_prompt_injection=rag_scan_prompt_injection,
            rag_max_documents=rag_max_documents,
            rag_context=rag_context,
            on_block=on_block,
            error_message=error_message,
            audit=audit,
            audit_logger=audit_logger,
            audit_level=audit_level,
            audit_context=audit_context or {},
            param_name=param_name,
        )

        # Initialize SQL inspector if needed
        self._sql_inspector: SQLInspector | None = None
        if sql:
            self._sql_inspector = SQLInspector(
                mode=mode,
                dialect=dialect,
                allowed_tables=allowed_tables,
                blocked_tables=blocked_tables,
            )

        # Initialize PII inspector if needed
        self._pii_inspector: PIIInspector | None = None
        if pii:
            self._pii_inspector = PIIInspector(
                strategy=pii_strategy,
                detect_types=pii_detect,
            )

        # Initialize File inspector if needed
        self._file_inspector: FileInspector | None = None
        if file_access:
            self._file_inspector = FileInspector(
                mode=file_mode,
                base_directory=file_base_directory,
                allowed_paths=file_allowed_paths,
                blocked_paths=file_blocked_paths,
                blocked_extensions=file_blocked_extensions,
            )

        # Initialize Shell inspector if needed
        self._shell_inspector: ShellInspector | None = None
        if shell:
            self._shell_inspector = ShellInspector(
                mode=shell_mode,
                allowed_commands=shell_allowed_commands,
                blocked_commands=shell_blocked_commands,
                blocked_patterns=shell_blocked_patterns,
                allow_operators=shell_allow_operators,
            )

        # Initialize RAG inspector if needed (inspects output, not input)
        self._rag_inspector: RAGInspector | None = None
        self._rag_context: RAGContext | None = None
        if rag:
            self._rag_inspector = RAGInspector(
                mode=rag_mode,
                allowed_collections=rag_allowed_collections,
                blocked_collections=rag_blocked_collections,
                classification_max=rag_classification_max,
                scan_pii=rag_scan_pii,
                pii_strategy=rag_pii_strategy,
                scan_secrets=rag_scan_secrets,
                scan_prompt_injection=rag_scan_prompt_injection,
                max_documents=rag_max_documents,
            )
            if rag_context:
                self._rag_context = RAGContext.from_dict(rag_context)

        # Initialize audit logger if needed
        self._audit_logger: AuditLogger | None = None
        if audit and audit_logger is None:
            level_map = {
                "all": AuditLevel.ALL,
                "block": AuditLevel.BLOCK,
                "none": AuditLevel.NONE,
            }
            self._audit_logger = AuditLogger(
                destinations=[LogDestination.STDOUT],
                min_level=level_map.get(audit_level, AuditLevel.ALL),
            )
        elif audit_logger:
            self._audit_logger = audit_logger

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorate a function with this guard."""
        return self._wrap_function(func)

    def _wrap_function(self, func: Callable[P, R]) -> Callable[P, R]:
        """Wrap a sync or async function with guard protection."""

        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return await self._execute_async(func, args, kwargs)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return self._execute_sync(func, args, kwargs)

            return sync_wrapper  # type: ignore

    def _execute_sync(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute sync function with guard protection."""
        # Extract the value to inspect
        value = self._extract_value(func, args, kwargs)

        # Run input inspections
        verdict, sanitized_input = self._inspect_input(value, func.__name__)

        # Handle blocked result
        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        # If PII was sanitized on input, update the argument
        if sanitized_input is not None and sanitized_input != value:
            args, kwargs = self._replace_value(func, args, kwargs, sanitized_input)

        # Execute the original function
        result = func(*args, **kwargs)

        # Run output inspections if needed
        if self._pii_inspector and self.config.pii_apply_to in ("output", "both"):
            result = self._inspect_output(result, func.__name__)

        # RAG inspection on output (filters retrieved documents)
        if self._rag_inspector and self.config.rag:
            result = self._inspect_rag_output(result, func.__name__)

        return result

    async def _execute_async(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute async function with guard protection."""
        # Extract the value to inspect
        value = self._extract_value(func, args, kwargs)

        # Run input inspections
        verdict, sanitized_input = self._inspect_input(value, func.__name__)

        # Handle blocked result
        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        # If PII was sanitized on input, update the argument
        if sanitized_input is not None and sanitized_input != value:
            args, kwargs = self._replace_value(func, args, kwargs, sanitized_input)

        # Execute the original function
        result = await func(*args, **kwargs)

        # Run output inspections if needed
        if self._pii_inspector and self.config.pii_apply_to in ("output", "both"):
            result = self._inspect_output(result, func.__name__)

        # RAG inspection on output (filters retrieved documents)
        if self._rag_inspector and self.config.rag:
            result = self._inspect_rag_output(result, func.__name__)

        return result

    def _extract_value(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str | None:
        """Extract the value to inspect from function arguments."""

        # If param_name specified, use that
        if self.config.param_name:
            if self.config.param_name in kwargs:
                return kwargs[self.config.param_name]

            # Check positional args by parameter name
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if self.config.param_name in params:
                idx = params.index(self.config.param_name)
                if idx < len(args):
                    return args[idx]

            return None

        # Auto-detect: use first string argument
        # Check kwargs first
        for value in kwargs.values():
            if isinstance(value, str):
                return value

        # Check positional args
        for arg in args:
            if isinstance(arg, str):
                return arg

        return None

    def _inspect_input(
        self, value: str | None, func_name: str
    ) -> tuple[Verdict | None, str | None]:
        """
        Run input inspections on the value.

        Returns:
            Tuple of (verdict, sanitized_value).
            If PII is redacted/masked/hashed, sanitized_value contains the clean text.
        """
        if value is None:
            return None, None

        verdict: Verdict | None = None
        sanitized_value: str | None = value

        # SQL inspection
        if self._sql_inspector and self.config.sql:
            verdict = self._sql_inspector.inspect(value)
            if self._audit_logger:
                context = {
                    "tool": func_name,
                    "inspector": "sql",
                    **self.config.audit_context,
                }
                self._audit_logger.log(verdict, context=context)

            if verdict.blocked:
                return verdict, None

        # File access inspection
        if self._file_inspector and self.config.file_access:
            file_result = self._file_inspector.inspect(value)
            if self._audit_logger:
                context = {
                    "tool": func_name,
                    "inspector": "file",
                    **self.config.audit_context,
                }
                self._audit_logger.log(file_result.verdict, context=context)

            if file_result.verdict.blocked:
                return file_result.verdict, None

        # Shell command inspection
        if self._shell_inspector and self.config.shell:
            shell_result = self._shell_inspector.inspect(value)
            if self._audit_logger:
                context = {
                    "tool": func_name,
                    "inspector": "shell",
                    **self.config.audit_context,
                }
                self._audit_logger.log(shell_result.verdict, context=context)

            if shell_result.verdict.blocked:
                return shell_result.verdict, None

        # PII inspection on input
        if self._pii_inspector and self.config.pii_apply_to in ("input", "both"):
            pii_result = self._pii_inspector.inspect(value)

            if self._audit_logger and pii_result.has_pii:
                context = {
                    "tool": func_name,
                    "inspector": "pii",
                    "pii_types": [t.value for t in pii_result.pii_types_found],
                    **self.config.audit_context,
                }
                self._audit_logger.log(pii_result.verdict, context=context)

            if pii_result.verdict.blocked:
                return pii_result.verdict, None

            # Use sanitized text if PII was transformed
            sanitized_value = pii_result.sanitized_text

        return verdict, sanitized_value

    def _inspect_output(self, result: Any, func_name: str) -> Any:
        """
        Run PII inspection on output and sanitize if needed.

        Handles string results and dicts with string values.
        """
        if not self._pii_inspector:
            return result

        if isinstance(result, str):
            pii_result = self._pii_inspector.inspect(result)
            if self._audit_logger and pii_result.has_pii:
                context = {
                    "tool": func_name,
                    "inspector": "pii",
                    "direction": "output",
                    "pii_types": [t.value for t in pii_result.pii_types_found],
                    **self.config.audit_context,
                }
                self._audit_logger.log(pii_result.verdict, context=context)

            if pii_result.verdict.blocked:
                return self._handle_block(pii_result.verdict, func_name)

            return pii_result.sanitized_text

        elif isinstance(result, dict):
            # Recursively sanitize string values in dict
            sanitized = {}
            for key, val in result.items():
                if isinstance(val, str):
                    pii_result = self._pii_inspector.inspect(val)
                    if pii_result.verdict.blocked:
                        return self._handle_block(pii_result.verdict, func_name)
                    sanitized[key] = pii_result.sanitized_text
                else:
                    sanitized[key] = val
            return sanitized

        return result

    def _inspect_rag_output(self, result: Any, func_name: str) -> Any:
        """
        Inspect RAG output (retrieved documents) and filter based on security policy.

        RAG inspection is different from other inspectors - it filters the OUTPUT
        (the documents returned by the retrieval function) not the input.

        Args:
            result: The function's return value (should be list of documents)
            func_name: Name of the function for logging

        Returns:
            Filtered list of allowed documents, or blocks based on config
        """
        if not self._rag_inspector:
            return result

        # Handle different result formats
        documents: list[dict[str, Any]] = []

        if isinstance(result, list):
            documents = result
        elif isinstance(result, dict) and "documents" in result:
            # Common format: {"documents": [...], "metadata": ...}
            documents = result["documents"]
        else:
            # Can't inspect non-list results
            return result

        if not documents:
            return result

        # Run RAG inspection
        rag_result = self._rag_inspector.inspect(documents, self._rag_context)

        # Log the inspection
        if self._audit_logger:
            context = {
                "tool": func_name,
                "inspector": "rag",
                "documents_total": len(documents),
                "documents_allowed": len(rag_result.allowed_documents),
                "documents_blocked": len(rag_result.blocked_documents),
                **self.config.audit_context,
            }
            self._audit_logger.log(rag_result.verdict, context=context)

        # Handle based on mode and verdict
        if rag_result.verdict.blocked:
            # In strict mode with blocked verdict
            return self._handle_block(rag_result.verdict, func_name)

        # Return filtered documents
        filtered_docs = [doc.to_dict() for doc in rag_result.allowed_documents]

        # Preserve original format
        if isinstance(result, dict) and "documents" in result:
            return {**result, "documents": filtered_docs}

        return filtered_docs

    def _replace_value(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        new_value: str,
    ) -> tuple[tuple[Any, ...], dict[str, Any]]:
        """Replace the inspected value with a sanitized version."""
        # If param_name specified, replace in kwargs or positional
        if self.config.param_name:
            if self.config.param_name in kwargs:
                new_kwargs = dict(kwargs)
                new_kwargs[self.config.param_name] = new_value
                return args, new_kwargs

            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if self.config.param_name in params:
                idx = params.index(self.config.param_name)
                if idx < len(args):
                    new_args = list(args)
                    new_args[idx] = new_value
                    return tuple(new_args), kwargs

        # Auto-detect: replace first string argument
        for key, value in kwargs.items():
            if isinstance(value, str):
                new_kwargs = dict(kwargs)
                new_kwargs[key] = new_value
                return args, new_kwargs

        for i, arg in enumerate(args):
            if isinstance(arg, str):
                new_args = list(args)
                new_args[i] = new_value
                return tuple(new_args), kwargs

        return args, kwargs

    def _handle_block(self, verdict: Verdict, func_name: str) -> Any:
        """Handle a blocked operation based on config."""

        error_msg = self.config.error_message.format(
            reason=verdict.reason,
            rule=verdict.rule,
            inspector=verdict.inspector,
            tool=func_name,
        )

        action = BlockAction(self.config.on_block)

        if action == BlockAction.RAISE:
            # Raise exception for critical violations
            if verdict.rule in {"critical_node_detected", "schema_change_blocked"}:
                raise CriticalViolation(error_msg, verdict=verdict)
            raise PolicyViolation(error_msg, verdict=verdict)

        elif action == BlockAction.RETURN_ERROR:
            # Return error dict that agent can understand
            return {
                "error": True,
                "message": error_msg,
                "blocked": True,
                "reason": verdict.reason,
                "rule": verdict.rule,
            }

        elif action == BlockAction.RETURN_NONE:
            return None

        # Default: raise
        raise PolicyViolation(error_msg, verdict=verdict)


# =============================================================================
# THE @guard DECORATOR
# =============================================================================


@overload
def guard(func: Callable[P, R]) -> Callable[P, R]: ...


@overload
def guard(
    *,
    sql: bool = True,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    allowed_tables: set[str] | None = None,
    blocked_tables: set[str] | None = None,
    pii: bool = False,
    pii_strategy: Literal["block", "redact", "mask", "hash", "monitor"] = "block",
    pii_detect: list[str] | None = None,
    pii_apply_to: Literal["input", "output", "both"] = "input",
    file_access: bool = False,
    file_mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist",
    file_base_directory: str | None = None,
    file_allowed_paths: set[str] | None = None,
    file_blocked_paths: set[str] | None = None,
    file_blocked_extensions: set[str] | None = None,
    shell: bool = False,
    shell_mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted",
    shell_allowed_commands: set[str] | None = None,
    shell_blocked_commands: set[str] | None = None,
    shell_blocked_patterns: list[str] | None = None,
    shell_allow_operators: bool = False,
    rag: bool = False,
    rag_mode: Literal["strict", "filtered", "monitor"] = "filtered",
    rag_allowed_collections: set[str] | None = None,
    rag_blocked_collections: set[str] | None = None,
    rag_classification_max: str | None = None,
    rag_scan_pii: bool = True,
    rag_pii_strategy: Literal["block", "redact"] = "redact",
    rag_scan_secrets: bool = True,
    rag_scan_prompt_injection: bool = True,
    rag_max_documents: int = 20,
    rag_context: dict[str, Any] | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    error_message: str = "Operation blocked by security policy: {reason}",
    audit: bool = True,
    audit_logger: AuditLogger | None = None,
    audit_level: Literal["all", "block", "none"] = "all",
    audit_context: dict[str, Any] | None = None,
    param_name: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]: ...


def guard(
    func: Callable[P, R] | None = None,
    *,
    sql: bool = True,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    allowed_tables: set[str] | None = None,
    blocked_tables: set[str] | None = None,
    pii: bool = False,
    pii_strategy: Literal["block", "redact", "mask", "hash", "monitor"] = "block",
    pii_detect: list[str] | None = None,
    pii_apply_to: Literal["input", "output", "both"] = "input",
    file_access: bool = False,
    file_mode: Literal["strict", "allowlist", "blocklist", "monitor"] = "allowlist",
    file_base_directory: str | None = None,
    file_allowed_paths: set[str] | None = None,
    file_blocked_paths: set[str] | None = None,
    file_blocked_extensions: set[str] | None = None,
    shell: bool = False,
    shell_mode: Literal["restricted", "allowlist", "blocklist", "monitor"] = "restricted",
    shell_allowed_commands: set[str] | None = None,
    shell_blocked_commands: set[str] | None = None,
    shell_blocked_patterns: list[str] | None = None,
    shell_allow_operators: bool = False,
    rag: bool = False,
    rag_mode: Literal["strict", "filtered", "monitor"] = "filtered",
    rag_allowed_collections: set[str] | None = None,
    rag_blocked_collections: set[str] | None = None,
    rag_classification_max: str | None = None,
    rag_scan_pii: bool = True,
    rag_pii_strategy: Literal["block", "redact"] = "redact",
    rag_scan_secrets: bool = True,
    rag_scan_prompt_injection: bool = True,
    rag_max_documents: int = 20,
    rag_context: dict[str, Any] | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    error_message: str = "Operation blocked by security policy: {reason}",
    audit: bool = True,
    audit_logger: AuditLogger | None = None,
    audit_level: Literal["all", "block", "none"] = "all",
    audit_context: dict[str, Any] | None = None,
    param_name: str | None = None,
) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Decorator to protect AI agent tools with Warden security inspections.

    Can be used with or without arguments:

        @guard
        def my_tool(query: str): ...

        @guard(mode="safe-write")
        def my_tool(query: str): ...

    Args:
        sql: Enable SQL injection protection (default: True)
        mode: SQL inspection mode
            - "read-only": Only SELECT allowed (safest)
            - "safe-write": SELECT, INSERT, UPDATE to allowed tables
            - "strict": Block all schema changes
            - "monitor": Log only, don't block
        dialect: SQL dialect (mysql, postgres, snowflake, etc.)
        allowed_tables: Tables allowed for writes (safe-write mode)
        blocked_tables: Tables never allowed
        pii: Enable PII detection (default: False)
        pii_strategy: How to handle detected PII
            - "block": Block the request entirely
            - "redact": Replace PII with [TYPE REDACTED]
            - "mask": Show only last 4 characters
            - "hash": Replace with deterministic hash
            - "monitor": Log but don't block or modify
        pii_detect: List of PII types to detect (email, phone, ssn, credit_card, ip_address)
        pii_apply_to: Where to apply PII detection (input, output, both)
        rag: Enable RAG document security (default: False)
        rag_mode: RAG inspection mode
            - "strict": Block on any violation
            - "filtered": Filter out violating docs, pass allowed ones
            - "monitor": Log only, don't block
        rag_allowed_collections: Collections allowed for retrieval
        rag_blocked_collections: Collections never allowed
        rag_classification_max: Maximum classification level (public, internal, etc.)
        rag_scan_pii: Scan document content for PII
        rag_pii_strategy: How to handle PII in documents (block, redact)
        rag_scan_secrets: Scan document content for secrets
        rag_scan_prompt_injection: Detect prompt injection in documents
        rag_max_documents: Maximum documents to return
        rag_context: Static ABAC context for filtering (agent_id, tenant_id, etc.)
        on_block: What to do when blocked
            - "raise": Raise PolicyViolation exception
            - "return_error": Return error dict to agent
            - "return_none": Return None
        error_message: Custom error message template
        audit: Enable audit logging
        audit_logger: Custom AuditLogger instance
        audit_level: Minimum level to log (all, block, none)
        audit_context: Static context for all audit logs
        param_name: Specific parameter to inspect (default: first string)

    Example:
        from warden.integrations.strands import guard

        # Basic usage - read-only SQL protection
        @guard
        def query_database(sql: str) -> list[dict]:
            return db.execute(sql)

        # Allow writes to specific tables
        @guard(mode="safe-write", allowed_tables={"logs", "events"})
        def write_log(sql: str) -> None:
            db.execute(sql)

        # PII protection with redaction
        @guard(sql=False, pii=True, pii_strategy="redact")
        def process_text(text: str) -> str:
            return llm.process(text)

        # RAG document security - filter retrieved documents
        @guard(
            sql=False,
            rag=True,
            rag_allowed_collections={"public_docs", "help_articles"},
            rag_classification_max="internal",
            rag_scan_pii=True,
        )
        def search_knowledge(query: str) -> list[dict]:
            return vectordb.search(query)

        # RAG with ABAC context for tenant isolation
        @guard(
            sql=False,
            rag=True,
            rag_context={"agent_id": "support-bot", "tenant_id": "acme-corp"},
        )
        def search_tenant_docs(query: str) -> list[dict]:
            return vectordb.search(query)

        # With AWS Strands @tool decorator
        from strands import tool

        @tool
        @guard(mode="read-only", pii=True, pii_strategy="redact")
        def database_query(query: str) -> str:
            '''Execute a read-only SQL query.'''
            return json.dumps(db.execute(query))
    """

    # Create the guard instance
    tool_guard = ToolGuard(
        sql=sql,
        mode=mode,
        dialect=dialect,
        allowed_tables=allowed_tables,
        blocked_tables=blocked_tables,
        pii=pii,
        pii_strategy=pii_strategy,
        pii_detect=pii_detect,
        pii_apply_to=pii_apply_to,
        file_access=file_access,
        file_mode=file_mode,
        file_base_directory=file_base_directory,
        file_allowed_paths=file_allowed_paths,
        file_blocked_paths=file_blocked_paths,
        file_blocked_extensions=file_blocked_extensions,
        shell=shell,
        shell_mode=shell_mode,
        shell_allowed_commands=shell_allowed_commands,
        shell_blocked_commands=shell_blocked_commands,
        shell_blocked_patterns=shell_blocked_patterns,
        shell_allow_operators=shell_allow_operators,
        rag=rag,
        rag_mode=rag_mode,
        rag_allowed_collections=rag_allowed_collections,
        rag_blocked_collections=rag_blocked_collections,
        rag_classification_max=rag_classification_max,
        rag_scan_pii=rag_scan_pii,
        rag_pii_strategy=rag_pii_strategy,
        rag_scan_secrets=rag_scan_secrets,
        rag_scan_prompt_injection=rag_scan_prompt_injection,
        rag_max_documents=rag_max_documents,
        rag_context=rag_context,
        on_block=on_block,
        error_message=error_message,
        audit=audit,
        audit_logger=audit_logger,
        audit_level=audit_level,
        audit_context=audit_context,
        param_name=param_name,
    )

    # Handle both @guard and @guard(...) syntax
    if func is not None:
        # Called as @guard without parentheses
        return tool_guard(func)
    else:
        # Called as @guard(...) with arguments
        return tool_guard


# =============================================================================
# POLICY-BASED GUARD
# =============================================================================


class PolicyGuard:
    """
    Guard that uses a PolicyEngine for configuration.

    This allows defining security rules in YAML files instead of code,
    with support for agent-specific rules.

    Example:
        from warden import PolicyEngine
        from warden.integrations.strands import PolicyGuard

        # Load policy from file
        engine = PolicyEngine.from_file("policy.yaml")

        # Create guard for specific agent
        guard = PolicyGuard(engine, agent="analytics-bot")

        @guard
        def query_reports(sql: str) -> list:
            return db.execute(sql)
    """

    def __init__(
        self,
        policy: PolicyEngine | Policy | str,
        agent: str | None = None,
        on_block: Literal["raise", "return_error", "return_none"] = "raise",
        error_message: str = "Operation blocked by security policy: {reason}",
        audit: bool = True,
        audit_logger: AuditLogger | None = None,
        audit_level: Literal["all", "block", "none"] = "all",
        audit_context: dict[str, Any] | None = None,
        param_name: str | None = None,
    ) -> None:
        """
        Initialize PolicyGuard.

        Args:
            policy: PolicyEngine instance, Policy instance, or path to YAML file
            agent: Agent name for agent-specific rules
            on_block: Action when blocked (raise, return_error, return_none)
            error_message: Custom error message template
            audit: Enable audit logging
            audit_logger: Custom audit logger instance
            audit_level: Minimum level to log
            audit_context: Static context for audit logs
            param_name: Specific parameter to inspect
        """
        # Handle different policy input types
        if isinstance(policy, str):
            self._engine = PolicyEngine.from_file(policy)
        elif isinstance(policy, Policy):
            self._engine = PolicyEngine(policy)
        else:
            self._engine = policy

        self._agent = agent
        self._on_block = on_block
        self._error_message = error_message
        self._param_name = param_name
        self._audit_context = audit_context or {}

        # Initialize audit logger
        self._audit_logger: AuditLogger | None = None
        if audit and audit_logger is None:
            level_map = {
                "all": AuditLevel.ALL,
                "block": AuditLevel.BLOCK,
                "none": AuditLevel.NONE,
            }
            self._audit_logger = AuditLogger(
                destinations=[LogDestination.STDOUT],
                min_level=level_map.get(audit_level, AuditLevel.ALL),
            )
        elif audit_logger:
            self._audit_logger = audit_logger

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Decorate a function with this guard."""
        return self._wrap_function(func)

    def _wrap_function(self, func: Callable[P, R]) -> Callable[P, R]:
        """Wrap a sync or async function with guard protection."""
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return await self._execute_async(func, args, kwargs)

            return async_wrapper  # type: ignore
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                return self._execute_sync(func, args, kwargs)

            return sync_wrapper  # type: ignore

    def _execute_sync(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute sync function with guard protection."""
        value = self._extract_value(func, args, kwargs)
        verdict = self._inspect(value, func.__name__)

        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        return func(*args, **kwargs)

    async def _execute_async(
        self,
        func: Callable[P, R],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> R:
        """Execute async function with guard protection."""
        value = self._extract_value(func, args, kwargs)
        verdict = self._inspect(value, func.__name__)

        if verdict and verdict.blocked:
            return self._handle_block(verdict, func.__name__)

        return await func(*args, **kwargs)

    def _extract_value(
        self,
        func: Callable[..., Any],
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
    ) -> str | None:
        """Extract the value to inspect from function arguments."""
        if self._param_name:
            if self._param_name in kwargs:
                return kwargs[self._param_name]
            sig = inspect.signature(func)
            params = list(sig.parameters.keys())
            if self._param_name in params:
                idx = params.index(self._param_name)
                if idx < len(args):
                    return args[idx]
            return None

        # Auto-detect: use first string argument
        for value in kwargs.values():
            if isinstance(value, str):
                return value
        for arg in args:
            if isinstance(arg, str):
                return arg
        return None

    def _inspect(self, value: str | None, func_name: str) -> Verdict | None:
        """Run inspections using the policy engine."""
        if value is None:
            return None

        verdict = self._engine.inspect(value, agent=self._agent)

        if self._audit_logger:
            context = {
                "tool": func_name,
                "agent": self._agent,
                "inspector": "sql",
                **self._audit_context,
            }
            self._audit_logger.log(verdict, context=context)

        return verdict

    def _handle_block(self, verdict: Verdict, func_name: str) -> Any:
        """Handle a blocked operation based on config."""
        error_msg = self._error_message.format(
            reason=verdict.reason,
            rule=verdict.rule,
            inspector=verdict.inspector,
            tool=func_name,
        )

        action = BlockAction(self._on_block)

        if action == BlockAction.RAISE:
            if verdict.rule in {"critical_node_detected", "schema_change_blocked"}:
                raise CriticalViolation(error_msg, verdict=verdict)
            raise PolicyViolation(error_msg, verdict=verdict)
        elif action == BlockAction.RETURN_ERROR:
            return {
                "error": True,
                "message": error_msg,
                "blocked": True,
                "reason": verdict.reason,
                "rule": verdict.rule,
            }
        elif action == BlockAction.RETURN_NONE:
            return None

        raise PolicyViolation(error_msg, verdict=verdict)


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def create_policy_guard(
    policy: PolicyEngine | Policy | str,
    agent: str | None = None,
    on_block: Literal["raise", "return_error", "return_none"] = "raise",
    audit_logger: AuditLogger | None = None,
) -> PolicyGuard:
    """
    Create a policy-based guard for protecting tools.

    This is the recommended way to use Warden with multi-agent systems.

    Args:
        policy: PolicyEngine, Policy, or path to YAML file
        agent: Agent name for agent-specific rules
        on_block: Action when blocked
        audit_logger: Custom audit logger

    Example:
        # Load policy
        guard = create_policy_guard("policy.yaml", agent="analytics-bot")

        @guard
        def query_reports(sql: str) -> list:
            return db.execute(sql)
    """
    return PolicyGuard(
        policy=policy,
        agent=agent,
        on_block=on_block,
        audit_logger=audit_logger,
    )


def create_sql_guard(
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
    audit_logger: AuditLogger | None = None,
) -> ToolGuard:
    """
    Create a reusable SQL guard for protecting multiple tools.

    Example:
        sql_guard = create_sql_guard(mode="read-only")

        @sql_guard
        def tool1(query: str): ...

        @sql_guard
        def tool2(query: str): ...
    """
    return ToolGuard(
        sql=True,
        mode=mode,
        dialect=dialect,
        audit_logger=audit_logger,
    )
