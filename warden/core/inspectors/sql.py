"""
SQL Inspector - AST-based SQL security analysis.

THIS IS THE MOAT FEATURE OF AGENT-WARDEN.

Uses sqlglot to parse SQL into an Abstract Syntax Tree, then
traverses the tree to detect dangerous operations. Unlike regex,
this catches obfuscated attacks like EXEC('DR' + 'OP TABLE').

Philosophy: Deny by Default. If we can't parse it, we block it.

Example:
    from warden.core.inspectors.sql import SQLInspector, check_sql

    # Quick check
    if check_sql("SELECT * FROM users"):
        execute_query(query)

    # Full inspection with details
    inspector = SQLInspector(mode="read-only")
    verdict = inspector.inspect("DROP TABLE users")
    if verdict.blocked:
        print(verdict.to_audit_log())
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import sqlglot
from sqlglot import exp

from warden.core.verdict import Verdict, create_block_verdict, create_pass_verdict


class SQLMode(Enum):
    """
    SQL inspection modes.

    READ_ONLY: Only SELECT queries allowed (safest)
    SAFE_WRITE: SELECT, INSERT, UPDATE allowed to specific tables
    STRICT: Block all schema changes, allow controlled writes
    MONITOR: Log only, don't block (for tuning policies)
    """

    READ_ONLY = "read-only"
    SAFE_WRITE = "safe-write"
    STRICT = "strict"
    MONITOR = "monitor"


# =============================================================================
# CRITICAL NODES - Always blocked regardless of mode
# These represent existential threats to data integrity
# =============================================================================
CRITICAL_NODE_TYPES: frozenset[type[exp.Expression]] = frozenset({
    exp.Drop,           # DROP TABLE, DROP DATABASE, DROP INDEX
    exp.Alter,          # ALTER TABLE (schema changes)
    exp.TruncateTable,  # TRUNCATE TABLE (mass delete)
    exp.Grant,          # GRANT privileges (privilege escalation)
    exp.Command,        # Raw commands (EXEC, EXECUTE, CALL)
    exp.LoadData,       # LOAD DATA INFILE (file access)
    exp.Copy,           # COPY TO/FROM (PostgreSQL file access)
})

# Schema modification nodes (subset that's always critical)
SCHEMA_CHANGE_NODES: frozenset[type[exp.Expression]] = frozenset({
    exp.Create,         # CREATE TABLE, CREATE INDEX, CREATE USER
    exp.Alter,
    exp.Drop,
    exp.TruncateTable,
})

# =============================================================================
# WRITE NODES - Blocked in read-only mode
# =============================================================================
WRITE_NODE_TYPES: frozenset[type[exp.Expression]] = frozenset({
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
})

# SQL keywords that should never appear in string concatenations
SQL_DANGER_KEYWORDS: frozenset[str] = frozenset({
    "drop", "alter", "truncate", "delete", "grant", "revoke",
    "exec", "execute", "xp_", "sp_", "create", "shutdown",
})


@dataclass
class SQLInspectorConfig:
    """Configuration for the SQL Inspector."""

    mode: SQLMode = SQLMode.READ_ONLY
    allowed_tables: frozenset[str] = field(default_factory=frozenset)
    blocked_tables: frozenset[str] = field(default_factory=frozenset)
    dialect: str | None = None
    fail_closed: bool = True  # Deny by Default
    max_query_length: int = 100_000  # Prevent DoS via huge queries


class SQLInspector:
    """
    AST-based SQL security inspector.

    The core of Agent-Warden's "moat" - deterministic SQL analysis
    that cannot be bypassed by prompt injection or obfuscation.

    Args:
        mode: Inspection mode (read-only, safe-write, strict, monitor)
        allowed_tables: Tables allowed for writes in safe-write mode
        blocked_tables: Tables that are never allowed (e.g., audit_logs)
        dialect: SQL dialect for parsing (postgres, mysql, snowflake, etc.)
        fail_closed: If True, block unparseable queries (Deny by Default)

    Example:
        inspector = SQLInspector(mode="read-only")
        verdict = inspector.inspect("SELECT * FROM users WHERE id = 1")
        assert verdict.passed

        verdict = inspector.inspect("DROP TABLE users")
        assert verdict.blocked
        assert verdict.rule == "critical_node_detected"
    """

    INSPECTOR_NAME = "sql_inspector"

    def __init__(
        self,
        mode: SQLMode | str = SQLMode.READ_ONLY,
        allowed_tables: set[str] | frozenset[str] | None = None,
        blocked_tables: set[str] | frozenset[str] | None = None,
        dialect: str | None = None,
        fail_closed: bool = True,
        max_query_length: int = 100_000,
    ) -> None:
        # Convert string mode to enum
        if isinstance(mode, str):
            mode = SQLMode(mode)

        self.config = SQLInspectorConfig(
            mode=mode,
            allowed_tables=frozenset(t.lower() for t in (allowed_tables or set())),
            blocked_tables=frozenset(t.lower() for t in (blocked_tables or set())),
            dialect=dialect,
            fail_closed=fail_closed,
            max_query_length=max_query_length,
        )

    def inspect(self, query: str) -> Verdict:
        """
        Inspect a SQL query for security violations.

        This is the main entry point. It parses the query into an AST
        and traverses it looking for dangerous patterns.

        Args:
            query: The SQL query string to inspect

        Returns:
            Verdict with PASS or BLOCK decision and audit details
        """
        start_time = time.perf_counter()

        # Pre-parse checks
        pre_check = self._pre_parse_checks(query, start_time)
        if pre_check is not None:
            return pre_check

        # Parse the SQL into AST
        try:
            statements = sqlglot.parse(query, dialect=self.config.dialect)
        except Exception as e:
            return self._handle_parse_error(query, e, start_time)

        # Check each statement
        for statement in statements:
            if statement is None:
                continue

            verdict = self._check_statement(statement, query, start_time)
            if verdict.blocked:
                return verdict

        # All checks passed
        return create_pass_verdict(
            inspector=self.INSPECTOR_NAME,
            reason="Query passed all security checks",
            latency_ms=self._elapsed_ms(start_time),
        )

    def _pre_parse_checks(self, query: str, start_time: float) -> Verdict | None:
        """Run checks before attempting to parse."""

        # Empty query
        if not query or not query.strip():
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason="Empty or whitespace-only query",
                rule="empty_query",
                latency_ms=self._elapsed_ms(start_time),
            )

        # Query too long (DoS prevention)
        if len(query) > self.config.max_query_length:
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Query exceeds maximum length ({len(query)} > {self.config.max_query_length})",  # noqa: E501
                rule="query_too_long",
                details={"length": len(query), "max_length": self.config.max_query_length},
                latency_ms=self._elapsed_ms(start_time),
            )

        # Check for obvious injection patterns in raw text
        # (Belt and suspenders - AST check is primary)
        suspicious = self._check_raw_query_patterns(query)
        if suspicious:
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Suspicious pattern in raw query: {suspicious}",
                rule="raw_pattern_detected",
                details={"pattern": suspicious},
                latency_ms=self._elapsed_ms(start_time),
            )

        return None

    def _handle_parse_error(
        self, query: str, error: Exception, start_time: float
    ) -> Verdict:
        """Handle SQL parse failures."""
        error_msg = str(error)

        if self.config.fail_closed:
            # Deny by Default: unparseable = blocked
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Failed to parse SQL (Deny by Default): {error_msg}",
                rule="parse_failure",
                details={
                    "parse_error": error_msg,
                    "query_preview": query[:200] if len(query) > 200 else query,
                },
                latency_ms=self._elapsed_ms(start_time),
            )
        else:
            # Monitor mode: allow but log
            return create_pass_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Parse failed but fail_closed=False: {error_msg}",
                latency_ms=self._elapsed_ms(start_time),
            )

    def _check_statement(
        self, statement: exp.Expression, query: str, start_time: float
    ) -> Verdict:
        """Check a single SQL statement for violations."""

        # Walk the AST and check each node
        for node in statement.walk():
            node_type = type(node)

            # =================================================================
            # CRITICAL VIOLATIONS - Always blocked
            # =================================================================
            if node_type in CRITICAL_NODE_TYPES:
                return create_block_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Critical operation blocked: {node_type.__name__}",
                    rule="critical_node_detected",
                    details={
                        "node_type": node_type.__name__,
                        "sql_fragment": self._safe_sql(node),
                    },
                    latency_ms=self._elapsed_ms(start_time),
                )

            # Schema changes via CREATE (separate from critical for granularity)
            if node_type == exp.Create:
                return create_block_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Schema change blocked: {node_type.__name__}",
                    rule="schema_change_blocked",
                    details={
                        "node_type": node_type.__name__,
                        "sql_fragment": self._safe_sql(node),
                    },
                    latency_ms=self._elapsed_ms(start_time),
                )

            # =================================================================
            # WRITE VIOLATIONS - Mode dependent
            # =================================================================
            if node_type in WRITE_NODE_TYPES:
                verdict = self._check_write_operation(node, node_type, start_time)
                if verdict is not None:
                    return verdict

            # =================================================================
            # SUSPICIOUS PATTERNS - Injection attempts
            # =================================================================
            suspicious = self._check_suspicious_node(node)
            if suspicious:
                return create_block_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Suspicious pattern detected: {suspicious}",
                    rule="suspicious_pattern",
                    details={"pattern": suspicious, "node_type": node_type.__name__},
                    latency_ms=self._elapsed_ms(start_time),
                )

        # Check blocked tables
        tables = self._extract_tables(statement)
        blocked = tables & self.config.blocked_tables
        if blocked:
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Access to blocked table(s): {blocked}",
                rule="blocked_table_access",
                details={"blocked_tables": list(blocked)},
                latency_ms=self._elapsed_ms(start_time),
            )

        return create_pass_verdict(
            inspector=self.INSPECTOR_NAME,
            latency_ms=self._elapsed_ms(start_time),
        )

    def _check_write_operation(
        self,
        node: exp.Expression,
        node_type: type[exp.Expression],
        start_time: float,
    ) -> Verdict | None:
        """Check if a write operation is allowed."""

        # READ_ONLY mode: all writes blocked
        if self.config.mode == SQLMode.READ_ONLY:
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason=f"Write operation blocked in read-only mode: {node_type.__name__}",
                rule="write_in_read_only_mode",
                details={"operation": node_type.__name__},
                latency_ms=self._elapsed_ms(start_time),
            )

        # SAFE_WRITE mode: check allowed tables
        if self.config.mode == SQLMode.SAFE_WRITE and self.config.allowed_tables:
            tables = self._extract_tables(node)
            disallowed = tables - self.config.allowed_tables
            if disallowed:
                return create_block_verdict(
                    inspector=self.INSPECTOR_NAME,
                    reason=f"Write to unauthorized table(s): {disallowed}",
                    rule="write_to_unauthorized_table",
                    details={
                        "disallowed_tables": list(disallowed),
                        "allowed_tables": list(self.config.allowed_tables),
                    },
                    latency_ms=self._elapsed_ms(start_time),
                )

        # DELETE is special - often restricted even in write modes
        # Check if DELETE has a WHERE clause (bulk delete prevention)
        if (
            node_type == exp.Delete
            and self.config.mode != SQLMode.MONITOR
            and not self._has_where_clause(node)
        ):
            return create_block_verdict(
                inspector=self.INSPECTOR_NAME,
                reason="DELETE without WHERE clause blocked (bulk delete prevention)",
                rule="bulk_delete_blocked",
                details={"operation": "DELETE"},
                latency_ms=self._elapsed_ms(start_time),
            )

        return None

    def _check_suspicious_node(self, node: exp.Expression) -> str | None:
        """
        Check for suspicious patterns that might indicate injection.

        This catches obfuscated attacks like EXEC('DR' + 'OP TABLE').
        """

        # Dynamic SQL execution patterns - this is where concat becomes dangerous
        if isinstance(node, exp.Anonymous):
            func_name = str(node.this).lower() if node.this else ""
            if func_name in {"exec", "execute", "sp_executesql", "eval"}:
                # Check if arguments contain suspicious string concatenation
                for arg in node.expressions if hasattr(node, 'expressions') else []:
                    if isinstance(arg, (exp.Concat, exp.DPipe, exp.ConcatWs)):
                        concat_result = self._analyze_concat(arg)
                        if concat_result:
                            return f"Dynamic SQL with {concat_result}"
                return f"Dynamic SQL execution via {func_name}"

        # Suspicious function calls
        if isinstance(node, exp.Anonymous):
            func_name = str(node.this).lower() if node.this else ""
            dangerous_funcs = {"xp_cmdshell", "xp_regread", "load_file"}
            if func_name in dangerous_funcs:
                return f"Dangerous function: {func_name}"

        # UNION-based injection patterns (unusual UNION with literals)
        if isinstance(node, exp.Union):
            # Check for UNION SELECT with many NULL/literal columns (injection signature)
            for select in node.find_all(exp.Select):
                if self._is_injection_select(select):
                    return "UNION-based injection pattern detected"

        return None

    def _analyze_concat(self, node: exp.Expression) -> str | None:
        """
        Analyze string concatenation for hidden SQL keywords.

        Only called when concat is in a dangerous context (like EXEC).
        """
        literals: list[str] = []

        for child in node.walk():
            if isinstance(child, exp.Literal) and child.is_string:
                val = str(child.this).lower()
                literals.append(val)

        # Join all literals and check for dangerous keywords
        combined = "".join(literals)
        for keyword in SQL_DANGER_KEYWORDS:
            if keyword in combined:
                return f"string concatenation reconstructs SQL keyword: {keyword}"

        return None

    def _is_injection_select(self, select: exp.Select) -> bool:
        """Check if a SELECT looks like an injection payload."""
        null_count = 0
        literal_count = 0

        for expr in select.expressions:
            if isinstance(expr, exp.Null):
                null_count += 1
            elif isinstance(expr, exp.Literal):
                literal_count += 1

        # Injection signatures: many NULLs or literals in column position
        total = null_count + literal_count
        all_exprs = len(list(select.expressions))

        return all_exprs > 0 and total == all_exprs and total >= 3

    def _check_raw_query_patterns(self, query: str) -> str | None:
        """
        Check raw query text for obvious injection patterns.

        This is a belt-and-suspenders check - the AST analysis is primary.
        """
        query_lower = query.lower()

        # Stacked queries (semicolon followed by dangerous command)
        import re
        stacked_pattern = r";\s*(drop|alter|truncate|delete|grant|revoke|exec)"
        if re.search(stacked_pattern, query_lower):
            return "Possible stacked query injection"

        # NOTE: We do NOT check for keywords inside comments.
        # Keywords inside comments (like SELECT * FROM users--sp_password) are harmless.
        # The AST parser correctly handles comments, and the stacked query check
        # above will catch actual dangerous patterns like SELECT 1;--\nDROP TABLE.

        # MySQL conditional comments: /*!50000 DROP TABLE users */
        # These execute on specific MySQL versions - treat as dangerous
        mysql_cond_pattern = r"/\*!\d+\s*(drop|alter|truncate|delete|grant|revoke|create)"
        if re.search(mysql_cond_pattern, query_lower):
            return "MySQL conditional comment with dangerous SQL"

        # UNION injection pattern: literal UNION SELECT (not SELECT UNION SELECT)
        # Pattern: starts with a literal/number followed by UNION
        union_inject_pattern = r"^\s*[\d'\"]+\s+union\s+"
        if re.search(union_inject_pattern, query_lower):
            return "UNION injection pattern (literal UNION SELECT)"

        # REVOKE statement detection (not in all sqlglot versions as AST node)
        revoke_pattern = r"^\s*revoke\s+"
        if re.search(revoke_pattern, query_lower):
            return "REVOKE statement detected (privilege manipulation)"

        # NOTE: Hex literals (0x...) are NOT blocked here.
        # They're just data values in SQL (like SELECT 0x44524F50).
        # AST analysis handles the actual security - hex literals can't
        # become executable code just by being hex-encoded.

        return None

    def _has_where_clause(self, node: exp.Expression) -> bool:
        """Check if a statement has a WHERE clause."""
        return node.find(exp.Where) is not None

    def _extract_tables(self, statement: exp.Expression) -> frozenset[str]:
        """Extract all table names referenced in a statement."""
        tables: set[str] = set()
        for table in statement.find_all(exp.Table):
            if table.name:
                tables.add(table.name.lower())
        return frozenset(tables)

    def _safe_sql(self, node: exp.Expression, max_length: int = 100) -> str:
        """Get SQL representation of a node, safely truncated."""
        try:
            sql = node.sql()
            if len(sql) > max_length:
                return sql[:max_length] + "..."
            return sql
        except Exception:
            return f"<{type(node).__name__}>"

    def _elapsed_ms(self, start_time: float) -> float:
        """Calculate elapsed time in milliseconds."""
        return (time.perf_counter() - start_time) * 1000


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================


def check_sql(
    query: str,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
) -> bool:
    """
    Quick check if a SQL query is safe.

    This is the simple API for common use cases.

    Args:
        query: SQL query to check
        mode: Inspection mode (default: read-only)
        dialect: SQL dialect (optional)

    Returns:
        True if query is safe, False if blocked

    Example:
        if check_sql("SELECT * FROM users WHERE id = 1"):
            cursor.execute(query)
        else:
            raise SecurityError("Query blocked by Warden")
    """
    inspector = SQLInspector(mode=mode, dialect=dialect)
    verdict = inspector.inspect(query)
    return verdict.passed


def inspect_sql(
    query: str,
    mode: Literal["read-only", "safe-write", "strict", "monitor"] = "read-only",
    dialect: str | None = None,
) -> Verdict:
    """
    Inspect a SQL query and get full verdict details.

    Use this when you need the audit trail or detailed reasoning.

    Args:
        query: SQL query to inspect
        mode: Inspection mode (default: read-only)
        dialect: SQL dialect (optional)

    Returns:
        Verdict with full details

    Example:
        verdict = inspect_sql("DROP TABLE users")
        if verdict.blocked:
            logger.warning(verdict.to_audit_log())
            return verdict.to_agent_response()
    """
    inspector = SQLInspector(mode=mode, dialect=dialect)
    return inspector.inspect(query)
