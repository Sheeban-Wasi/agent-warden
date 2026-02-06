"""
Tests for the AWS Strands @guard decorator integration.

These tests verify that the @guard decorator correctly:
- Intercepts function arguments
- Runs SQL inspections
- Blocks dangerous operations
- Allows safe operations
- Handles async functions
- Integrates with audit logging
"""

import asyncio
import pytest

from warden import (
    guard,
    ToolGuard,
    GuardConfig,
    create_sql_guard,
    PolicyViolation,
    CriticalViolation,
    AuditLogger,
    LogDestination,
)


# =============================================================================
# BASIC @guard DECORATOR TESTS
# =============================================================================

class TestGuardDecorator:
    """Test the @guard decorator basic functionality."""

    def test_guard_allows_safe_select(self):
        """Guard allows safe SELECT queries."""
        @guard(audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("SELECT * FROM users")
        assert result == "executed: SELECT * FROM users"

    def test_guard_blocks_drop_table(self):
        """Guard blocks DROP TABLE queries."""
        @guard(audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises(CriticalViolation) as exc_info:
            execute_query("DROP TABLE users")

        assert "blocked" in str(exc_info.value).lower()

    def test_guard_blocks_delete(self):
        """Guard blocks DELETE in read-only mode."""
        @guard(mode="read-only", audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises(PolicyViolation):
            execute_query("DELETE FROM users WHERE id = 1")

    def test_guard_allows_insert_in_safe_write_mode(self):
        """Guard allows INSERT in safe-write mode with allowed tables."""
        @guard(mode="safe-write", allowed_tables={"logs"}, audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("INSERT INTO logs (msg) VALUES ('test')")
        assert "executed:" in result

    def test_guard_blocks_insert_to_unauthorized_table(self):
        """Guard blocks INSERT to unauthorized table."""
        @guard(mode="safe-write", allowed_tables={"logs"}, audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises(PolicyViolation) as exc_info:
            execute_query("INSERT INTO users (name) VALUES ('hacker')")

        assert "unauthorized" in str(exc_info.value).lower()

    def test_guard_without_parentheses(self):
        """Guard works without parentheses."""
        @guard
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("SELECT 1")
        assert result == "executed: SELECT 1"

    def test_guard_with_parentheses(self):
        """Guard works with parentheses and no args."""
        @guard()
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("SELECT 1")
        assert result == "executed: SELECT 1"


# =============================================================================
# BLOCK ACTION TESTS
# =============================================================================

class TestBlockActions:
    """Test different on_block actions."""

    def test_on_block_raise(self):
        """on_block='raise' raises exception."""
        @guard(on_block="raise", audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises((PolicyViolation, CriticalViolation)):
            execute_query("DROP TABLE users")

    def test_on_block_return_error(self):
        """on_block='return_error' returns error dict."""
        @guard(on_block="return_error", audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("DROP TABLE users")
        assert isinstance(result, dict)
        assert result["error"] is True
        assert result["blocked"] is True
        assert "reason" in result

    def test_on_block_return_none(self):
        """on_block='return_none' returns None."""
        @guard(on_block="return_none", audit=False)
        def execute_query(query: str) -> str:
            return f"executed: {query}"

        result = execute_query("DROP TABLE users")
        assert result is None


# =============================================================================
# PARAMETER DETECTION TESTS
# =============================================================================

class TestParameterDetection:
    """Test automatic parameter detection."""

    def test_first_string_param_detected(self):
        """Guard inspects first string parameter by default."""
        @guard(audit=False)
        def execute(query: str, limit: int = 10) -> str:
            return f"{query} LIMIT {limit}"

        result = execute("SELECT * FROM users", limit=5)
        assert "LIMIT 5" in result

    def test_kwargs_string_detected(self):
        """Guard inspects string kwargs."""
        @guard(audit=False)
        def execute(query: str) -> str:
            return f"executed: {query}"

        result = execute(query="SELECT 1")
        assert result == "executed: SELECT 1"

    def test_explicit_param_name(self):
        """Guard can be configured to inspect specific parameter."""
        @guard(param_name="sql", audit=False)
        def execute(name: str, sql: str) -> str:
            return f"{name}: {sql}"

        result = execute("test", "SELECT 1")
        assert result == "test: SELECT 1"

        with pytest.raises((PolicyViolation, CriticalViolation)):
            execute("test", "DROP TABLE users")

    def test_no_string_param_passes(self):
        """Guard passes if no string parameter found."""
        @guard(audit=False)
        def compute(a: int, b: int) -> int:
            return a + b

        result = compute(1, 2)
        assert result == 3


# =============================================================================
# ASYNC FUNCTION TESTS
# =============================================================================

class TestAsyncFunctions:
    """Test guard with async functions."""

    @pytest.mark.asyncio
    async def test_async_function_allowed(self):
        """Guard works with async functions - allows safe queries."""
        @guard(audit=False)
        async def async_query(query: str) -> str:
            await asyncio.sleep(0.01)
            return f"executed: {query}"

        result = await async_query("SELECT * FROM users")
        assert result == "executed: SELECT * FROM users"

    @pytest.mark.asyncio
    async def test_async_function_blocked(self):
        """Guard works with async functions - blocks dangerous queries."""
        @guard(audit=False)
        async def async_query(query: str) -> str:
            await asyncio.sleep(0.01)
            return f"executed: {query}"

        with pytest.raises((PolicyViolation, CriticalViolation)):
            await async_query("DROP TABLE users")

    @pytest.mark.asyncio
    async def test_async_return_error(self):
        """Guard async with return_error action."""
        @guard(on_block="return_error", audit=False)
        async def async_query(query: str) -> str:
            return f"executed: {query}"

        result = await async_query("DROP TABLE users")
        assert isinstance(result, dict)
        assert result["blocked"] is True


# =============================================================================
# TOOL GUARD CLASS TESTS
# =============================================================================

class TestToolGuard:
    """Test ToolGuard class for reusable guards."""

    def test_tool_guard_reusable(self):
        """ToolGuard can be reused across multiple functions."""
        sql_guard = ToolGuard(sql=True, mode="read-only", audit=False)

        @sql_guard
        def query1(sql: str) -> str:
            return f"q1: {sql}"

        @sql_guard
        def query2(sql: str) -> str:
            return f"q2: {sql}"

        assert query1("SELECT 1") == "q1: SELECT 1"
        assert query2("SELECT 2") == "q2: SELECT 2"

        with pytest.raises((PolicyViolation, CriticalViolation)):
            query1("DROP TABLE x")

        with pytest.raises((PolicyViolation, CriticalViolation)):
            query2("DROP TABLE y")

    def test_create_sql_guard_helper(self):
        """create_sql_guard creates a configured guard."""
        sql_guard = create_sql_guard(mode="read-only")

        @sql_guard
        def execute(query: str) -> str:
            return query

        assert execute("SELECT 1") == "SELECT 1"


# =============================================================================
# AUDIT LOGGING TESTS
# =============================================================================

class TestAuditLogging:
    """Test audit logging integration."""

    def test_guard_logs_to_audit_logger(self, tmp_path):
        """Guard logs verdicts to audit logger."""
        import json

        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        @guard(audit=True, audit_logger=logger, on_block="return_error")
        def execute(query: str) -> str:
            return f"executed: {query}"

        # Execute a query that gets blocked
        execute("DROP TABLE users")
        logger.flush()
        logger.close()

        # Check log file
        content = log_file.read_text()
        record = json.loads(content.strip())
        assert record["verdict"] == "BLOCK"
        assert record["context"]["tool"] == "execute"

    def test_guard_logs_pass_verdicts(self, tmp_path):
        """Guard logs passing verdicts when audit_level='all'."""
        import json

        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        @guard(audit=True, audit_logger=logger, audit_level="all")
        def execute(query: str) -> str:
            return f"executed: {query}"

        execute("SELECT 1")
        logger.flush()
        logger.close()

        content = log_file.read_text()
        record = json.loads(content.strip())
        assert record["verdict"] == "PASS"

    def test_guard_with_audit_context(self, tmp_path):
        """Guard includes static audit context."""
        import json

        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(
            destinations=[LogDestination.FILE],
            log_file=log_file,
        )

        @guard(
            audit=True,
            audit_logger=logger,
            audit_context={"agent": "test-agent", "user_id": "123"},
        )
        def execute(query: str) -> str:
            return f"executed: {query}"

        execute("SELECT 1")
        logger.close()

        content = log_file.read_text()
        record = json.loads(content.strip())
        assert record["context"]["agent"] == "test-agent"
        assert record["context"]["user_id"] == "123"


# =============================================================================
# SQL DIALECT TESTS
# =============================================================================

class TestSQLDialects:
    """Test SQL dialect support in guard."""

    def test_mysql_dialect(self):
        """Guard works with MySQL dialect."""
        @guard(dialect="mysql", audit=False)
        def execute(query: str) -> str:
            return f"executed: {query}"

        # MySQL-specific syntax should work
        result = execute("SELECT * FROM users LIMIT 10")
        assert "executed:" in result

    def test_postgres_dialect(self):
        """Guard works with PostgreSQL dialect."""
        @guard(dialect="postgres", audit=False)
        def execute(query: str) -> str:
            return f"executed: {query}"

        result = execute("SELECT * FROM users LIMIT 10 OFFSET 5")
        assert "executed:" in result


# =============================================================================
# ERROR MESSAGE TESTS
# =============================================================================

class TestErrorMessages:
    """Test custom error messages."""

    def test_custom_error_message(self):
        """Guard uses custom error message template."""
        @guard(
            error_message="Security blocked: {reason}",
            audit=False,
        )
        def execute(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises((PolicyViolation, CriticalViolation)) as exc_info:
            execute("DROP TABLE users")

        assert "Security blocked:" in str(exc_info.value)

    def test_error_message_with_placeholders(self):
        """Error message template supports multiple placeholders."""
        @guard(
            error_message="Tool {tool} blocked by {inspector}: {reason}",
            on_block="return_error",
            audit=False,
        )
        def my_tool(query: str) -> str:
            return f"executed: {query}"

        result = my_tool("DROP TABLE users")
        assert "my_tool" in result["message"]


# =============================================================================
# BLOCKED TABLES TESTS
# =============================================================================

class TestBlockedTables:
    """Test blocked tables configuration."""

    def test_blocked_table_rejected(self):
        """Guard blocks access to blocked tables."""
        @guard(blocked_tables={"secrets", "credentials"}, audit=False)
        def execute(query: str) -> str:
            return f"executed: {query}"

        with pytest.raises(PolicyViolation):
            execute("SELECT * FROM secrets")

    def test_non_blocked_table_allowed(self):
        """Guard allows access to non-blocked tables."""
        @guard(blocked_tables={"secrets"}, audit=False)
        def execute(query: str) -> str:
            return f"executed: {query}"

        result = execute("SELECT * FROM users")
        assert "executed:" in result


# =============================================================================
# INTEGRATION WITH STRANDS-LIKE PATTERNS
# =============================================================================

class TestStrandsPatterns:
    """Test patterns that match AWS Strands SDK usage."""

    def test_tool_decorator_pattern(self):
        """Guard works with @tool-like decorator pattern."""
        # Simulate @tool decorator
        def tool(func):
            func._is_tool = True
            return func

        @tool
        @guard(audit=False)
        def database_query(query: str) -> str:
            """Execute a SQL query."""
            return f"result: {query}"

        assert hasattr(database_query, "_is_tool")
        assert database_query._is_tool is True
        assert database_query("SELECT 1") == "result: SELECT 1"

    def test_guard_then_tool_pattern(self):
        """Guard then tool decorator pattern."""
        def tool(func):
            func._is_tool = True
            return func

        @guard(audit=False)
        @tool
        def database_query(query: str) -> str:
            """Execute a SQL query."""
            return f"result: {query}"

        # Note: _is_tool might be hidden by guard wrapper
        assert database_query("SELECT 1") == "result: SELECT 1"

    def test_class_method_guard(self):
        """Guard works with class methods."""
        class DatabaseTool:
            @guard(audit=False)
            def execute(self, query: str) -> str:
                return f"executed: {query}"

        tool = DatabaseTool()
        assert tool.execute("SELECT 1") == "executed: SELECT 1"

        with pytest.raises((PolicyViolation, CriticalViolation)):
            tool.execute("DROP TABLE users")
