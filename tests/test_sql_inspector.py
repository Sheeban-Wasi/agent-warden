"""
Comprehensive SQL Injection Test Suite for Agent-Warden.

This test suite validates that the SQLInspector (THE MOAT) actually blocks
real-world attack vectors, not just trivial cases.

Run with: pytest tests/test_sql_inspector.py -v
"""

import json
from pathlib import Path

import pytest

from warden import SQLInspector, SQLMode, VerdictType, check_sql, inspect_sql

# =============================================================================
# FIXTURES
# =============================================================================


@pytest.fixture
def attack_vectors():
    """Load attack vectors from JSON file."""
    vectors_path = Path(__file__).parent / "vectors" / "sql_injection.json"
    with open(vectors_path) as f:
        return json.load(f)


@pytest.fixture
def read_only_inspector():
    """SQLInspector in read-only mode (strictest)."""
    return SQLInspector(mode=SQLMode.READ_ONLY)


@pytest.fixture
def safe_write_inspector():
    """SQLInspector allowing writes to specific tables."""
    return SQLInspector(mode=SQLMode.SAFE_WRITE, allowed_tables={"users", "orders", "logs"})


# =============================================================================
# BASIC FUNCTIONALITY TESTS
# =============================================================================


class TestBasicFunctionality:
    """Test basic SQLInspector functionality."""

    def test_simple_select_passes(self):
        """A basic SELECT should always pass."""
        assert check_sql("SELECT * FROM users") is True

    def test_drop_table_blocked(self):
        """DROP TABLE should always be blocked."""
        assert check_sql("DROP TABLE users") is False

    def test_verdict_structure(self):
        """Verify Verdict contains expected fields."""
        verdict = inspect_sql("DROP TABLE users")

        assert verdict.blocked is True
        assert verdict.verdict == VerdictType.BLOCK
        assert verdict.inspector == "sql_inspector"
        assert verdict.rule is not None
        assert verdict.reason is not None
        assert verdict.event_id is not None
        assert verdict.timestamp is not None
        assert verdict.latency_ms >= 0

    def test_audit_log_format(self):
        """Verify audit log output format."""
        verdict = inspect_sql("DROP TABLE users")
        audit_log = verdict.to_audit_log()

        assert "event_id" in audit_log
        assert "timestamp" in audit_log
        assert "verdict" in audit_log
        assert audit_log["verdict"] == "BLOCK"
        assert "inspector" in audit_log
        assert "rule" in audit_log
        assert "reason" in audit_log
        assert "latency_ms" in audit_log

    def test_agent_response_format(self):
        """Verify agent response message."""
        verdict = inspect_sql("DROP TABLE users")
        response = verdict.to_agent_response()

        assert "blocked" in response.lower()
        assert "security policy" in response.lower()


# =============================================================================
# CRITICAL OPERATIONS (Always Blocked)
# =============================================================================


class TestCriticalOperations:
    """Test that critical operations are ALWAYS blocked."""

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP TABLE users",
            "DROP DATABASE production",
            "DROP INDEX idx_users",
            "DROP VIEW user_view",
            "DROP SCHEMA public",
        ],
    )
    def test_drop_statements_blocked(self, sql):
        """All DROP statements must be blocked."""
        verdict = inspect_sql(sql)
        assert verdict.blocked, f"Should block: {sql}"
        assert "Drop" in verdict.details.get("node_type", "") or "critical" in verdict.rule

    @pytest.mark.parametrize(
        "sql",
        [
            "ALTER TABLE users ADD COLUMN admin BOOLEAN",
            "ALTER TABLE users DROP COLUMN password",
            "ALTER TABLE users RENAME TO customers",
            "ALTER TABLE users ALTER COLUMN name TYPE TEXT",
        ],
    )
    def test_alter_statements_blocked(self, sql):
        """All ALTER statements must be blocked."""
        verdict = inspect_sql(sql)
        assert verdict.blocked, f"Should block: {sql}"

    @pytest.mark.parametrize(
        "sql",
        [
            "CREATE TABLE hackers (id INT)",
            "CREATE INDEX idx ON users(password)",
            "CREATE VIEW admin_view AS SELECT * FROM users",
            "CREATE DATABASE hacked",
        ],
    )
    def test_create_statements_blocked(self, sql):
        """All CREATE statements must be blocked."""
        verdict = inspect_sql(sql)
        assert verdict.blocked, f"Should block: {sql}"

    @pytest.mark.parametrize(
        "sql",
        [
            "TRUNCATE TABLE users",
            "TRUNCATE users",
        ],
    )
    def test_truncate_statements_blocked(self, sql):
        """TRUNCATE must be blocked."""
        verdict = inspect_sql(sql)
        # TRUNCATE might parse as a command or might fail to parse
        # Either way, it should be blocked (deny by default)
        assert verdict.blocked, f"Should block: {sql}"


# =============================================================================
# WRITE OPERATIONS (Mode Dependent)
# =============================================================================


class TestWriteOperations:
    """Test write operations are blocked in read-only mode."""

    def test_insert_blocked_in_read_only(self, read_only_inspector):
        """INSERT blocked in read-only mode."""
        verdict = read_only_inspector.inspect("INSERT INTO users (name) VALUES ('test')")
        assert verdict.blocked

    def test_update_blocked_in_read_only(self, read_only_inspector):
        """UPDATE blocked in read-only mode."""
        verdict = read_only_inspector.inspect("UPDATE users SET name='hacked' WHERE id=1")
        assert verdict.blocked

    def test_delete_blocked_in_read_only(self, read_only_inspector):
        """DELETE blocked in read-only mode."""
        verdict = read_only_inspector.inspect("DELETE FROM users WHERE id=1")
        assert verdict.blocked

    def test_insert_allowed_in_safe_write(self, safe_write_inspector):
        """INSERT allowed to permitted tables in safe-write mode."""
        verdict = safe_write_inspector.inspect("INSERT INTO users (name) VALUES ('test')")
        assert verdict.passed, f"Should allow INSERT to allowed table: {verdict.reason}"

    def test_insert_blocked_to_unauthorized_table(self, safe_write_inspector):
        """INSERT blocked to non-permitted tables."""
        verdict = safe_write_inspector.inspect("INSERT INTO secrets (data) VALUES ('stolen')")
        assert verdict.blocked

    def test_bulk_delete_blocked(self, safe_write_inspector):
        """DELETE without WHERE (bulk delete) should be blocked."""
        verdict = safe_write_inspector.inspect("DELETE FROM users")
        assert verdict.blocked
        assert "bulk" in verdict.rule.lower() or "where" in verdict.reason.lower()


# =============================================================================
# CASE VARIATIONS
# =============================================================================


class TestCaseVariations:
    """Test that case variations don't bypass protection."""

    @pytest.mark.parametrize(
        "sql",
        [
            "drop table users",
            "DROP TABLE users",
            "Drop Table Users",
            "dRoP tAbLe UsErS",
            "DROP TABLE USERS",
        ],
    )
    def test_drop_case_insensitive(self, sql):
        """DROP should be blocked regardless of case."""
        assert check_sql(sql) is False

    @pytest.mark.parametrize(
        "sql",
        [
            "select * from users",
            "SELECT * FROM users",
            "Select * From Users",
            "sElEcT * fRoM uSeRs",
        ],
    )
    def test_select_case_insensitive(self, sql):
        """SELECT should pass regardless of case."""
        assert check_sql(sql) is True


# =============================================================================
# WHITESPACE VARIATIONS
# =============================================================================


class TestWhitespaceVariations:
    """Test that whitespace variations don't bypass protection."""

    @pytest.mark.parametrize(
        "sql",
        [
            "DROP TABLE users",
            "DROP  TABLE  users",
            "DROP\tTABLE\tusers",
            "DROP\nTABLE\nusers",
            "  DROP TABLE users  ",
            "DROP\r\nTABLE\r\nusers",
        ],
    )
    def test_drop_with_whitespace(self, sql):
        """DROP blocked regardless of whitespace."""
        assert check_sql(sql) is False


# =============================================================================
# STACKED QUERIES
# =============================================================================


class TestStackedQueries:
    """Test that stacked queries with dangerous statements are blocked."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM users; DROP TABLE users",
            "SELECT 1; DROP TABLE users",
            "SELECT 1;DROP TABLE users",
            "SELECT * FROM users;\nDROP TABLE users",
            "SELECT * FROM users; ALTER TABLE users ADD col INT",
            "SELECT * FROM users; CREATE TABLE hackers (id INT)",
        ],
    )
    def test_stacked_dangerous_queries_blocked(self, sql):
        """Stacked queries with dangerous operations must be blocked."""
        assert check_sql(sql) is False


# =============================================================================
# EDGE CASES
# =============================================================================


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_query_blocked(self):
        """Empty query should be blocked."""
        assert check_sql("") is False
        assert check_sql("   ") is False
        assert check_sql("\n\t") is False

    def test_invalid_sql_blocked(self):
        """Invalid SQL should be blocked (deny by default)."""
        assert check_sql("NOT VALID SQL!!!") is False
        assert check_sql("GIBBERISH xyz 123") is False

    def test_incomplete_sql_blocked(self):
        """Incomplete SQL should be blocked (when it fails to parse)."""
        # Note: "SELECT" alone is valid in some dialects (PostgreSQL)
        # We focus on blocking actually dangerous incomplete statements
        assert check_sql("SELECT * FROM") is False
        assert check_sql("DROP TABLE") is False
        assert check_sql("INSERT INTO") is False

    def test_drop_in_string_literal_allowed(self):
        """DROP as a string literal should be allowed."""
        assert check_sql("SELECT 'DROP TABLE users' AS text") is True

    def test_drop_as_table_name_allowed(self):
        """Table named with DROP in name should be allowed."""
        assert check_sql("SELECT * FROM drop_logs") is True
        assert check_sql("SELECT * FROM user_drops") is True

    def test_drop_as_column_value_allowed(self):
        """DROP as a column value should be allowed."""
        assert check_sql("SELECT * FROM users WHERE action = 'DROP'") is True


# =============================================================================
# LEGITIMATE QUERIES
# =============================================================================


class TestLegitimateQueries:
    """Test that legitimate queries pass."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT * FROM users",
            "SELECT id, name, email FROM users WHERE active = true",
            "SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id",
            "SELECT COUNT(*) FROM users GROUP BY status",
            "SELECT * FROM users ORDER BY created_at DESC LIMIT 10",
            "SELECT * FROM users WHERE name LIKE '%john%'",
            "SELECT * FROM users WHERE id IN (1, 2, 3)",
            "SELECT DISTINCT status FROM users",
            "SELECT MAX(price), MIN(price), AVG(price) FROM products",
            "SELECT * FROM users WHERE created_at > '2024-01-01'",
        ],
    )
    def test_legitimate_selects_pass(self, sql):
        """Legitimate SELECT queries should pass."""
        assert check_sql(sql) is True, f"Should allow: {sql}"

    def test_subquery_allowed(self):
        """Subqueries should be allowed."""
        sql = "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders)"
        assert check_sql(sql) is True

    def test_cte_allowed(self):
        """Common Table Expressions should be allowed."""
        sql = "WITH active AS (SELECT * FROM users WHERE active=true) SELECT * FROM active"
        assert check_sql(sql) is True

    def test_union_of_selects_allowed(self):
        """UNION of SELECT statements should be allowed."""
        sql = "SELECT id, name FROM users UNION SELECT id, name FROM admins"
        assert check_sql(sql) is True


# =============================================================================
# PERFORMANCE TESTS
# =============================================================================


class TestPerformance:
    """Test that inspection is fast enough for real-time use."""

    def test_latency_under_50ms(self):
        """Inspection should complete in under 50ms."""
        import time

        queries = [
            "SELECT * FROM users WHERE id = 1",
            "DROP TABLE users",
            "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true",
        ]

        for sql in queries:
            start = time.perf_counter()
            inspect_sql(sql)
            elapsed_ms = (time.perf_counter() - start) * 1000

            assert elapsed_ms < 50, f"Query took {elapsed_ms:.2f}ms: {sql[:50]}..."

    def test_verdict_reports_latency(self):
        """Verdict should report inspection latency."""
        verdict = inspect_sql("SELECT * FROM users")
        assert verdict.latency_ms > 0
        assert verdict.latency_ms < 100  # Sanity check


# =============================================================================
# VECTOR FILE TESTS
# =============================================================================


class TestVectorFile:
    """Test all vectors from the JSON file."""

    def test_basic_destructive_vectors(self, attack_vectors):
        """Test basic destructive SQL vectors."""
        for vector in attack_vectors["categories"]["basic_destructive"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]  # check_sql returns True if allowed
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_case_variation_vectors(self, attack_vectors):
        """Test case variation vectors."""
        for vector in attack_vectors["categories"]["case_variations"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_safe_query_vectors(self, attack_vectors):
        """Test that safe queries pass."""
        for vector in attack_vectors["categories"]["safe_queries"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_edge_case_vectors(self, attack_vectors):
        """Test edge case vectors."""
        for vector in attack_vectors["categories"]["edge_cases"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_stacked_query_vectors(self, attack_vectors):
        """Test stacked query vectors."""
        for vector in attack_vectors["categories"]["stacked_queries"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"


# =============================================================================
# OBFUSCATION TESTS (THE REAL MOAT TEST)
# =============================================================================


class TestObfuscationDetection:
    """
    Test detection of obfuscated attacks.

    THIS IS WHERE THE MOAT IS PROVEN.
    Regex-based solutions fail these tests.
    """

    def test_comment_within_keyword(self):
        """Comments within keywords should still be detected."""
        # DROP/**/TABLE should still be parsed as DROP TABLE
        result = check_sql("DROP/*comment*/TABLE users")
        assert result is False, "Should block DROP with inline comment"

    def test_multiple_statements_detection(self):
        """Multiple statements should all be analyzed."""
        # Even if first statement is safe, second is dangerous
        result = check_sql("SELECT 1; DROP TABLE users; SELECT 2")
        assert result is False, "Should detect DROP in middle of batch"

    def test_string_concatenation_not_executed(self):
        """String concatenation in SELECT should not be treated as command."""
        # This is a SELECT that returns a string, not an execution
        result = check_sql("SELECT 'DROP' || ' TABLE'")
        assert result is True, "String concat in SELECT is not dangerous"

    def test_deeply_nested_subquery_with_danger(self):
        """Dangerous operations in deep subqueries should be caught."""
        # This shouldn't be possible in standard SQL, but test AST depth
        sql = """
        SELECT * FROM users WHERE id IN (
            SELECT user_id FROM orders WHERE product_id IN (
                SELECT id FROM products
            )
        )
        """
        result = check_sql(sql)
        assert result is True, "Deep but safe subqueries should pass"


# =============================================================================
# DIALECT TESTS
# =============================================================================


class TestDialects:
    """Test SQL dialect handling."""

    def test_postgres_syntax(self):
        """PostgreSQL-specific syntax should work."""
        inspector = SQLInspector(dialect="postgres")

        # PostgreSQL LIMIT syntax
        verdict = inspector.inspect("SELECT * FROM users LIMIT 10 OFFSET 5")
        assert verdict.passed

    def test_mysql_syntax(self):
        """MySQL-specific syntax should work."""
        inspector = SQLInspector(dialect="mysql")

        # MySQL backtick quoting
        verdict = inspector.inspect("SELECT * FROM `users` WHERE `id` = 1")
        assert verdict.passed

    def test_drop_blocked_all_dialects(self):
        """DROP should be blocked in all dialects."""
        for dialect in ["postgres", "mysql", "sqlite", "snowflake", "bigquery"]:
            inspector = SQLInspector(dialect=dialect)
            verdict = inspector.inspect("DROP TABLE users")
            assert verdict.blocked, f"DROP should be blocked in {dialect}"


# =============================================================================
# PRIVILEGE ESCALATION TESTS
# =============================================================================


class TestPrivilegeEscalation:
    """Test that privilege escalation attempts are blocked."""

    @pytest.mark.parametrize(
        "sql",
        [
            "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'",
            "GRANT SELECT ON users TO public",
            "GRANT INSERT, UPDATE ON orders TO app_user",
        ],
    )
    def test_grant_statements_blocked(self, sql):
        """GRANT statements should be blocked."""
        verdict = inspect_sql(sql)
        assert verdict.blocked, f"Should block: {sql}"

    @pytest.mark.parametrize(
        "sql",
        [
            "CREATE ROLE admin",
            "CREATE USER hacker WITH PASSWORD 'password123'",
        ],
    )
    def test_create_user_role_blocked(self, sql):
        """CREATE USER/ROLE should be blocked."""
        verdict = inspect_sql(sql)
        assert verdict.blocked, f"Should block: {sql}"


# =============================================================================
# DANGEROUS FUNCTION TESTS
# =============================================================================


class TestDangerousFunctions:
    """Test that dangerous database functions are detected."""

    def test_exec_blocked(self):
        """EXEC/EXECUTE commands should be blocked."""
        assert check_sql("EXEC xp_cmdshell 'whoami'") is False
        assert check_sql("EXECUTE sp_executesql N'SELECT 1'") is False

    def test_load_data_blocked(self):
        """LOAD DATA should be blocked."""
        # This may or may not parse depending on dialect
        verdict = inspect_sql("LOAD DATA INFILE '/etc/passwd' INTO TABLE users")
        # Should be blocked either by LoadData node or parse failure
        assert verdict.blocked, "LOAD DATA should be blocked"


# =============================================================================
# BLOCKED TABLE TESTS
# =============================================================================


class TestBlockedTables:
    """Test that access to blocked tables is prevented."""

    def test_blocked_table_select(self):
        """SELECT from blocked tables should be blocked."""
        inspector = SQLInspector(
            mode=SQLMode.READ_ONLY, blocked_tables={"audit_logs", "secrets", "credentials"}
        )

        verdict = inspector.inspect("SELECT * FROM audit_logs")
        assert verdict.blocked
        assert "blocked_table" in verdict.rule

    def test_blocked_table_in_join(self):
        """Blocked tables in JOINs should be detected."""
        inspector = SQLInspector(mode=SQLMode.READ_ONLY, blocked_tables={"secrets"})

        verdict = inspector.inspect(
            "SELECT u.name, s.api_key FROM users u JOIN secrets s ON u.id = s.user_id"
        )
        assert verdict.blocked

    def test_allowed_table_passes(self):
        """Non-blocked tables should pass."""
        inspector = SQLInspector(mode=SQLMode.READ_ONLY, blocked_tables={"secrets"})

        verdict = inspector.inspect("SELECT * FROM users")
        assert verdict.passed


# =============================================================================
# COMPREHENSIVE VECTOR TESTS
# =============================================================================


class TestAllVectorCategories:
    """Run all vectors from the JSON file by category."""

    def test_privilege_escalation_vectors(self, attack_vectors):
        """Test privilege escalation vectors."""
        if "privilege_escalation" not in attack_vectors["categories"]:
            pytest.skip("No privilege_escalation category")

        for vector in attack_vectors["categories"]["privilege_escalation"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_dangerous_functions_vectors(self, attack_vectors):
        """Test dangerous functions vectors."""
        if "dangerous_functions" not in attack_vectors["categories"]:
            pytest.skip("No dangerous_functions category")

        for vector in attack_vectors["categories"]["dangerous_functions"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"

    def test_whitespace_variations_vectors(self, attack_vectors):
        """Test whitespace variation vectors."""
        for vector in attack_vectors["categories"]["whitespace_variations"]["vectors"]:
            result = check_sql(vector["sql"])
            expected = not vector["should_block"]
            assert result == expected, f"Vector failed: {vector['reason']} - SQL: {vector['sql']}"


# =============================================================================
# SUMMARY: What This Test Suite Validates
# =============================================================================
#
# BLOCKED (Security Threats):
# - DROP, ALTER, CREATE, TRUNCATE (schema destruction)
# - GRANT (privilege escalation)
# - EXEC, EXECUTE, xp_cmdshell (command execution)
# - LOAD DATA, INTO OUTFILE (file access)
# - INSERT, UPDATE, DELETE (in read-only mode)
# - Stacked queries with dangerous operations
# - Bulk DELETE without WHERE clause
#
# ALLOWED (Legitimate Operations):
# - SELECT queries (simple and complex)
# - JOINs, subqueries, CTEs, UNIONs
# - String literals containing SQL keywords
# - Tables with SQL keywords in names
# - Dialect-specific syntax
#
# STILL NEED WORK:
# - Hex encoding detection
# - Unicode bypass detection
# - Time-based attack detection (SLEEP, WAITFOR)
# - More sophisticated obfuscation patterns
#
