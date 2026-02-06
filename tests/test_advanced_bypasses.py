"""
Advanced SQL Injection Bypass Tests.

These tests validate that Agent-Warden blocks sophisticated bypass techniques
used by attackers to evade regex-based WAFs.

Sources:
- https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/
- https://github.com/danielmiessler/SecLists
- https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF
- https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet
- https://nastystereo.com/security/sqli-polyglots.html
"""

import json
from pathlib import Path

import pytest

from warden import check_sql


@pytest.fixture
def bypass_vectors():
    """Load advanced bypass vectors from JSON file."""
    vectors_path = Path(__file__).parent / "vectors" / "advanced_bypasses.json"
    with open(vectors_path) as f:
        return json.load(f)


def run_vector_tests(vectors, category_name):
    """Helper to run tests for a category of vectors."""
    for v in vectors:
        dialect = v.get("dialect")
        result = check_sql(v["sql"], dialect=dialect)
        expected = not v["should_block"]
        assert result == expected, f"Failed [{category_name}]: {v['reason']} - {v['sql']}"


# =============================================================================
# AST PARSING ADVANTAGE TESTS
# =============================================================================


class TestASTAdvantage:
    """
    Tests that demonstrate AST parsing advantage over regex.

    Regex-based filters fail these. AST parsing handles them because
    it understands SQL structure, not just text patterns.
    """

    def test_comments_dont_hide_drop(self):
        """Comments within DROP statement are still parsed as DROP."""
        # Regex might see "DR" and "OP" as separate, AST sees DROP
        assert check_sql("DROP/*comment*/TABLE users") is False
        assert check_sql("DROP/* sneaky */TABLE/* comment */users") is False

    def test_whitespace_variations_dont_bypass(self):
        """Various whitespace characters don't bypass detection."""
        # All of these should be blocked
        assert check_sql("DROP\tTABLE\tusers") is False  # tabs
        assert check_sql("DROP\nTABLE\nusers") is False  # newlines
        assert check_sql("DROP  TABLE  users") is False  # multiple spaces
        assert check_sql("DROP\r\nTABLE\r\nusers") is False  # CRLF

    def test_case_insensitive_detection(self):
        """Mixed case doesn't bypass detection."""
        assert check_sql("dRoP tAbLe UsErS") is False
        assert check_sql("DROP TABLE USERS") is False
        assert check_sql("drop table users") is False

    def test_string_literals_are_safe(self):
        """Keywords in string literals are not dangerous."""
        # These are just data, not commands
        assert check_sql("SELECT 'DROP TABLE users' AS text") is True
        assert check_sql("SELECT * FROM users WHERE action = 'DROP'") is True
        # blocked by read-only mode, not the content
        assert check_sql("INSERT INTO logs VALUES ('User tried DROP')") is False


# =============================================================================
# VECTOR-BASED CATEGORY TESTS
# =============================================================================


class TestWhitespaceBypass:
    """Test whitespace alternative bypass attempts."""

    def test_whitespace_vectors(self, bypass_vectors):
        """Whitespace alternative techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["whitespace_alternatives"]["vectors"],
            "whitespace_alternatives",
        )


class TestNoSpaceBypass:
    """Test no-space bypass attempts."""

    def test_no_space_vectors(self, bypass_vectors):
        """No-space bypass techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["no_space_bypass"]["vectors"], "no_space_bypass"
        )


class TestCommentObfuscation:
    """Test comment-based obfuscation attempts."""

    def test_comment_vectors(self, bypass_vectors):
        """Comment obfuscation techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["comment_obfuscation"]["vectors"], "comment_obfuscation"
        )


class TestMySQLConditional:
    """Test MySQL conditional comment attacks."""

    def test_mysql_conditional_vectors(self, bypass_vectors):
        """MySQL version-specific conditional comments."""
        for v in bypass_vectors["categories"]["mysql_conditional_comments"]["vectors"]:
            result = check_sql(v["sql"])
            if v["should_block"]:
                assert result is False, f"Should block: {v['reason']} - {v['sql']}"


class TestCaseAndEncoding:
    """Test case manipulation and encoding tricks."""

    def test_case_encoding_vectors(self, bypass_vectors):
        """Case and encoding techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["case_and_encoding"]["vectors"], "case_and_encoding"
        )


class TestKeywordDoubling:
    """Test keyword doubling bypass attempts."""

    def test_keyword_doubling_vectors(self, bypass_vectors):
        """Keyword doubling techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["keyword_doubling"]["vectors"], "keyword_doubling"
        )


class TestParenthesesNesting:
    """Test excessive parentheses nesting."""

    def test_parentheses_vectors(self, bypass_vectors):
        """Parentheses nesting techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["parentheses_nesting"]["vectors"], "parentheses_nesting"
        )


class TestStackedWithObfuscation:
    """Test stacked queries with obfuscation."""

    def test_stacked_obfuscation_vectors(self, bypass_vectors):
        """Stacked queries with various bypass techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["stacked_with_obfuscation"]["vectors"],
            "stacked_with_obfuscation",
        )


class TestUnionAdvanced:
    """Test advanced UNION injection patterns."""

    def test_union_advanced_vectors(self, bypass_vectors):
        """Advanced UNION-based injection patterns."""
        run_vector_tests(
            bypass_vectors["categories"]["union_based_advanced"]["vectors"], "union_based_advanced"
        )


class TestNoCommaBypass:
    """Test no-comma bypass techniques."""

    def test_no_comma_vectors(self, bypass_vectors):
        """No-comma bypass techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["no_comma_bypass"]["vectors"], "no_comma_bypass"
        )


class TestNoEqualBypass:
    """Test no-equal-sign bypass techniques."""

    def test_no_equal_vectors(self, bypass_vectors):
        """No-equal-sign bypass techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["no_equal_bypass"]["vectors"], "no_equal_bypass"
        )


class TestFunctionSynonyms:
    """Test function synonym bypass techniques."""

    def test_function_synonym_vectors(self, bypass_vectors):
        """Function synonym techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["function_synonyms"]["vectors"], "function_synonyms"
        )


class TestBooleanBlind:
    """Test boolean-based blind injection patterns."""

    def test_boolean_blind_vectors(self, bypass_vectors):
        """Boolean-based blind injection patterns."""
        run_vector_tests(bypass_vectors["categories"]["boolean_blind"]["vectors"], "boolean_blind")


class TestTimeBasedBlind:
    """Test time-based blind injection patterns."""

    def test_time_based_vectors(self, bypass_vectors):
        """Time-based blind injection patterns."""
        run_vector_tests(
            bypass_vectors["categories"]["time_based_blind"]["vectors"], "time_based_blind"
        )


class TestAuthenticationBypass:
    """Test authentication bypass patterns."""

    def test_auth_bypass_vectors(self, bypass_vectors):
        """Authentication bypass patterns."""
        run_vector_tests(
            bypass_vectors["categories"]["authentication_bypass"]["vectors"],
            "authentication_bypass",
        )


class TestOutOfBand:
    """Test out-of-band data exfiltration techniques."""

    def test_oob_vectors(self, bypass_vectors):
        """Out-of-band exfiltration techniques."""
        run_vector_tests(bypass_vectors["categories"]["out_of_band"]["vectors"], "out_of_band")


class TestSecondOrder:
    """Test second-order injection payloads."""

    def test_second_order_vectors(self, bypass_vectors):
        """Second-order injection payloads."""
        run_vector_tests(bypass_vectors["categories"]["second_order"]["vectors"], "second_order")


class TestPolyglot:
    """Test polyglot payloads."""

    def test_polyglot_vectors(self, bypass_vectors):
        """Polyglot payloads that work in multiple contexts."""
        run_vector_tests(bypass_vectors["categories"]["polyglot"]["vectors"], "polyglot")


class TestRealWorldPayloads:
    """Test real-world payloads from disclosed vulnerabilities."""

    def test_real_world_vectors(self, bypass_vectors):
        """Real-world injection payloads."""
        run_vector_tests(
            bypass_vectors["categories"]["real_world_payloads"]["vectors"], "real_world_payloads"
        )


class TestSQLServerSpecific:
    """Test SQL Server specific techniques."""

    def test_sqlserver_vectors(self, bypass_vectors):
        """SQL Server specific techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["sqlserver_specific"]["vectors"], "sqlserver_specific"
        )


class TestOracleSpecific:
    """Test Oracle specific techniques."""

    def test_oracle_vectors(self, bypass_vectors):
        """Oracle specific techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["oracle_specific"]["vectors"], "oracle_specific"
        )


class TestPostgresSpecific:
    """Test PostgreSQL specific techniques."""

    def test_postgres_vectors(self, bypass_vectors):
        """PostgreSQL specific techniques."""
        run_vector_tests(
            bypass_vectors["categories"]["postgres_specific"]["vectors"], "postgres_specific"
        )


class TestDangerousFunctions:
    """Test dangerous database functions."""

    def test_dangerous_function_vectors(self, bypass_vectors):
        """Dangerous database functions."""
        run_vector_tests(
            bypass_vectors["categories"]["dangerous_functions"]["vectors"], "dangerous_functions"
        )


# =============================================================================
# ENCODING AND OBFUSCATION
# =============================================================================


class TestEncodingAttacks:
    """Test encoding-based attacks."""

    def test_hex_literals_safe(self):
        """Hex literals in SELECT are just data."""
        # 0x44524F50 = "DROP" in hex, but it's just a string value
        # Note: Hex literals require MySQL dialect to parse correctly
        assert check_sql("SELECT 0x44524F50", dialect="mysql") is True
        assert check_sql("SELECT * FROM users WHERE data = 0x41424344", dialect="mysql") is True

    def test_char_function_safe(self):
        """CHAR() function returns data, not executed."""
        # CHAR(68,82,79,80) returns "DROP" as a string
        assert check_sql("SELECT CHAR(68,82,79,80)") is True

    def test_concat_in_select_safe(self):
        """String concatenation in SELECT is safe."""
        assert check_sql("SELECT CONCAT('DR', 'OP')") is True
        assert check_sql("SELECT 'DROP' || ' TABLE'") is True


# =============================================================================
# BUFFER OVERFLOW / DOS PREVENTION
# =============================================================================


class TestBufferOverflow:
    """Test buffer overflow and DoS prevention."""

    def test_max_query_length(self):
        """Extremely long queries are blocked."""
        from warden.core.inspectors.sql import SQLInspector

        inspector = SQLInspector(max_query_length=1000)
        long_query = "SELECT * FROM users WHERE id IN (" + ",".join(["1"] * 500) + ")"
        verdict = inspector.inspect(long_query)
        assert verdict.blocked
        assert "exceeds maximum length" in verdict.reason

    def test_normal_length_allowed(self):
        """Normal length queries pass."""
        from warden.core.inspectors.sql import SQLInspector

        inspector = SQLInspector(max_query_length=100_000)
        normal_query = "SELECT * FROM users WHERE id = 1"
        verdict = inspector.inspect(normal_query)
        assert verdict.passed


# =============================================================================
# SUMMARY
# =============================================================================
#
# Why AST parsing beats regex:
#
# 1. STRUCTURE over TEXT
#    Regex: Sees "DROP" as 4 characters
#    AST:   Sees DROP as a node type in the syntax tree
#
# 2. WHITESPACE NORMALIZATION
#    Regex: "DROP\t\nTABLE" might not match "DROP TABLE"
#    AST:   Both parse to the same tree structure
#
# 3. COMMENT HANDLING
#    Regex: "DR/**/OP" looks like "DR" and "OP"
#    AST:   Comments stripped, sees "DROP"
#
# 4. CONTEXT AWARENESS
#    Regex: 'DROP' in a string looks dangerous
#    AST:   Knows it's inside a string literal (safe)
#
# ADDITIONAL PATTERNS DETECTED:
# - MySQL conditional comments (/*!50000 ... */)
# - UNION injection signatures (literal UNION SELECT)
# - Keyword doubling attempts
# - Out-of-band exfiltration (LOAD_FILE, INTO OUTFILE)
# - Dynamic SQL execution (EXEC, sp_executesql)
# - Stacked queries with obfuscation
#
