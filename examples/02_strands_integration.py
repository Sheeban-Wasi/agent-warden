"""
Example 2: AWS Strands SDK Integration

This example shows how to protect your Strands agent tools
with the @guard decorator.

Prerequisites:
    pip install strands-agents agent-warden
"""

import json
from warden import guard

# =============================================================================
# MOCK DATABASE (replace with your actual database)
# =============================================================================

class MockDatabase:
    """Simulates a database for this example."""

    def __init__(self):
        self.users = [
            {"id": 1, "name": "Alice", "email": "alice@example.com"},
            {"id": 2, "name": "Bob", "email": "bob@example.com"},
        ]

    def execute(self, query: str) -> list:
        # In real code, this would execute the actual query
        if "SELECT" in query.upper():
            return self.users
        return []

db = MockDatabase()

# =============================================================================
# PROTECTED TOOLS
# =============================================================================

# Basic protection - read-only mode
@guard(mode="read-only", audit=False)
def query_database(sql: str) -> str:
    """Execute a read-only SQL query."""
    results = db.execute(sql)
    return json.dumps(results, indent=2)


# Safe-write mode - allows writes to specific tables
@guard(
    mode="safe-write",
    allowed_tables={"audit_logs", "user_preferences"},
    audit=False,
)
def write_data(sql: str) -> str:
    """Write data to allowed tables only."""
    db.execute(sql)
    return "Write successful"


# Return error instead of raising exception
@guard(
    mode="read-only",
    on_block="return_error",
    audit=False,
)
def safe_query(sql: str) -> dict:
    """Query that returns error dict on block (good for agents)."""
    results = db.execute(sql)
    return {"success": True, "data": results}


# =============================================================================
# TEST THE TOOLS
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Testing Protected Tools")
    print("=" * 60)

    # Test 1: Safe SELECT
    print("\n1. Safe SELECT query:")
    result = query_database("SELECT * FROM users")
    print(result)

    # Test 2: Blocked DROP
    print("\n2. Blocked DROP query:")
    try:
        query_database("DROP TABLE users")
    except Exception as e:
        print(f"   Blocked! Error: {type(e).__name__}")
        print(f"   Message: {e}")

    # Test 3: Safe write to allowed table
    print("\n3. Write to allowed table (audit_logs):")
    result = write_data("INSERT INTO audit_logs (msg) VALUES ('test')")
    print(f"   Result: {result}")

    # Test 4: Blocked write to unauthorized table
    print("\n4. Write to unauthorized table (users):")
    try:
        write_data("INSERT INTO users (name) VALUES ('hacker')")
    except Exception as e:
        print(f"   Blocked! Error: {type(e).__name__}")

    # Test 5: Return error instead of exception
    print("\n5. Query with on_block='return_error':")
    result = safe_query("DELETE FROM users")
    print(f"   Result: {result}")


# =============================================================================
# WITH ACTUAL STRANDS SDK
# =============================================================================
#
# Uncomment this section if you have strands-agents installed:
#
# from strands import Agent, tool
# from warden import guard
#
# @tool
# @guard(mode="read-only")
# def database_query(query: str) -> str:
#     """Execute a read-only SQL query against the database.
#
#     Args:
#         query: The SQL query to execute (SELECT only)
#
#     Returns:
#         JSON string with query results
#     """
#     results = db.execute(query)
#     return json.dumps(results)
#
# # Create agent with protected tools
# agent = Agent(
#     tools=[database_query],
#     system_prompt="You are a helpful assistant with read-only database access."
# )
#
# # Run the agent
# response = agent.run("Show me all users")
# print(response)
