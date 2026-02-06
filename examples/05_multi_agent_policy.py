"""
Example 5: Multi-Agent Policy Engine

This example shows how to use the Policy Engine with multiple AI agents,
where each agent has different permissions based on its role.

SCENARIO:
- You have multiple Strands agents (analytics-bot, support-bot, admin-bot)
- Each agent can execute SQL queries based on user questions
- You don't know what tables they'll hit - it depends on the user's question
- You want different security rules for each agent

HOW IT WORKS:
1. Define rules in policy.yaml (which tables each agent can access)
2. Load the policy once at startup
3. Each agent gets its own guard with its specific rules
4. When user asks a question, the agent generates SQL
5. Warden checks the SQL against that agent's rules
6. Blocked if it tries to access unauthorized tables
"""

from warden import PolicyEngine, create_policy_guard, PolicyViolation, CriticalViolation

# =============================================================================
# STEP 1: LOAD POLICY FROM YAML
# =============================================================================

# In production, load from file:
# engine = PolicyEngine.from_file("policy.yaml")

# For this example, we'll create policy inline:
POLICY_YAML = """
version: "1.0"
name: "multi-agent-demo"

# Default rules (if agent not specified)
sql:
  mode: read-only
  blocked_tables:
    - credentials
    - api_keys
    - secrets

# Agent-specific rules
agents:
  analytics-bot:
    description: "Can only read from reporting tables"
    sql:
      mode: read-only
      allowed_tables:
        - reports
        - metrics
        - dashboard_data
      blocked_tables:
        - users
        - orders
        - payments

  support-bot:
    description: "Can read customers, write to tickets"
    sql:
      mode: safe-write
      allowed_tables:
        - tickets
        - ticket_comments
      blocked_tables:
        - credentials
        - payments

  admin-bot:
    description: "More access, but still protected"
    sql:
      mode: safe-write
      allowed_tables:
        - audit_logs
        - system_settings
      blocked_tables:
        - credentials
"""

engine = PolicyEngine.from_yaml(POLICY_YAML)

# =============================================================================
# STEP 2: CREATE AGENT-SPECIFIC GUARDS
# =============================================================================

# Each agent gets its own guard with its rules from the policy
analytics_guard = create_policy_guard(engine, agent="analytics-bot", on_block="return_error")
support_guard = create_policy_guard(engine, agent="support-bot", on_block="return_error")
admin_guard = create_policy_guard(engine, agent="admin-bot", on_block="return_error")

# =============================================================================
# STEP 3: PROTECTED AGENT TOOLS
# =============================================================================


# Analytics bot's SQL tool
@analytics_guard
def analytics_query(sql: str) -> dict:
    """Execute SQL for analytics bot."""
    # In real code: return db.execute(sql)
    return {"success": True, "data": f"Analytics result for: {sql}"}


# Support bot's SQL tool
@support_guard
def support_query(sql: str) -> dict:
    """Execute SQL for support bot."""
    return {"success": True, "data": f"Support result for: {sql}"}


# Admin bot's SQL tool
@admin_guard
def admin_query(sql: str) -> dict:
    """Execute SQL for admin bot."""
    return {"success": True, "data": f"Admin result for: {sql}"}


# =============================================================================
# STEP 4: SIMULATE USER INTERACTIONS
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("Multi-Agent Policy Demo")
    print("=" * 70)

    # ----- ANALYTICS BOT -----
    print("\n[ANALYTICS BOT]")
    print("-" * 40)

    # User asks: "Show me the sales metrics"
    # Agent generates: SELECT * FROM metrics
    result = analytics_query("SELECT * FROM metrics")
    print(f"Query metrics: {result}")

    # User asks: "Show me user emails"
    # Agent generates: SELECT email FROM users
    # BLOCKED - analytics can't access users table
    result = analytics_query("SELECT email FROM users")
    print(f"Query users: {result}")

    # User asks: "Delete old reports"
    # Agent generates: DELETE FROM reports WHERE date < '2020-01-01'
    # BLOCKED - analytics is read-only
    result = analytics_query("DELETE FROM reports WHERE date < '2020-01-01'")
    print(f"Delete reports: {result}")

    # ----- SUPPORT BOT -----
    print("\n[SUPPORT BOT]")
    print("-" * 40)

    # User asks: "Create a ticket for me"
    # Agent generates: INSERT INTO tickets (subject) VALUES ('Help needed')
    result = support_query("INSERT INTO tickets (subject) VALUES ('Help needed')")
    print(f"Create ticket: {result}")

    # User asks: "Show me payment info"
    # Agent generates: SELECT * FROM payments
    # BLOCKED - support can't access payments
    result = support_query("SELECT * FROM payments")
    print(f"Query payments: {result}")

    # ----- ADMIN BOT -----
    print("\n[ADMIN BOT]")
    print("-" * 40)

    # User asks: "Log this action"
    # Agent generates: INSERT INTO audit_logs (action) VALUES ('test')
    result = admin_query("INSERT INTO audit_logs (action) VALUES ('test')")
    print(f"Write audit log: {result}")

    # User asks: "Show credentials"
    # Agent generates: SELECT * FROM credentials
    # BLOCKED - even admin can't access credentials
    result = admin_query("SELECT * FROM credentials")
    print(f"Query credentials: {result}")

    # User asks: "Drop the users table"
    # Agent generates: DROP TABLE users
    # BLOCKED - DROP is always blocked
    result = admin_query("DROP TABLE users")
    print(f"Drop table: {result}")

    print("\n" + "=" * 70)
    print("KEY TAKEAWAYS:")
    print("=" * 70)
    print("""
1. DYNAMIC QUERIES ARE SAFE
   - Agents generate SQL based on user questions
   - Warden checks every query against the agent's rules
   - No need to predict what tables the agent will query

2. AGENT ISOLATION
   - analytics-bot can't see user data
   - support-bot can't see payments
   - admin-bot still can't access credentials

3. LAYERED PROTECTION
   - Table-level restrictions (allowed_tables, blocked_tables)
   - Operation-level restrictions (read-only vs safe-write)
   - Always-blocked operations (DROP, TRUNCATE, etc.)

4. YAML CONFIGURATION
   - Security team can edit rules without code changes
   - Different policies for dev/staging/prod
   - Git history shows who changed what
""")
