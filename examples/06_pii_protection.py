"""
Example 6: PII Protection

This example shows how to detect and handle Personally Identifiable Information
(PII) in AI agent workflows using Agent-Warden's PII Inspector.

SCENARIO:
- You have an AI agent that processes user messages
- Messages may contain sensitive data (emails, SSNs, credit cards, etc.)
- You need to either block, redact, mask, or hash the PII before processing

STRATEGIES:
1. block   - Reject the request entirely if PII is found
2. redact  - Replace PII with [TYPE REDACTED]
3. mask    - Show only last 4 characters (***1234)
4. hash    - Replace with deterministic hash [HASH:abc123]
5. monitor - Log PII but don't modify (for testing)
"""

from warden import (
    PIIInspector,
    check_pii,
    guard,
    inspect_pii,
    redact_pii,
)

# =============================================================================
# EXAMPLE 1: QUICK PII CHECK
# =============================================================================

print("=" * 70)
print("Example 1: Quick PII Check")
print("=" * 70)

# Simple boolean check - does text contain PII?
messages = [
    "Hello, how are you today?",
    "My email is john@example.com",
    "Call me at 555-123-4567",
    "My SSN is 123-45-6789",
    "Pay with card 4111111111111111",
]

for msg in messages:
    has_pii = check_pii(msg)
    status = "Contains PII" if has_pii else "Clean"
    print(f"  [{status}] {msg[:50]}")

# =============================================================================
# EXAMPLE 2: REDACT PII FROM TEXT
# =============================================================================

print("\n" + "=" * 70)
print("Example 2: Redact PII")
print("=" * 70)

# The redact_pii function is a quick way to sanitize text
text = """
Customer Support Ticket:
From: john.smith@company.com
Phone: (555) 123-4567
SSN: 123-45-6789
Credit Card: 4111-1111-1111-1111

Please help me reset my password.
"""

clean_text = redact_pii(text)
print("Original:")
print(text)
print("Sanitized:")
print(clean_text)

# =============================================================================
# EXAMPLE 3: DIFFERENT STRATEGIES
# =============================================================================

print("\n" + "=" * 70)
print("Example 3: Different Strategies")
print("=" * 70)

sample = "Contact: john@example.com, SSN: 123-45-6789"

strategies = ["block", "redact", "mask", "hash", "monitor"]

for strategy in strategies:
    result = inspect_pii(sample, strategy=strategy)
    print(f"\n{strategy.upper()}:")
    print(f"  Blocked: {result.verdict.blocked}")
    print(f"  Output:  {result.sanitized_text}")
    print(f"  PII found: {[t.value for t in result.pii_types_found]}")

# =============================================================================
# EXAMPLE 4: CUSTOM PII PATTERNS
# =============================================================================

print("\n" + "=" * 70)
print("Example 4: Custom PII Patterns")
print("=" * 70)

# Detect API keys (custom pattern)
inspector = PIIInspector(
    strategy="redact",
    custom_patterns={
        "api_key": r"sk-[a-zA-Z0-9]{32}",
        "aws_key": r"AKIA[0-9A-Z]{16}",
    },
)

text_with_keys = """
Here are my credentials:
OpenAI: sk-abcdefghijklmnopqrstuvwxyz123456
AWS: AKIAIOSFODNN7EXAMPLE
"""

result = inspector.inspect(text_with_keys)
print("Original:")
print(text_with_keys)
print("Sanitized:")
print(result.sanitized_text)

# =============================================================================
# EXAMPLE 5: PII WITH @guard DECORATOR
# =============================================================================

print("\n" + "=" * 70)
print("Example 5: PII with @guard Decorator")
print("=" * 70)


# Protect a function with PII redaction
@guard(
    sql=False,  # Disable SQL inspection
    pii=True,  # Enable PII detection
    pii_strategy="redact",  # Redact PII
    pii_apply_to="input",  # Apply to input only
    on_block="return_error",
    audit=False,  # Disable audit logging for demo
)
def process_message(message: str) -> dict:
    """Process a user message with PII protection."""
    # The message is already sanitized by the guard
    return {"processed": message, "length": len(message)}


# Test with different inputs
test_messages = [
    "Hello world!",
    "My email is john@example.com",
    "Contact me at 555-123-4567 or john@test.com",
]

for msg in test_messages:
    result = process_message(msg)
    print(f"\nInput:  {msg}")
    print(f"Output: {result}")


# =============================================================================
# EXAMPLE 6: BLOCK STRATEGY WITH @guard
# =============================================================================

print("\n" + "=" * 70)
print("Example 6: Block PII (Strict Mode)")
print("=" * 70)


@guard(
    sql=False,
    pii=True,
    pii_strategy="block",  # Block if PII detected
    on_block="return_error",
    audit=False,
)
def strict_process(message: str) -> dict:
    """Process message - blocks if PII found."""
    return {"success": True, "message": message}


# This will succeed (no PII)
result = strict_process("Hello, how can I help?")
print(f"Clean message: {result}")

# This will be blocked (contains PII)
result = strict_process("My SSN is 123-45-6789")
print(f"PII message: {result}")


# =============================================================================
# EXAMPLE 7: COMBINED SQL AND PII PROTECTION
# =============================================================================

print("\n" + "=" * 70)
print("Example 7: Combined SQL + PII Protection")
print("=" * 70)


@guard(
    sql=True,  # Enable SQL protection
    mode="read-only",
    pii=True,  # Enable PII protection
    pii_strategy="redact",
    pii_apply_to="both",  # Check both input and output
    on_block="return_error",
    audit=False,
)
def secure_query(query: str) -> dict:
    """Execute a query with full protection."""
    # In real code: return db.execute(query)
    return {"data": f"Results for: {query}"}


# Test: Clean query - works
result = secure_query("SELECT * FROM products")
print(f"Clean query: {result}")

# Test: PII in query - redacted
result = secure_query("SELECT * FROM users WHERE email = 'john@example.com'")
print(f"PII query: {result}")

# Test: SQL injection - blocked
result = secure_query("DROP TABLE users")
print(f"SQL injection: {result}")


# =============================================================================
# SUMMARY
# =============================================================================

print("\n" + "=" * 70)
print("KEY TAKEAWAYS")
print("=" * 70)
print("""
1. QUICK CHECK
   if check_pii(text):
       print("Contains PII!")

2. REDACT FOR LOGGING
   clean = redact_pii(user_message)
   logger.info(f"User said: {clean}")

3. STRATEGIES
   - block:   Reject requests with PII
   - redact:  Replace with [TYPE REDACTED]
   - mask:    Show last 4 chars only
   - hash:    Deterministic hash for linking
   - monitor: Log only, don't modify

4. WITH @guard DECORATOR
   @guard(pii=True, pii_strategy="redact")
   def my_tool(text: str): ...

5. CUSTOM PATTERNS
   PIIInspector(custom_patterns={"api_key": r"sk-..."})

6. BUILT-IN PII TYPES
   - email, phone, ssn, credit_card
   - ip_address, date_of_birth

7. CREDIT CARD VALIDATION
   - Uses Luhn algorithm
   - Rejects invalid card numbers
""")
