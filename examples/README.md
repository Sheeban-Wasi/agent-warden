# Agent-Warden Examples

This directory contains working examples demonstrating Agent-Warden features.

## Prerequisites

```bash
pip install agent-warden
```

## Examples

### 1. Basic Usage (`01_basic_usage.py`)

The simplest way to use Agent-Warden. Shows:
- `check_sql()` - Quick True/False check
- `inspect_sql()` - Full inspection with details
- `SQLInspector` - Different modes (read-only, safe-write)

```bash
python examples/01_basic_usage.py
```

### 2. AWS Strands Integration (`02_strands_integration.py`)

How to protect your Strands agent tools with the `@guard` decorator. Shows:
- Basic `@guard` protection
- Safe-write mode with allowed tables
- Return error instead of raising exceptions

```bash
python examples/02_strands_integration.py
```

### 3. Audit Logging (`03_audit_logging.py`)

Set up audit logging for compliance (SOC2, HIPAA, GDPR). Shows:
- Console logging
- File-based JSON Lines logging
- Block-only logging
- Integration with `@guard` decorator

```bash
python examples/03_audit_logging.py
```

### 4. Production Setup (`04_production_setup.py`)

Complete production-ready configuration. Shows:
- Environment-based configuration
- Centralized audit logger
- Blocked tables for sensitive data
- Proper error handling patterns

```bash
python examples/04_production_setup.py
```

### 5. Multi-Agent Policy (`05_multi_agent_policy.py`)

YAML-based policy engine for multi-agent systems. Shows:
- Loading policies from YAML files
- Agent-specific permissions
- Policy guards for different agents

```bash
python examples/05_multi_agent_policy.py
```

### 6. PII Guard (`06_pii_guard.py`)

PII detection and handling. Shows:
- Detecting PII (email, SSN, credit card, phone, IP)
- 5 strategies: block, redact, mask, hash, monitor
- Luhn algorithm for credit card validation
- Custom regex patterns
- @guard decorator integration

```bash
python examples/06_pii_guard.py
```

### 7. File Access Guard (`07_file_access_guard.py`)

File path security. Shows:
- Path traversal detection
- Sensitive file blocking (.env, .ssh, credentials)
- Cloud metadata protection (169.254.169.254)
- Base directory constraints
- @guard decorator integration

```bash
python examples/07_file_access_guard.py
```

### 8. Shell Guard (`08_shell_guard.py`)

Shell command security. Shows:
- Dangerous command blocking (rm, sudo, chmod)
- Command chaining detection (;, |, &&)
- Reverse shell detection (/dev/tcp, nc -e)
- Privilege escalation detection
- Obfuscation detection ($IFS, base64)
- @guard decorator integration

```bash
python examples/08_shell_guard.py
```

### 9. RAG Guard (`09_rag_guard.py`)

RAG document security with ABAC. Shows:
- Collection access control (allow/block)
- Classification hierarchy (public < internal < confidential < restricted)
- Tenant isolation for multi-tenant systems
- Agent scope enforcement (confused deputy prevention)
- PII detection and redaction in retrieved content
- Secret detection in documents
- Prompt injection detection in documents
- Output constraints (max documents, max length)
- Works with any vector database

```bash
python examples/09_rag_guard.py
```

### 10. API Guard (`10_api_guard.py`)

API call security for preventing data exfiltration and SSRF attacks. Shows:
- SSRF protection (private IPs, localhost, cloud metadata endpoints)
- Domain allowlist/blocklist with wildcard support
- PII and secret detection in requests (URL, body, headers)
- HTTP method restrictions (restrict to GET/HEAD in safe mode)
- HTTPS enforcement
- Data exfiltration prevention
- Audit trail generation

```bash
python examples/10_api_guard.py
```

---

## Quick Reference

### SQL Protection

```python
from warden import check_sql, guard

# Quick check
check_sql("SELECT * FROM users")  # True
check_sql("DROP TABLE users")     # False

# With decorator
@guard(sql=True, mode="read-only")
def query(sql: str) -> dict:
    return db.execute(sql)
```

### PII Protection

```python
from warden import check_pii, redact_pii, guard

# Quick check
check_pii("Email: john@example.com")  # True (has PII)

# Redact PII
redact_pii("SSN: 123-45-6789")  # "SSN: [SSN REDACTED]"

# With decorator
@guard(sql=False, pii=True, pii_strategy="redact")
def process(text: str) -> str:
    return llm.process(text)
```

### File Protection

```python
from warden import check_file, guard

# Quick check
check_file("/app/data/file.txt")   # True
check_file("../../../etc/passwd")  # False

# With decorator
@guard(sql=False, file_access=True, file_base_directory="/app")
def read_file(path: str) -> str:
    return open(path).read()
```

### Shell Protection

```python
from warden import check_shell, guard

# Quick check
check_shell("ls -la")     # True
check_shell("rm -rf /")   # False

# With decorator
@guard(sql=False, shell=True, shell_allowed_commands={"ls", "cat"})
def run_cmd(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
```

### RAG Protection

```python
from warden import RAGInspector, RAGContext, check_rag_documents

# Quick filter
safe_docs = check_rag_documents(
    documents,
    allowed_collections=["public_docs"],
    classification_max="internal",
)

# Full inspection with ABAC context
inspector = RAGInspector(
    classification_max="internal",
    scan_pii=True,
    pii_strategy="redact",
)
context = RAGContext(
    agent_id="support-bot",
    tenant_id="acme-corp",
)
result = inspector.inspect(documents, context)
safe_docs = result.allowed_documents  # Pass to LLM
```

### API Protection

```python
from warden import check_api_call, inspect_api_call, APIInspector

# Quick check
check_api_call("https://api.openai.com/v1/chat")  # True
check_api_call("http://169.254.169.254/meta-data/")  # False (AWS metadata)

# With domain allowlist
inspector = APIInspector(
    mode="allowlist",
    allowed_domains={"api.openai.com", "api.anthropic.com"},
    scan_pii=True,
    scan_secrets=True,
)
result = inspector.inspect("https://api.openai.com/v1/chat")
if result.blocked:
    print(f"Blocked: {result.verdict.reason}")
```

---

## More Information

See the main [README.md](../README.md) for complete documentation.
