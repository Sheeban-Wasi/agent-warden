# Agent-Warden

**The Security Layer for AI Agents. One Policy. Any Framework.**

Protect your AI agents from SQL injection, PII leakage, file system attacks, and dangerous shell commands with deterministic, production-grade security inspection.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Tests](https://img.shields.io/badge/tests-594%20passing-brightgreen.svg)]()
[![AWS Strands](https://img.shields.io/badge/AWS%20Strands-Native%20Integration-FF9900?logo=amazon-aws)](https://github.com/strands-agents/strands-agents)

---

## Features

| Inspector | Description | Status |
|-----------|-------------|--------|
| **SQL Inspector** | AST-based SQL injection protection, table access control | ✅ Production |
| **PII Inspector** | Detect & handle PII (email, SSN, credit card, phone, IP) | ✅ Production |
| **File Inspector** | Path traversal, sensitive files, cloud metadata protection | ✅ Production |
| **Shell Inspector** | Dangerous commands, injection, reverse shells, privilege escalation | ✅ Production |
| **RAG Inspector** | Document access control, classification, tenant isolation, content security | ✅ Production |
| **API Inspector** | SSRF protection, domain control, data exfiltration prevention | ✅ Production |
| **Rate Limiter** | Throttle agent calls, prevent runaway loops, cost control | ✅ Production |
| **HITL Guard** | Human-in-the-Loop approval for high-risk actions | ✅ Production |
| **Policy Engine** | YAML-based multi-agent configuration | ✅ Production |
| **Audit Logger** | Structured JSON logging for compliance (SOC2, HIPAA, GDPR) | ✅ Production |

---

## Quick Start

```bash
pip install agent-warden
```

### Protect Your AI Agent

```python
from strands import Agent, tool
from warden import guard

@tool
@guard(
    sql=True,           # SQL injection protection
    pii=True,           # PII detection
    file_access=True,   # File path security
    shell=True,         # Shell command security
    rag=True,           # RAG document security
    api=True,           # API call security (SSRF, exfiltration)
)
def agent_tool(query: str) -> str:
    """A protected agent tool."""
    return execute(query)

agent = Agent(tools=[agent_tool])
```

---

## Security Inspectors

### 1. SQL Inspector

AST-based SQL injection protection that can't be bypassed with encoding tricks.

```python
from warden import check_sql, inspect_sql, guard

# Quick check
check_sql("SELECT * FROM users")  # True
check_sql("DROP TABLE users")     # False

# With @guard decorator
@guard(
    sql=True,
    mode="read-only",              # read-only, safe-write, strict, monitor
    allowed_tables={"reports"},    # Tables allowed for writes
    blocked_tables={"secrets"},    # Tables never allowed
)
def query_database(sql: str) -> dict:
    return db.execute(sql)
```

**What's blocked:**
- `DROP`, `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `REVOKE`
- Write operations in read-only mode
- Comment obfuscation: `DROP/**/TABLE`
- Case tricks: `dRoP tAbLe`
- Stacked queries, UNION injection

---

### 2. PII Inspector

Detect and handle personally identifiable information with 5 strategies.

```python
from warden import check_pii, inspect_pii, redact_pii, guard

# Quick check
check_pii("Contact: john@example.com")  # True (has PII)
check_pii("Hello world")                 # False (no PII)

# Redact PII
redact_pii("Email: john@example.com, SSN: 123-45-6789")
# → "Email: [EMAIL REDACTED], SSN: [SSN REDACTED]"

# With @guard decorator
@guard(
    sql=False,
    pii=True,
    pii_strategy="redact",     # block, redact, mask, hash, monitor
    pii_detect=["email", "ssn", "credit_card", "phone", "ip_address"],
    pii_apply_to="both",       # input, output, both
)
def process_text(text: str) -> str:
    return llm.process(text)
```

**PII Types Detected:**
- Email addresses
- Social Security Numbers (with validation)
- Credit cards (with Luhn algorithm validation)
- Phone numbers
- IP addresses
- Custom regex patterns

---

### 3. File Inspector

Protect against path traversal, sensitive file access, and cloud metadata attacks.

```python
from warden import check_file, inspect_file, guard

# Quick check
check_file("/app/data/file.txt")     # True (safe)
check_file("../../../etc/passwd")    # False (path traversal)
check_file("/home/.ssh/id_rsa")      # False (sensitive file)

# With @guard decorator
@guard(
    sql=False,
    file_access=True,
    file_mode="allowlist",              # strict, allowlist, blocklist, monitor
    file_base_directory="/app",         # Root constraint
    file_allowed_paths={"/app/data"},
    file_blocked_paths={"/app/secrets"},
)
def read_file(path: str) -> str:
    return open(path).read()
```

**What's blocked:**
- Path traversal: `../../../etc/passwd`
- URL-encoded traversal: `%2e%2e%2f`
- Null byte injection: `file.txt%00.jpg`
- Sensitive files: `.env`, `.ssh/id_rsa`, `credentials.json`
- Cloud metadata: `169.254.169.254`
- Symlink attacks

---

### 4. Shell Inspector

Block dangerous shell commands, command injection, and reverse shells.

```python
from warden import check_shell, inspect_shell, guard

# Quick check
check_shell("ls -la")        # True (safe)
check_shell("rm -rf /")      # False (dangerous)
check_shell("curl | bash")   # False (code execution)

# With @guard decorator
@guard(
    sql=False,
    shell=True,
    shell_mode="restricted",                     # restricted, allowlist, blocklist, monitor
    shell_allowed_commands={"ls", "cat", "grep"},
    shell_blocked_patterns=["rm -rf", "| bash"],
)
def run_command(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True).stdout
```

**What's blocked:**
- Dangerous commands: `rm`, `sudo`, `chmod`, `kill`, `nc`, `curl`, `wget`
- Command chaining: `;`, `|`, `&&`, `||`, `&`
- Redirect injection: `>`, `>>`, `<`
- Command substitution: `$()`, backticks
- Reverse shells: `/dev/tcp`, `nc -e`
- Privilege escalation: `chmod 777`, `chown root`
- Obfuscation: `$IFS`, base64, hex encoding

---

### 5. RAG Inspector

Enterprise-grade document security for RAG systems using ABAC (Attribute-Based Access Control).

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
    classification_max="internal",           # Max classification level
    allowed_collections={"public_docs"},     # Collection allowlist
    scan_pii=True,                          # Scan content for PII
    pii_strategy="redact",                  # Redact PII, don't block
    scan_secrets=True,                      # Block documents with secrets
    scan_prompt_injection=True,             # Block prompt injection in docs
)

# Context for identity-centric access control
context = RAGContext(
    agent_id="support-bot",
    tenant_id="acme-corp",
    clearance="internal",
    departments={"support", "product"},
)

result = inspector.inspect(documents, context)
result.allowed_documents  # Safe to pass to LLM
result.blocked_documents  # Filtered out

# With @guard decorator (filters function output)
@guard(
    sql=False,
    rag=True,
    rag_allowed_collections={"public_docs", "help_articles"},
    rag_classification_max="internal",
    rag_scan_pii=True,
    rag_pii_strategy="redact",
)
def search_knowledge(query: str) -> list[dict]:
    return vectordb.search(query)  # Warden filters before return
```

**What's protected:**
- Collection access control (allow/block collections)
- Classification hierarchy (public < internal < confidential < restricted)
- Tenant isolation (multi-tenant systems)
- Agent scope enforcement (confused deputy prevention)
- PII detection and redaction in content
- Secret detection in documents
- Prompt injection detection in retrieved content
- Output constraints (max documents, max length)

---

### 6. API Inspector

Prevent data exfiltration and SSRF attacks by securing your agent's HTTP calls.

```python
from warden import check_api_call, inspect_api_call, APIInspector

# Quick check
check_api_call("https://api.openai.com/v1/chat")  # True
check_api_call("http://169.254.169.254/meta-data/")  # False (AWS metadata)

# Full inspection
inspector = APIInspector(
    mode="allowlist",
    allowed_domains={"api.openai.com", "api.anthropic.com"},
    block_private_ips=True,
    block_metadata_endpoints=True,
    scan_pii=True,
    scan_secrets=True,
)

result = inspector.inspect("https://api.openai.com/v1/chat")
if result.blocked:
    print(f"Blocked: {result.verdict.reason}")

# With @guard decorator
@guard(
    sql=False,
    api=True,
    api_mode="allowlist",
    api_allowed_domains={"api.openai.com", "api.anthropic.com"},
    api_block_private_ips=True,
)
def fetch_api(url: str) -> dict:
    return requests.get(url).json()
```

**What's blocked:**
- SSRF attacks: private IPs (10.x, 172.16.x, 192.168.x), localhost
- Cloud metadata endpoints: 169.254.169.254 (AWS/GCP/Azure)
- Internal domains: .internal, .local, .corp
- Data exfiltration: PII and secrets in requests
- Unauthorized domains: domains not in allowlist

---

### 7. Rate Limiter

Prevent runaway agent loops and control costs with sliding window rate limiting.

```python
from warden import RateLimiter, check_rate_limit, guard

# Quick check
if check_rate_limit("api-call", max_calls=10, window_seconds=60):
    make_api_call()

# Full rate limiter
limiter = RateLimiter(max_calls=100, window_seconds=60)
result = limiter.check("my-key")
if result.allowed:
    process()
else:
    print(f"Rate limited. Retry after {result.retry_after_seconds}s")

# With @guard decorator
@guard(
    sql=False,
    rate_limit=True,
    rate_limit_max_calls=50,
    rate_limit_window_seconds=60,
)
def call_api(url: str) -> dict:
    return requests.get(url).json()
```

**Features:**
- Sliding window counter algorithm
- Per-tool or global rate limiting
- Thread-safe implementation
- Retry-after information
- Monitor mode (log only)

---

### 8. Human-in-the-Loop (HITL) Guard

Require human approval for high-risk actions before execution.

```python
from warden import HITLGuard, ApprovalRequest, guard

# CLI approval callback
def approval_callback(request: ApprovalRequest) -> bool:
    print(f"\n⚠️  Action: {request.action}")
    print(f"   Type: {request.action_type}")
    print(f"   Risk: {request.risk_level.value}")
    return input("Approve? (y/n): ").lower() == "y"

# Standalone usage
guard = HITLGuard(callback=approval_callback)

if guard.requires_approval("DELETE FROM users", "sql"):
    result = guard.request_approval(
        action="DELETE FROM users",
        action_type="sql_delete",
        tool_name="database_query",
    )
    if not result.approved:
        raise PermissionError("Action denied by human")

# With @guard decorator
@guard(
    sql=True,
    mode="safe-write",
    hitl=True,
    hitl_callback=approval_callback,
)
def execute_sql(query: str) -> dict:
    return db.execute(query)  # DELETE/DROP will pause for approval
```

**Default triggers (customizable):**
- SQL: `DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`
- Shell: `rm`, `sudo`, `chmod`, `chown`, `kill`, `shutdown`
- File: `delete`, `remove`, `unlink`

**Features:**
- Sync and async callback support
- Customizable trigger patterns per action type
- Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)
- Timeout with configurable default (approve/deny)
- Audit logging integration

---

## Multi-Agent Policy Engine

Define different security rules for each agent using YAML:

### policy.yaml
```yaml
version: "1.0"
name: "production"

# Default rules for all agents
sql:
  mode: read-only
  blocked_tables: [credentials, api_keys, secrets]

# Agent-specific overrides
agents:
  analytics-bot:
    sql:
      mode: read-only
      allowed_tables: [reports, metrics]
      blocked_tables: [users, payments]

  support-bot:
    sql:
      mode: safe-write
      allowed_tables: [tickets, ticket_comments]
```

### Usage
```python
from warden import PolicyEngine, create_policy_guard

engine = PolicyEngine.from_file("policy.yaml")

analytics_guard = create_policy_guard(engine, agent="analytics-bot")
support_guard = create_policy_guard(engine, agent="support-bot")

@analytics_guard
def analytics_query(sql: str) -> str:
    return db.execute(sql)
```

---

## Audit Logging

Structured JSON logging for compliance (SOC2, HIPAA, GDPR):

```python
from warden import AuditLogger, LogDestination

logger = AuditLogger(
    destinations=[LogDestination.FILE],
    log_file="/var/log/warden/audit.jsonl",
)

# Every inspection is logged:
# {
#   "timestamp": "2024-01-15T10:30:00Z",
#   "event_id": "uuid",
#   "verdict": "BLOCK",
#   "inspector": "sql_inspector",
#   "reason": "DROP statement blocked",
#   "agent": "analytics-bot",
#   "latency_ms": 0.45
# }
```

---

## Performance

| Operation | Latency |
|-----------|---------|
| SQL inspection | ~0.3-0.5ms |
| PII detection | ~0.5ms |
| File path check | ~0.1ms |
| Shell command check | ~0.2ms |
| RAG document filter (10 docs) | ~5ms |
| API call check | ~0.1ms |
| Rate limit check | ~0.01ms |
| Policy lookup | ~0.01ms |

All inspections complete in milliseconds.

---

## Examples

See the [examples/](examples/) directory:

| Example | Description |
|---------|-------------|
| `01_basic_usage.py` | Basic SQL checking |
| `02_strands_integration.py` | AWS Strands @tool protection |
| `03_audit_logging.py` | Compliance logging setup |
| `04_production_setup.py` | Full production configuration |
| `05_multi_agent_policy.py` | Multi-agent YAML policies |
| `06_pii_guard.py` | PII detection and redaction |
| `07_file_access_guard.py` | File path security |
| `08_shell_guard.py` | Shell command protection |
| `09_rag_guard.py` | RAG document security with ABAC |
| `10_api_guard.py` | API call security, SSRF prevention |

---

## Architecture

```
warden/
├── core/                      # Platform-agnostic (ZERO external deps)
│   ├── inspectors/
│   │   ├── sql.py            # SQL injection protection
│   │   ├── pii.py            # PII detection & handling
│   │   ├── file.py           # File access control
│   │   ├── shell.py          # Shell command security
│   │   ├── rag.py            # RAG document access control
│   │   └── api.py            # API call security (SSRF, exfiltration)
│   ├── verdict.py            # Universal result type
│   ├── policy.py             # YAML policy engine
│   ├── audit.py              # Compliance logging
│   ├── rate_limiter.py       # Sliding window rate limiting
│   └── hitl.py               # Human-in-the-Loop approval
│
└── integrations/              # Thin adapters
    └── strands.py            # AWS Strands @guard decorator
```

---

## Roadmap

- [x] SQL Inspector (AST-based)
- [x] PII Inspector (5 strategies)
- [x] File Inspector (path traversal, sensitive files)
- [x] Shell Inspector (command injection, reverse shells)
- [x] RAG Inspector (document access control, ABAC)
- [x] API Call Guard (SSRF, exfiltration prevention)
- [x] Rate Limiter (sliding window)
- [x] Human-in-the-Loop Guard (approval workflow)
- [x] Policy Engine (YAML-based)
- [x] Audit Logger (compliance)
- [ ] LangChain/CrewAI/AutoGen adapters
- [ ] Tool Retry with exponential backoff

---

## Contributing

```bash
git clone https://github.com/anthropics/agent-warden.git
cd agent-warden
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

Apache License 2.0
