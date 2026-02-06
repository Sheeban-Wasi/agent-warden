# Agent-Warden Roadmap

This document outlines the feature roadmap for Agent-Warden, ensuring feature parity with LangChain middleware while adding unique security differentiators for AWS Strands.

---

## Current Status (v0.1.0)

### Completed Features

| Feature | Description | Status |
|---------|-------------|--------|
| **SQL Inspector** | AST-based SQL injection protection using sqlglot | ✅ Done |
| **@guard Decorator** | Simple decorator for protecting Strands tools | ✅ Done |
| **Policy Engine** | YAML-based configuration for multi-agent rules | ✅ Done |
| **Audit Logger** | Structured JSON logging for compliance | ✅ Done |
| **Multi-Agent Support** | Different permissions per agent | ✅ Done |
| **Blocked/Allowed Tables** | Table-level access control | ✅ Done |

---

## Phase 1: Feature Parity with LangChain

These features exist in LangChain middleware but not in AWS Strands. We should build them first.

### 1.1 PII Detection Guard

**LangChain has:** PIIDetection middleware with block/redact/mask/hash strategies.

**What to build:**
```python
@guard(
    pii=True,
    pii_strategy="redact",  # block, redact, mask, hash
    pii_detect=["email", "credit_card", "ssn", "phone", "ip_address"],
    pii_apply_to="input,output,tool_results",
)
def my_tool(query: str) -> str: ...
```

**Implementation approach:**
- Built-in regex detectors for common PII types
- Support custom regex patterns
- Strategies: block (raise error), redact (replace with [REDACTED]), mask (show last 4), hash (deterministic)
- Apply to input, output, or both

**Priority:** 🔥 High
**Effort:** Medium (2-3 days)

---

### 1.2 Human-in-the-Loop Approval

**LangChain has:** HumanInTheLoop middleware for pausing execution.

**What to build:**
```python
@guard(
    require_approval=True,
    approval_for=["DELETE", "UPDATE", "INSERT"],  # SQL operations
    approval_callback=my_approval_function,
)
def execute_sql(sql: str) -> str: ...
```

**Implementation approach:**
- Pause before executing sensitive operations
- Call approval callback function
- Support async approval (webhook, queue)
- Timeout handling

**Priority:** ⚡ Medium
**Effort:** Medium (2-3 days)

---

### 1.3 Tool Call Limits (Rate Limiting)

**LangChain has:** ToolCallLimit with thread_limit and run_limit.

**What to build:**
```python
@guard(
    rate_limit=True,
    max_calls_per_minute=100,
    max_calls_per_conversation=1000,
    on_limit="error",  # error, block, warn
)
def my_tool(query: str) -> str: ...
```

**Implementation approach:**
- Track call counts per tool, per conversation
- Enforce limits from policy.yaml
- Support sliding window rate limiting
- Return clear error messages

**Priority:** ⚡ Medium
**Effort:** Low (1 day)

---

### 1.4 Tool Retry with Backoff

**LangChain has:** ToolRetry with exponential backoff.

**What to build:**
```python
@guard(
    retry=True,
    max_retries=3,
    backoff_factor=2.0,
    initial_delay=1.0,
    retry_on=[ConnectionError, TimeoutError],
)
def my_tool(query: str) -> str: ...
```

**Implementation approach:**
- Wrap tool execution with retry logic
- Exponential backoff with jitter
- Configurable retry conditions
- Max delay cap

**Priority:** 🔵 Low
**Effort:** Low (1 day)

---

### 1.5 File Search Guard

**LangChain has:** FileSearch with glob and grep.

**What to build:**
```python
@guard(
    file_access=True,
    allowed_paths=["/data/public", "/app/docs"],
    blocked_paths=["/etc", "/root", "/data/secrets"],
    blocked_patterns=["*.env", "*.key", "*.pem", "*.credentials"],
    max_file_size=10_000_000,
)
def search_files(pattern: str) -> list: ...
```

**Implementation approach:**
- Path-based access control
- Pattern blocking (glob patterns)
- File size limits
- Symlink traversal protection

**Priority:** 🔥 High
**Effort:** Medium (2 days)

---

### 1.6 Shell Command Guard

**LangChain has:** ShellTool with execution policies (Docker, sandbox).

**What to build:**
```python
@guard(
    shell=True,
    shell_mode="restricted",  # restricted, sandbox, docker
    allowed_commands=["ls", "cat", "grep", "python"],
    blocked_commands=["rm", "sudo", "curl", "wget", "chmod"],
    blocked_patterns=["rm -rf", "> /dev", "| bash"],
)
def run_command(cmd: str) -> str: ...
```

**Implementation approach:**
- Command parsing and validation
- Whitelist/blacklist approach
- Pattern detection for dangerous sequences
- Optional Docker isolation

**Priority:** 🔥 High
**Effort:** Medium (2-3 days)

---

### 1.7 Content Moderation

**LangChain has:** OpenAI content moderation integration.

**What to build:**
```python
@guard(
    content_moderation=True,
    provider="openai",  # or "aws_comprehend", "perspective"
    block_categories=["hate", "violence", "self-harm"],
    threshold=0.7,
)
def chat(message: str) -> str: ...
```

**Implementation approach:**
- Integrate with moderation APIs
- Support multiple providers
- Configurable thresholds
- Block or flag content

**Priority:** 🔵 Low
**Effort:** Medium (2 days)

---

## Phase 2: Differentiators (Unique to Agent-Warden)

These features don't exist in LangChain and will make Agent-Warden unique.

### 2.1 RAG/Vector Database Guard

**Problem:** No access control for document retrieval in RAG systems.

**What to build:**
```python
@guard(
    rag=True,
    allowed_collections=["public_docs", "product_info"],
    blocked_collections=["hr_confidential", "legal", "financial"],
    document_acl=user_permissions_function,  # Dynamic per-user
    chunk_filtering=True,  # Filter sensitive chunks
)
def search_knowledge_base(query: str) -> list: ...
```

**Implementation approach:**
- Collection-level access control
- Document-level ACLs (per user/role)
- Chunk-level security (filter sensitive sections)
- Metadata-based filtering
- Support Pinecone, Weaviate, Chroma, etc.

**Priority:** 🔥 High (Blue Ocean)
**Effort:** High (1 week)

---

### 2.2 API Call Guard

**Problem:** Agents can call external APIs with sensitive data.

**What to build:**
```python
@guard(
    api=True,
    allowed_domains=["api.company.com", "*.internal.com"],
    blocked_domains=["*.pastebin.com", "webhook.site"],
    redact_headers=["Authorization", "X-API-Key"],
    log_requests=True,
)
def call_api(url: str, data: dict) -> dict: ...
```

**Implementation approach:**
- Domain whitelist/blacklist
- Header redaction in logs
- Request/response inspection
- Data exfiltration prevention

**Priority:** ⚡ Medium
**Effort:** Medium (2-3 days)

---

### 2.3 Data Exfiltration Prevention

**Problem:** Agents can leak data through various channels.

**What to build:**
```python
@guard(
    exfiltration=True,
    max_output_size=10000,  # Characters
    block_base64=True,
    block_encoded_data=True,
    sensitive_patterns=["password", "secret", "api_key"],
)
def my_tool(query: str) -> str: ...
```

**Implementation approach:**
- Output size limits
- Encoded data detection (base64, hex)
- Sensitive pattern blocking in output
- Anomaly detection (sudden large outputs)

**Priority:** ⚡ Medium
**Effort:** Medium (2 days)

---

### 2.4 Semantic Query Guard

**Problem:** AST parsing doesn't catch semantic attacks.

**What to build:**
```python
@guard(
    semantic=True,
    model="gpt-4o-mini",  # Use LLM to analyze intent
    block_if="query attempts to access data outside user's scope",
)
def query(sql: str) -> str: ...
```

**Implementation approach:**
- Use LLM to analyze query intent
- Compare against policy rules
- Catch attacks AST parsing misses
- Fallback to AST for performance

**Priority:** 🔵 Low (experimental)
**Effort:** High (1 week)

---

## Phase 3: Enterprise Features

### 3.1 Centralized Policy Management

- Policy server with REST API
- Hot-reload policies across all agents
- Policy versioning and rollback
- A/B testing for policy changes

### 3.2 Real-time Monitoring Dashboard

- Live view of all guard decisions
- Alert on anomalies
- Query patterns visualization
- Agent behavior analytics

### 3.3 Compliance Reporting

- SOC2 audit reports
- HIPAA compliance reports
- GDPR data access logs
- Custom compliance templates

---

## Feature Comparison Matrix

| Feature | LangChain | Agent-Warden | Status |
|---------|-----------|--------------|--------|
| SQL Injection Protection | ❌ | ✅ | **Done** |
| AST-based Query Parsing | ❌ | ✅ | **Done** |
| Table Access Control | ❌ | ✅ | **Done** |
| Multi-Agent Policies | ❌ | ✅ | **Done** |
| YAML Configuration | ❌ | ✅ | **Done** |
| Audit Logging | ⚡ Basic | ✅ Full | **Done** |
| PII Detection | ✅ | ❌ | Phase 1 |
| Human-in-the-Loop | ✅ | ❌ | Phase 1 |
| Rate Limiting | ✅ | ⚡ Policy only | Phase 1 |
| Tool Retry | ✅ | ❌ | Phase 1 |
| File Access Control | ⚡ Basic | ❌ | Phase 1 |
| Shell Sandboxing | ✅ | ❌ | Phase 1 |
| Content Moderation | ✅ | ❌ | Phase 1 |
| RAG Access Control | ❌ | ❌ | Phase 2 |
| API Call Guard | ❌ | ❌ | Phase 2 |
| Exfiltration Prevention | ❌ | ❌ | Phase 2 |
| Semantic Analysis | ❌ | ❌ | Phase 2 |

---

## Implementation Priority

### Immediate (Next Sprint)
1. **PII Guard** - Compliance requirement
2. **File Guard** - Data security
3. **Shell Guard** - System security

### Short-term (1-2 months)
4. **Rate Limit Enforcement** - Use existing policy
5. **Human Approval** - Enterprise requirement
6. **RAG Guard** - Differentiator

### Medium-term (3-6 months)
7. **API Call Guard**
8. **Content Moderation**
9. **Tool Retry**
10. **Exfiltration Prevention**

---

## Architecture Notes

All guards should follow the same pattern:

```python
from warden import guard

@guard(
    # SQL (existing)
    sql=True,
    mode="read-only",
    blocked_tables=["secrets"],

    # PII (new)
    pii=True,
    pii_strategy="redact",

    # File (new)
    file_access=True,
    allowed_paths=["/data"],

    # Shell (new)
    shell=True,
    shell_mode="restricted",

    # RAG (new)
    rag=True,
    allowed_collections=["public"],

    # Common
    on_block="return_error",
    audit=True,
)
def my_tool(input: str) -> str:
    ...
```

Each guard type:
1. Has its own inspector class
2. Returns a Verdict
3. Integrates with audit logging
4. Configurable via policy.yaml
5. Works with @guard decorator

---

## Next Steps

1. [ ] Build PII Guard (pii.py)
2. [ ] Build File Guard (file.py)
3. [ ] Build Shell Guard (shell.py)
4. [ ] Enforce rate limits in guard
5. [ ] Add human approval flow
6. [ ] Design RAG Guard architecture
