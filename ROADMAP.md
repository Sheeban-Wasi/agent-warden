# Agent-Warden Roadmap

**The Security Layer for AI Agents. One Policy. Any Framework.**

Agent-Warden provides security middleware for AI agents regardless of orchestration platform - AWS Strands, LangChain, LangGraph, CrewAI, AutoGen, or custom implementations.

---

## Vision: Platform-Agnostic Security

```
┌─────────────────────────────────────────────────────────────────────┐
│                        YOUR AI AGENTS                               │
├────────────┬────────────┬────────────┬────────────┬────────────────┤
│ AWS Strands│ LangChain  │  CrewAI    │  AutoGen   │ Custom/Other   │
├────────────┴────────────┴────────────┴────────────┴────────────────┤
│                       AGENT-WARDEN                                  │
│              (One Security Policy, Any Platform)                    │
├─────────────────────────────────────────────────────────────────────┤
│ SQL Guard │ PII Guard │ File Guard │ Shell Guard │ RAG Guard │ API │
└─────────────────────────────────────────────────────────────────────┘
```

### Architecture

```
warden/
├── core/                      # Platform-agnostic (THE MOAT)
│   ├── inspectors/
│   │   ├── sql.py            # SQL injection protection
│   │   ├── pii.py            # PII detection & handling
│   │   ├── file.py           # File access control (planned)
│   │   ├── shell.py          # Command sandboxing (planned)
│   │   └── rag.py            # RAG/Vector security (planned)
│   ├── verdict.py            # Universal result type
│   ├── policy.py             # YAML policy engine
│   └── audit.py              # Compliance logging
│
└── integrations/              # Thin adapters (~100 lines each)
    ├── strands.py            # AWS Strands @guard decorator
    ├── langchain.py          # LangChain middleware (planned)
    ├── langgraph.py          # LangGraph integration (planned)
    ├── crewai.py             # CrewAI integration (planned)
    └── generic.py            # Any Python function (planned)
```

**Key Principle:** Core inspectors have ZERO orchestrator dependencies. Each integration is a thin wrapper that adapts the core to the platform's patterns.

---

## Current Status (v0.1.0)

### Completed Features

| Feature | Description | Status |
|---------|-------------|--------|
| **SQL Inspector** | AST-based SQL injection protection using sqlglot | ✅ Done |
| **PII Inspector** | Regex-based PII detection with 5 strategies | ✅ Done |
| **File Inspector** | Path traversal, sensitive files, cloud metadata protection | ✅ Done |
| **Shell Inspector** | Command injection, dangerous commands, reverse shells | ✅ Done |
| **@guard Decorator** | Simple decorator for protecting Strands tools | ✅ Done |
| **Policy Engine** | YAML-based configuration for multi-agent rules | ✅ Done |
| **Audit Logger** | Structured JSON logging for compliance | ✅ Done |
| **Multi-Agent Support** | Different permissions per agent | ✅ Done |
| **Blocked/Allowed Tables** | Table-level access control | ✅ Done |
| **Luhn Validation** | Credit card validation in PII inspector | ✅ Done |
| **Confidence Scoring** | PII match confidence for reducing false positives | ✅ Done |

---

## Phase 1: Feature Parity with LangChain

These features exist in LangChain middleware. We build them to ensure teams switching from LangChain have everything they need.

### 1.1 PII Detection Guard ✅ DONE

**Status:** Implemented in `warden/core/inspectors/pii.py`

```python
@guard(
    pii=True,
    pii_strategy="redact",  # block, redact, mask, hash, monitor
    pii_detect=["email", "credit_card", "ssn", "phone", "ip_address"],
    pii_apply_to="input",   # input, output, both
)
def my_tool(query: str) -> str: ...
```

**Features:**
- ✅ Built-in regex detectors for 6 PII types
- ✅ Custom regex pattern support
- ✅ 5 strategies: block, redact, mask, hash, monitor
- ✅ Luhn algorithm for credit card validation
- ✅ Confidence scoring to reduce false positives
- ✅ Input/output filtering
- ✅ Deterministic hashing with optional salt

---

### 1.2 Human-in-the-Loop Approval

**LangChain has:** HumanInTheLoop middleware for pausing execution.

**What to build:**
```python
@guard(
    require_approval=True,
    approval_for=["DELETE", "UPDATE", "INSERT"],  # SQL operations
    approval_callback=my_approval_function,
    approval_timeout=300,  # 5 minutes
)
def execute_sql(sql: str) -> str: ...
```

**Implementation approach:**
- Pause before executing sensitive operations
- Call approval callback function (sync or async)
- Support webhook-based approval for async workflows
- Timeout handling with configurable default action

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

**Priority:** 🔥 High
**Effort:** Medium (2 days)

---

### 1.6 Shell Command Guard ✅ DONE

**Status:** Implemented in `warden/core/inspectors/shell.py`

```python
@guard(
    shell=True,
    shell_mode="restricted",  # restricted, allowlist, blocklist, monitor
    shell_allowed_commands={"ls", "cat", "grep", "head", "tail"},
    shell_blocked_commands={"rm", "sudo", "curl", "wget", "chmod"},
    shell_blocked_patterns=["rm -rf", "| bash"],
)
def run_command(cmd: str) -> str: ...
```

**Features:**
- ✅ Dangerous command blocking (rm, sudo, chmod, kill, etc.)
- ✅ Command chaining detection (;, |, &&, ||, &)
- ✅ Redirect injection detection (>, >>, <)
- ✅ Command substitution detection ($(), backticks)
- ✅ Reverse shell pattern detection (/dev/tcp, nc -e)
- ✅ Privilege escalation detection (chmod 777, chown root)
- ✅ Obfuscation detection ($IFS, base64, hex encoding)
- ✅ Network exfiltration detection (curl -d @, wget --post-file)
- ✅ Custom blocked patterns
- ✅ 4 modes: restricted, allowlist, blocklist, monitor

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

**Priority:** 🔵 Low
**Effort:** Medium (2 days)

---

### 1.8 LangChain Integration Adapter

**What to build:** Native LangChain middleware that wraps our core inspectors.

```python
from langchain.agents import create_agent
from warden.integrations.langchain import WardenMiddleware

agent = create_agent(
    model="gpt-4.1",
    tools=[my_tools],
    middleware=[
        WardenMiddleware.from_policy("policy.yaml"),
    ],
)
```

**Priority:** 🔥 High (Market Capture)
**Effort:** Medium (2-3 days)

---

## Phase 2: Differentiators (Blue Ocean)

These features don't exist in LangChain and will make Agent-Warden unique.

### 2.1 RAG/Vector Database Guard 🎯 KEY DIFFERENTIATOR

**Problem:** No access control for document retrieval in RAG systems. Agents can access any document in the vector store, leaking confidential data.

**What to build:**
```python
@guard(
    rag=True,
    allowed_collections=["public_docs", "product_info"],
    blocked_collections=["hr_confidential", "legal", "financial"],
    document_acl=user_permissions_function,  # Dynamic per-user
    chunk_filtering=True,  # Filter sensitive chunks from results
    metadata_filters={"department": "engineering"},
)
def search_knowledge_base(query: str) -> list: ...
```

**Implementation approach:**
- **Collection-level access control** - Which vector collections can agent access
- **Document-level ACLs** - Per-user/role document permissions
- **Chunk-level security** - Filter sensitive sections from retrieved chunks
- **Metadata-based filtering** - Only return documents matching criteria
- **Provider adapters** - Support Pinecone, Weaviate, Chroma, Qdrant, pgvector

**Use cases:**
- Multi-tenant SaaS where each customer's docs are isolated
- Enterprise with department-level document access
- Healthcare with patient record isolation (HIPAA)
- Legal with matter-based document segregation

**Priority:** 🔥 High (Blue Ocean - No competitor has this)
**Effort:** High (1 week)

---

### 2.2 API Call Guard

**Problem:** Agents can call external APIs with sensitive data, enabling data exfiltration.

**What to build:**
```python
@guard(
    api=True,
    allowed_domains=["api.company.com", "*.internal.com"],
    blocked_domains=["*.pastebin.com", "webhook.site", "ngrok.io"],
    redact_headers=["Authorization", "X-API-Key"],
    log_requests=True,
    max_request_size=1_000_000,
)
def call_api(url: str, data: dict) -> dict: ...
```

**Priority:** ⚡ Medium
**Effort:** Medium (2-3 days)

---

### 2.3 Data Exfiltration Prevention

**Problem:** Agents can leak data through encoded outputs, large responses, or hidden channels.

**What to build:**
```python
@guard(
    exfiltration=True,
    max_output_size=10000,  # Characters
    block_base64=True,
    block_encoded_data=True,
    sensitive_patterns=["password", "secret", "api_key", "BEGIN RSA"],
)
def my_tool(query: str) -> str: ...
```

**Priority:** ⚡ Medium
**Effort:** Medium (2 days)

---

### 2.4 Semantic Query Guard (Experimental)

**Problem:** AST parsing doesn't catch semantic attacks where queries are technically valid but violate business logic.

**What to build:**
```python
@guard(
    semantic=True,
    model="gpt-4o-mini",  # Use LLM to analyze intent
    block_if="query attempts to access data outside user's scope",
    cache_ttl=3600,  # Cache semantic analysis
)
def query(sql: str) -> str: ...
```

**Priority:** 🔵 Low (experimental)
**Effort:** High (1 week)

---

## Phase 3: Platform Integrations

Build thin adapters for each major AI agent framework.

### 3.1 AWS Strands ✅ DONE

```python
from warden.integrations.strands import guard

@tool
@guard(sql=True, pii=True)
def my_tool(query: str) -> str: ...
```

### 3.2 LangChain / LangGraph

```python
from warden.integrations.langchain import WardenMiddleware

agent = create_agent(
    model="gpt-4.1",
    middleware=[WardenMiddleware.from_policy("policy.yaml")],
)
```

### 3.3 CrewAI

```python
from warden.integrations.crewai import warden_tool

@warden_tool(sql=True, pii=True)
def research_tool(query: str) -> str: ...
```

### 3.4 Microsoft AutoGen

```python
from warden.integrations.autogen import WardenAgent

agent = WardenAgent(
    policy="policy.yaml",
    base_agent=my_autogen_agent,
)
```

### 3.5 Generic Python

```python
from warden import protect

@protect(sql=True, pii=True)
def any_function(input: str) -> str: ...
```

---

## Phase 4: Enterprise Features

### 4.1 Centralized Policy Management

- Policy server with REST API
- Hot-reload policies across all agents
- Policy versioning and rollback
- A/B testing for policy changes

### 4.2 Real-time Monitoring Dashboard

- Live view of all guard decisions
- Alert on anomalies
- Query patterns visualization
- Agent behavior analytics

### 4.3 Compliance Reporting

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
| PII Detection | ✅ | ✅ | **Done** |
| Credit Card Validation (Luhn) | ❌ | ✅ | **Done** |
| Confidence Scoring | ❌ | ✅ | **Done** |
| Human-in-the-Loop | ✅ | ❌ | Phase 1 |
| Rate Limiting | ✅ | ⚡ Policy only | Phase 1 |
| Tool Retry | ✅ | ❌ | Phase 1 |
| File Access Control | ⚡ Basic | ✅ | **Done** |
| Shell Command Guard | ✅ | ✅ | **Done** |
| Content Moderation | ✅ | ❌ | Phase 1 |
| **RAG Access Control** | ❌ | ❌ | **Phase 2 (Blue Ocean)** |
| API Call Guard | ❌ | ❌ | Phase 2 |
| Exfiltration Prevention | ❌ | ❌ | Phase 2 |
| Semantic Analysis | ❌ | ❌ | Phase 2 |
| **Platform-Agnostic** | ❌ (LangChain only) | ✅ | **Architecture** |

---

## Implementation Priority

### Immediate (This Week)
1. ✅ **PII Guard** - Done
2. ✅ **File Guard** - Done
3. ✅ **Shell Guard** - Done

### Short-term (1-2 weeks)
4. **LangChain Adapter** - Market capture
5. **Rate Limit Enforcement** - Use existing policy
6. **Human Approval** - Enterprise requirement

### Medium-term (1 month)
7. **RAG Guard** - Blue Ocean differentiator
8. **API Call Guard** - Exfiltration prevention
9. **CrewAI/AutoGen Adapters** - Platform coverage

### Long-term (3-6 months)
10. **Enterprise Dashboard**
11. **Policy Server**
12. **Compliance Reporting**

---

## Next Steps

1. [x] Build PII Guard (pii.py) ✅
2. [x] Build File Guard (file.py) ✅
3. [x] Build Shell Guard (shell.py) ✅
4. [ ] Build LangChain adapter
5. [ ] Enforce rate limits in guard
6. [ ] Add human approval flow
7. [ ] Design RAG Guard architecture
