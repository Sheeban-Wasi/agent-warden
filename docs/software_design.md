This is the formal **Technical Design Document (TDD)** for **Agent-Warden**.

You can copy this directly into your repository as `DESIGN.md` or a Google Doc to share with your team. It follows standard engineering practices for building high-assurance infrastructure.

---

# Technical Design Document: Agent-Warden

**Version:** 1.0 (DRAFT)
**Status:** Approved for Implementation
**License:** Apache 2.0
**Core Philosophy:** "Deny by Default."

---

## 1. Executive Summary

**Agent-Warden** is a security middleware designed to sit between an AI Agent (LLM) and its execution environment (Tools/Database). Unlike observability tools (Langfuse) which passively record events, Agent-Warden actively **intercepts, inspects, and blocks** dangerous actions before they execute.

**Primary Goal:** Enable high-compliance enterprises (Finance, Healthcare) to deploy Agentic AI by guaranteeing that agents cannot perform destructive actions (e.g., `DROP TABLE`) or leak sensitive data (PII).

---

## 2. High-Level Architecture

We will use a **Hub-and-Spoke Architecture**.

* **The Hub (`warden-core`):** Contains all the security logic. It is framework-agnostic. It doesn't know what "LangChain" or "AWS" is. It just takes an input (e.g., a SQL string) and returns a verdict (`Pass` / `Block`).
* **The Spokes (`adapters`):** Thin wrappers that connect specific frameworks (AWS Strands, LangChain) to the Hub.

### System Diagram

```mermaid
graph TD
    subgraph "Application Layer"
        Agent[AI Agent (AWS/LangChain)]
        Tool[Tool Execution (SQL/API)]
    end

    subgraph "Agent-Warden Middleware"
        Adapter[Adapter (Decorator/Middleware)] -->|Intercept| Core[Warden Core]
        
        Core -->|1. Check Config| Policy[Policy Engine]
        Core -->|2. Analyze| Inspectors[Inspectors]
        
        Inspectors -->|Parse| SQLGuard[SQL Inspector (AST)]
        Inspectors -->|Scan| PIIGuard[PII Inspector]
        Inspectors -->|Verify| ContextGuard[Identity/Tenancy]
        
        Core -->|3. Decision| Logger[Audit Logger]
    end

    subgraph "Infrastructure"
        DB[(Database)]
        CloudWatch[Logs/SIEM]
    end

    Logger -->|Block| Agent
    Logger -->|Allow| Tool --> DB
    Logger -.->|Async Write| CloudWatch

```

---

## 3. Component Design (The "Hub")

### 3.1 Policy Engine (`warden.core.policy`)

The brain of the system. It loads rules from a YAML file or environment variables. It decouples *code* from *configuration*.

**Data Structure (The Manifest):**

```yaml
# policy.yaml
global:
  mode: "strict" # strict = block on error, monitor = log only
  
tools:
  execute_sql:
    inspector: "sql_ast"
    rules:
      allow_writes: false
      block_schema_changes: true
      required_scope: ["user_id"] # Must find 'WHERE user_id = X'

```

### 3.2 The Inspectors (`warden.core.inspectors`)

Each inspector is a specialized class focused on one type of threat.

#### A. SQL Inspector (The Moat)

**Library:** `sqlglot`
**Why:** Regex is easily bypassed. We need to parse the Abstract Syntax Tree (AST).
**Logic:**

1. Parse query into AST.
2. Traverse nodes.
3. If Node Type is `DROP`, `TRUNCATE`, `ALTER`, `GRANT` → **Raise CriticalViolation**.
4. If Node Type is `UPDATE`, `INSERT`, `DELETE` AND `allow_writes=False` → **Raise PolicyViolation**.

#### B. PII Inspector

**Library:** `presidio-analyzer` (Microsoft)
**Logic:**

1. Scan text for entities (`PHONE_NUMBER`, `CREDIT_CARD`, `SSN`).
2. If found, replace with token `<REDACTED_PII>`.
3. Return "Cleaned" text to the agent.

#### C. Context/Identity Inspector

**Logic:**

1. Accept a `context` dictionary (e.g., `{'user_id': 105}`).
2. Check if the tool arguments honor this context.
3. *Example:* If user is 105, but SQL is `SELECT * FROM invoices WHERE user_id = 106` → **Block**.

### 3.3 The Audit Logger (`warden.core.logger`)

This is the "Compliance Product."
**Requirements:**

* Must never throw an exception (logging failure shouldn't crash the app).
* Must output structured JSON.
* **Schema:**
```json
{
  "timestamp": "2026-02-05T12:00:00Z",
  "event_id": "uuid-v4",
  "agent_id": "finance-bot-01",
  "tool": "execute_sql",
  "input_payload": "DROP TABLE users",
  "verdict": "BLOCKED",
  "policy_rule": "block_schema_changes",
  "latency_ms": 4
}

```



---

## 4. Integration Design (The "Spokes")

### 4.1 AWS Strands Adapter (`warden.integrations.strands`)

**Mechanism:** Python Decorators (`@functools.wraps`).
**Design:**

* Create a function `guard()` that takes a policy name.
* It wraps the user's tool function.
* It extracts `args` and `kwargs` and passes them to `warden-core`.
* If Core returns `False`, the decorator returns a string error: *"Action blocked by security policy."* This allows the Agent to see the error and try again (Self-Correction).

### 4.2 LangChain Adapter (`warden.integrations.langchain`)

**Mechanism:** Class Inheritance (`AgentMiddleware`).
**Design:**

* Implement `on_tool_start`.
* Intercept the tool call.
* If blocked, raise a specific `ToolException` that LangChain knows how to handle (feeding the error back to the LLM).

---

## 5. Development Roadmap (Incremental Build)

We will build this in **4 Sprints** to ensure security and stability.

### Phase 1: The Core SQL Engine (Week 1)

**Goal:** Build the robust SQL parser. No AWS/LangChain code yet.

* [ ] Set up repo structure (`poetry new agent-warden`).
* [ ] Implement `SQLInspector` using `sqlglot`.
* [ ] Write Unit Tests: Create a file `tests/test_sql_injection.py` with 50+ attack vectors (obfuscated SQL, comment attacks, etc.) and ensure the parser blocks them all.
* **Deliverable:** A python package where `check_sql("DROP TABLE")` returns `False`.

### Phase 2: The AWS Strands Decorator (Week 2)

**Goal:** Integrate into NQuireHub.

* [ ] Build the `@guard` decorator.
* [ ] Connect it to the SQL Inspector from Phase 1.
* [ ] Add the `AuditLogger` (print to console for now).
* [ ] **Validation:** Deploy to a dev branch of NQuireHub. Try to make the agent delete data.

### Phase 3: The PII Layer (Week 3)

**Goal:** Handle text/prompt safety.

* [ ] Integrate `Microsoft Presidio`.
* [ ] Build the `PromptSanitizer` class.
* [ ] Update the Strands decorator to run PII checks on the *output* of tools (to prevent data leaks).

### Phase 4: Production Hardening (Week 4)

**Goal:** Enterprise features.

* [ ] Switch Logger to support JSON/CloudWatch.
* [ ] Load Policy from `warden.yaml` instead of code.
* [ ] Release v1.0 to PyPI.

---

## 6. Security Self-Assessment (Risk Analysis)

| Risk | Mitigation |
| --- | --- |
| **Bypass:** Agent prompts the tool to ignore instructions. | Warden ignores prompts. It looks at the *actual code* (AST) being executed. |
| **Latency:** Security checks slow down the agent. | `sqlglot` and regex are sub-millisecond. We avoid external API calls (everything runs locally). |
| **False Positives:** Valid queries get blocked. | Start in `monitor` mode (log only) to tune the policy before switching to `strict` (blocking). |
| **Dependency Risk:** `sqlglot` has a bug. | We pin dependency versions strictly in `pyproject.toml`. We run our own regression test suite. |

---

### Next Step

This document is your blueprint. Would you like me to generate the **File Structure** (folders and files) so you can initialize the repo right now?