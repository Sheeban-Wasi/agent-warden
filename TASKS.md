# Agent-Warden Task List

Last updated: 2026-02-07

## Completed Features

### Core Inspectors
- [x] **SQL Inspector** - AST-based SQL injection protection with sqlglot
- [x] **PII Inspector** - 5 strategies (block, redact, mask, hash, monitor), Luhn validation, custom detectors
- [x] **File Inspector** - Path traversal, sensitive files, cloud metadata protection
- [x] **Shell Inspector** - Dangerous commands, injection, reverse shells, privilege escalation
- [x] **RAG Inspector** - Document access control, ABAC, classification, tenant isolation
- [x] **API Inspector** - SSRF protection, domain control, data exfiltration prevention
- [x] **Identity Inspector** - RBAC/ABAC, agent/tenant allowlists, scope/role/permission enforcement
- [x] **Rate Limiter** - Sliding window counter, per-tool/global limits, @guard integration
- [x] **HITL Guard** - Human-in-the-Loop approval for high-risk actions, async callbacks
- [x] **Tool Retry** - Exponential/linear/constant/fibonacci backoff, jitter, @guard integration

### Infrastructure
- [x] **Verdict System** - Universal result type for all inspectors
- [x] **Policy Engine** - YAML-based multi-agent configuration
- [x] **Audit Logger** - Structured JSON logging for compliance (SOC2, HIPAA, GDPR)
- [x] **@guard Decorator** - AWS Strands integration with all inspectors
- [x] **Exception Hierarchy** - WardenError, PolicyViolation, CriticalViolation, etc.
- [x] **Custom PII Detectors** - Protocol-based detectors (RegexDetector, FunctionDetector)

### Testing & Documentation
- [x] 700 tests passing
- [x] 10 example files demonstrating all features
- [x] README with full documentation
- [x] CLAUDE.md with code style rules

---

## Pending Features

### High Priority

#### 1. LangChain Middleware Adapter
**Status:** Not started
**Description:** Thin adapter for LangChain integration.
**Location:** `warden/integrations/langchain.py`

---

## Architecture Overview

```
warden/
├── core/                      # Platform-agnostic (ZERO external deps except sqlglot)
│   ├── inspectors/
│   │   ├── sql.py            # SQL injection protection
│   │   ├── pii.py            # PII detection & handling + custom detectors
│   │   ├── file.py           # File access control
│   │   ├── shell.py          # Shell command security
│   │   ├── rag.py            # RAG document access control
│   │   ├── api.py            # API call security (SSRF, exfiltration)
│   │   └── identity.py       # Identity-based access control (RBAC/ABAC)
│   ├── verdict.py            # Universal result type
│   ├── policy.py             # YAML policy engine
│   ├── audit.py              # Compliance logging
│   ├── rate_limiter.py       # Sliding window rate limiting
│   ├── hitl.py               # Human-in-the-Loop approval
│   └── retry.py              # Tool retry with backoff
│
├── integrations/              # Thin adapters (~100 lines max)
│   └── strands.py            # AWS Strands @guard decorator
│
└── exceptions.py             # Error hierarchy
```

---

## Inspector Pattern

Every inspector follows this pattern:

1. **Config dataclass** - All configuration options
2. **`inspect()` method** - Returns Verdict/Result object
3. **Convenience functions** - `check_*()` for bool, `inspect_*()` for full result
4. **@guard integration** - Parameters prefixed with inspector name (e.g., `pii_strategy`)

---

## Control Points

| Inspector | Control Point | What It Checks |
|-----------|---------------|----------------|
| SQL | INPUT | Query before execution |
| PII | INPUT + OUTPUT | Text for PII patterns |
| File | INPUT | Path before file access |
| Shell | INPUT | Command before execution |
| RAG | OUTPUT | Documents before passing to LLM |
| API | INPUT | Request before HTTP call |
| Identity | INPUT | Agent/user identity and permissions |
| Rate Limit | INPUT | Call count before execution |
| HITL | INPUT | High-risk actions before execution |
| Retry | WRAPPER | Transient failures with backoff |

---

## Running Tests

```bash
# Full test suite
python -m pytest tests/ -v

# Specific inspector
python -m pytest tests/test_api_inspector.py -v

# With coverage
python -m pytest tests/ --cov=warden --cov-report=term-missing
```

---

## Recent Changes

### 2026-02-07 (Continued)
- Implemented Tool Retry with exponential/linear/constant/fibonacci backoff
- RetryHandler with jitter, configurable retry conditions, async support
- Integrated retry into @guard decorator (retry=True, retry_* parameters)
- 30 new retry tests + 6 integration tests
- Implemented Identity Inspector with RBAC/ABAC support
- Agent/tenant allowlists, scope/role/permission enforcement
- 45 new identity inspector tests
- Enhanced PII Inspector with custom detector API
- Added CustomDetector protocol, RegexDetector, FunctionDetector classes
- 25 new custom detector tests (700 total tests)

### 2026-02-07
- Added API Inspector with SSRF protection, domain control, data exfiltration prevention
- 51 new tests for API Inspector
- Example 10: API Guard demonstration
- Fixed bandit B104 false positive
- Integrated APIInspector into @guard decorator (api=True parameter)
- 9 new integration tests
- Implemented Rate Limiter with sliding window counter
- Integrated RateLimiter into @guard decorator (rate_limit=True parameter)
- 26 new rate limiter tests
- Implemented Human-in-the-Loop (HITL) Guard with async callback support
- HITLGuard with customizable triggers, timeout, risk levels
- Integrated HITL into @guard decorator (hitl=True, hitl_callback=... parameters)
- 31 new HITL tests (594 total)

### Previous
- RAG Inspector with ABAC, classification, tenant isolation
- @guard decorator integration for RAG
- Shell Inspector with command injection detection
- File Inspector with path traversal protection
- PII Inspector with 5 handling strategies
