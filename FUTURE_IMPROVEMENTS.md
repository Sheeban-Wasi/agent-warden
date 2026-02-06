# Agent-Warden: Future Improvements

This document tracks potential enhancements and features for future releases.

---

## SQL Inspector Enhancements

### Detection Improvements

- [ ] **JSON-based SQL Injection Detection**
  - Monitor for JSON syntax in SQL payloads (2024-2025 WAF bypass technique)
  - Reference: https://claroty.com/team82/research/js-on-security-off-abusing-json-based-sql-to-bypass-waf
  - Many WAFs failed to parse JSON in SQL until recently

- [ ] **Time-based Function Blocking (Optional Mode)**
  - Add optional strict mode to block `SLEEP()`, `BENCHMARK()`, `pg_sleep()`, `WAITFOR DELAY`
  - These are suspicious in agent-generated queries
  - Make configurable per policy

- [ ] **Information Schema Access Control**
  - Optional blocking of `information_schema`, `pg_catalog`, `sys` queries
  - Prevents schema enumeration attacks
  - Configurable allow/block list

- [ ] **Prepared Statement Detection**
  - Detect dynamic SQL building patterns
  - Flag `PREPARE` / `EXECUTE` statements
  - Monitor for `sp_executesql` with concatenation

### Database-Specific Features

- [ ] **MySQL 8.0+ Features**
  - Window functions security
  - CTE recursive depth limits
  - JSON_TABLE injection patterns

- [ ] **PostgreSQL Extensions**
  - `pg_read_file()` blocking
  - `lo_import()` / `lo_export()` detection
  - Extension-based attacks (`dblink`, `postgres_fdw`)

- [ ] **SQL Server Hardening**
  - `OPENROWSET` / `OPENDATASOURCE` blocking
  - `xp_*` extended procedure detection
  - Linked server query detection

- [ ] **SQLite Specific**
  - `ATTACH DATABASE` blocking
  - `.import` / `.output` detection

### Performance Optimizations

- [ ] **Query Caching**
  - LRU cache for repeated query patterns
  - Hash-based lookup for known-safe queries
  - Configurable cache size

- [ ] **Parallel Statement Analysis**
  - Async processing for multi-statement queries
  - Thread pool for high-throughput scenarios

- [ ] **Pre-compiled Pattern Matching**
  - Compile regex patterns once at init
  - Use `re.compile()` for hot paths

---

## New Inspectors

### PII Inspector (Planned - Task #10)
- [ ] Presidio integration for entity detection
- [ ] Custom pattern support (employee IDs, internal codes)
- [ ] Redaction strategies (mask, hash, remove)
- [ ] Language support beyond English

### Prompt Injection Inspector
- [ ] Detect prompt injection attempts in user input
- [ ] Jailbreak pattern detection
- [ ] System prompt leakage prevention
- [ ] Integration with prompt templates

### Output Inspector
- [ ] Validate agent outputs before returning to user
- [ ] Sensitive data leak detection
- [ ] Code execution risk assessment
- [ ] URL/link safety checking

### File Path Inspector
- [ ] Path traversal detection (`../`, `..\\`)
- [ ] Sensitive file access blocking (`/etc/passwd`, `.env`)
- [ ] Symlink attack prevention
- [ ] Allowed directory whitelisting

### Command Inspector
- [ ] Shell command injection detection
- [ ] Dangerous command blocking (`rm -rf`, `format`)
- [ ] Environment variable injection
- [ ] Pipe and redirect safety

---

## Policy Engine Enhancements

- [ ] **Policy Inheritance**
  - Base policies with overrides
  - Environment-specific policies (dev/staging/prod)
  - Role-based policy selection

- [ ] **Dynamic Policy Loading**
  - Hot-reload without restart
  - Remote policy fetching (S3, HTTP)
  - Policy versioning and rollback

- [ ] **Policy Testing Framework**
  - Dry-run mode for policy changes
  - Policy diff visualization
  - Automated policy validation

- [ ] **Conditional Policies**
  - Time-based rules (maintenance windows)
  - User/role-based rules
  - Request context conditions

---

## Integration Improvements

### AWS Strands SDK
- [ ] Native middleware support (when available)
- [ ] CloudWatch metrics integration
- [ ] X-Ray tracing support
- [ ] Secrets Manager for policy storage

### LangChain
- [ ] Chain-level guards
- [ ] Tool-specific policies
- [ ] Memory inspection
- [ ] Retriever output validation

### Other Frameworks
- [ ] LlamaIndex integration
- [ ] AutoGPT/AgentGPT support
- [ ] CrewAI integration
- [ ] Semantic Kernel adapter

---

## Observability & Compliance

### Audit Logging (Planned - Task #6)
- [ ] Structured JSON logs
- [ ] Log aggregation support (ELK, Splunk, DataDog)
- [ ] Compliance report generation
- [ ] Log retention policies

### Metrics & Monitoring
- [ ] Prometheus metrics endpoint
- [ ] Block rate tracking
- [ ] Latency percentiles (p50, p95, p99)
- [ ] Alert thresholds

### Dashboard
- [ ] Real-time blocking visualization
- [ ] Attack pattern trends
- [ ] Policy effectiveness metrics
- [ ] Agent behavior analytics

---

## Security Research Backlog

### Techniques to Monitor
- [ ] **Adversarial ML attacks** on SQL classifiers
- [ ] **Mutation-based bypass** techniques (BWAFSQLi framework)
- [ ] **HTTP Parameter Pollution** patterns
- [ ] **Content-Type confusion** attacks
- [ ] **Unicode normalization** bypasses

### Resources to Review Periodically
- PayloadsAllTheThings updates: https://github.com/swisskyrepo/PayloadsAllTheThings
- SecLists new additions: https://github.com/danielmiessler/SecLists
- OWASP updates: https://owasp.org/www-community/attacks/SQL_Injection
- WAF Bypass blog: https://waf-bypass.com/
- HackerOne disclosed reports

---

## Developer Experience

- [ ] **CLI Tool**
  - `warden check "SELECT * FROM users"` - quick SQL check
  - `warden test policy.yaml` - validate policy file
  - `warden audit logs/` - analyze audit logs

- [ ] **IDE Extensions**
  - VS Code extension for inline SQL validation
  - PyCharm plugin
  - Real-time feedback while coding

- [ ] **Documentation**
  - Interactive examples
  - Video tutorials
  - Architecture deep-dive
  - Contribution guide

---

## Notes

*Last updated: 2025-02-05*

This document is a living backlog. Items are not prioritized - priority should be determined based on user feedback and security landscape changes.

To contribute ideas, open an issue with the `enhancement` label.
