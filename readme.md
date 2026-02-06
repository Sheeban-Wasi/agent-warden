# 🛡️ Agent-Warden

**The active defense layer for Transactional AI Agents.**

[![PyPI version](https://badge.fury.io/py/agent-warden.svg)](https://badge.fury.io/py/agent-warden)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS Strands Compatible](https://img.shields.io/badge/AWS%20Strands-Native-orange)](https://aws.amazon.com/)

---

### 🛑 Observability is not enough.
Tools like Langfuse and Arize are great for telling you *why* your agent crashed the production database. **Agent-Warden** stops it from happening.

Agent-Warden is a lightweight, zero-latency middleware that sits between your Agent and your critical infrastructure. It inspects every tool call, SQL query, and API request against a strict policy file *before* execution.

**Built for:** 🏦 Fintech, 🏥 Healthcare, and 🏢 Enterprise SOC2 environments.

---

### ⚡ Key Features

* **🧱 SQL Firewall (AST-Based):** Uses `sqlglot` to parse Abstract Syntax Trees. Blocks `DROP`, `ALTER`, `GRANT` and other destructive commands even if the LLM obfuscates them.
* **🕵️ PII Air-Gap:** Automatically detects and redacts Sensitive Data (PII) from prompts *before* they leave your server using Microsoft Presidio.
* **🆔 Identity & Scope Enforcement:** Enforces "Row-Level Security" for agents. Ensures an agent acting for `User_A` cannot access data belonging to `User_B`.
* **📜 Immutable Audit Trail:** Generates a signed, structured JSON log of every blocked action for your Compliance Officer.
* **🔌 Native Integrations:** First-class decorators for **AWS Strands** and **LangChain**.

---

### 🚀 Quick Start

#### 1. Installation
```bash
pip install agent-warden
