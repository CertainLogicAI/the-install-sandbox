# the-install-sandbox

> **Sandbox and scan ClawHub skills before they touch your system.**

Every AI agent installs code automatically. Most developers never audit what they're installing. A malicious skill can steal API keys, exfiltrate data, or execute arbitrary code.

**the-install-sandbox is your firewall for the agent ecosystem.**

[![GitHub](https://img.shields.io/github/stars/CertainLogicAI/the-install-sandbox?style=social)](https://github.com/CertainLogicAI/the-install-sandbox)
![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## What It Does

```bash
# Scan a skill before installing
the_install_sandbox scan ./candidate-skill

# Check last report
the_install_sandbox report

# Set auto-approve policy
the_install_sandbox policy --auto-approve 5
```

**Flow:**
1. Creates isolated **tmpfs sandbox** (50MB, network-blocked, time-limited)
2. Copies skill into sandbox — never touches your real filesystem
3. Runs **30+ security checks** across 8 threat categories
4. Generates **PASS / WARNING / BLOCK** verdict with score
5. You decide whether to install

## Threat Detection

| Category | Severity | Examples |
|----------|----------|----------|
| Prompt injection | CRITICAL | "ignore previous instructions" |
| Code execution | CRITICAL | `eval()`, `exec()`, `subprocess` |
| Hardcoded secrets | CRITICAL | API keys, tokens, passwords |
| Privilege escalation | CRITICAL | `sudo`, `chmod +s`, setuid |
| Network access | HIGH | `socket`, `urllib`, `requests` |
| Dangerous commands | HIGH | `rm -rf /`, fork bombs |
| Obfuscation | MEDIUM | Base64, hex encoding, concatenation |
| File system abuse | MEDIUM | `shutil.rmtree`, outside workspace |

**Scoring:** CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1
- ≤10 = **PASS**
- 11–20 = **WARNING**
- >20 = **BLOCK**

## Installation

### Option 1: ClawHub (recommended)
```bash
clawhub install certainlogicai/the-install-sandbox
```

### Option 2: pip
```bash
pip install git+https://github.com/CertainLogicAI/the-install-sandbox.git
```

### Option 3: Clone
```bash
git clone https://github.com/CertainLogicAI/the-install-sandbox.git
cd the-install-sandbox
pip install -e .
```

## Usage

### Scan a local skill

```bash
the_install_sandbox scan /path/to/skill
```

Output:
```
============================================================
  the-install-sandbox SECURITY REPORT
============================================================

  Skill:     my-skill
  Timestamp: 2026-04-28T18:30:00+00:00

  VERDICT:   ✅ PASS (Score: 0)

  No findings detected.

------------------------------------------------------------
  RECOMMENDATION
------------------------------------------------------------
  APPROVED: Score 0 — No significant concerns.

============================================================
```

### Scan a known-bad skill (demo)

```bash
the_install_sandbox scan tests/fixtures/bad_skill
```

Output ends with:
```
  VERDICT:   ❌ BLOCK (Score: 154)

  [CRITICAL] — 15 finding(s)
    📁 bad_script.py:7
       Dynamic code execution detected
    📁 bad_script.py:18
       Hardcoded secret or credential detected
  ...

Installation BLOCKED (score 154).
```

### CI/CD Integration

```bash
# In your CI pipeline
the_install_sandbox scan ./candidate-skill --json-out > report.json
if [ $? -eq 1 ]; then
  echo "Security scan failed — skill blocked"
  exit 1
fi
```

## Why This Matters

AI agents install and run code automatically. A malicious skill can:
- 🔑 Steal your API keys from environment variables
- 📡 Exfiltrate data to remote servers
- 🖥️ Execute arbitrary code on your system
- 💬 Inject prompts into other agents
- 🗑️ Delete files with `rm -rf`

**the-install-sandbox verifies every skill before it runs.**

## Architecture

```
┌─────────────────────────────┐
│  the_install_sandbox scan   │
└─────────────┬───────────────┘
              │
     ┌────────▼────────┐
     │   tmpfs jail    │  ← 50MB, network OFF, 5min timeout
     │   + skill code  │
     └────────┬────────┘
              │
     ┌────────▼────────┐
     │  Scanner Engine │  ← 30+ regex/AST/entropy checks
     │  (8 categories) │
     └────────┬────────┘
              │
     ┌────────▼────────┐
     │  Reporter       │  ← JSON + human-readable output
     └─────────────────┘
```

## Company Brain

This is one component of the [Company Brain](https://x.com/4cryptoclearly/status/2049210336901791828) — deterministic AI infrastructure we're building in public.

| Component | What It Does |
|-----------|-------------|
| **the-install-sandbox** | 🔒 Secure — sandbox before trust |
| **AgentPathfinder** | 📋 Track — cryptographic task tracking |
| **Token Reduction Engine** | ✅ Validate — deterministic output |

## Contributing

Found a false positive? Missing detection? Open an issue or PR.

## License

MIT — use it, fork it, ship it.

---

*Built by [CertainLogic](https://github.com/CertainLogicAI) — deterministic AI, one component at a time.*
