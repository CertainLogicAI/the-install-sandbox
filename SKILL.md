---
summary: "the-install-sandbox"
name: "the-install-sandbox"
description: "Sandbox and scan ClawHub skills before installation. Isolated tmpfs + 30+ security checks."
version: 0.1.0
author: CertainLogic
license: MIT
read_when: ["installing", "configuring", "troubleshooting"]
platforms: [linux, macos]
---

# the-install-sandbox

Run every ClawHub skill in a sandbox. Scan it. Then decide whether to install it.

## Quick Reference

| Want to... | Do this |
|------------|---------|
| Scan a skill | `the_install_sandbox scan <skill-dir>` |
| Scan + auto-decide | `the_install_sandbox install <slug>` |
| View last report | `the_install_sandbox report` |
| Set auto-approve threshold | `the_install_sandbox policy --auto-approve 5` |

## Installation

```bash
clawhub install certainlogicai/the-install-sandbox
```

## Usage

### Scan a local skill

```bash
the_install_sandbox scan /path/to/skill-dir
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

## How It Works

1. **Create sandbox** — isolated tmpfs directory (50MB default)
2. **Copy skill** — into sandbox, never touches your workspace yet
3. **Run security scan** — 30+ checks across 8 categories:
   - Prompt injection patterns
   - Code execution (eval, exec, subprocess)
   - Hardcoded secrets & API keys
   - Privilege escalation (sudo, setuid)
   - Network access (socket, urllib, requests)
   - Obfuscation / encoding
   - Dangerous commands (rm -rf, fork bombs)
   - File system abuse
4. **Generate report** — PASS / WARNING / BLOCK with score
5. **Your decision** — Install only what passes your policy

## Scoring

| Severity | Points | Example |
|----------|--------|---------|
| CRITICAL | 10 | Prompt injection, code execution, secrets |
| HIGH | 5 | Shell commands, phone-home attempts |
| MEDIUM | 2 | Network imports, file operations |
| LOW | 1 | Minor concerns |

| Score | Verdict | Action |
|-------|---------|--------|
| ≤10 | **PASS** | Safe to install |
| 11–20 | **WARNING** | Review findings first |
| >20 | **BLOCK** | Do not install |

## Policy Configuration

Set auto-approve threshold:
```bash
the_install_sandbox policy --auto-approve 5
```

Skills scoring ≤5 auto-approve. Others require manual confirmation.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | PASS |
| 1 | BLOCK |
| 2 | WARNING |
| 3 | Error |

## CI/CD Integration

```bash
# In your CI pipeline
the_install_sandbox scan ./candidate-skill --json-out > report.json
if [ $? -eq 1 ]; then
  echo "Security scan failed — skill blocked"
  exit 1
fi
```

## Why This Matters

AI agents install and run code automatically. Most developers never audit what they're installing. A malicious skill can:
- Steal your API keys
- Exfiltrate data to remote servers
- Execute arbitrary code on your system
- Inject prompts into other agents

**the-install-sandbox is your firewall for the agent ecosystem.**

## Rules

- **Always scan before installing** — no exceptions
- **Never override a BLOCK** — the scan found real threats
- **Review WARNINGs** — they might be false positives
- **Stay updated** — pattern database improves over time
