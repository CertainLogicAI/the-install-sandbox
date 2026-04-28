"""Security scanner — analyzes skill code for threats."""
import re
from pathlib import Path
from typing import Any

from .utils import walk_files, is_text_file, find_high_entropy_strings
from .patterns import injection, execution, network, secrets, obfuscation


def _line_number(text: str, pos: int) -> int:
    """Return 1-based line number for character position."""
    return text[:pos].count("\n") + 1


class Scanner:
    """Scan skill directories for security threats."""

    SEVERITY_SCORES = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}

    def __init__(self):
        pass

    def scan_directory(self, skill_dir: Path) -> list[dict[str, Any]]:
        """Scan a skill directory and return list of finding dicts."""
        findings = []

        for file_path in walk_files(skill_dir):
            if not is_text_file(file_path):
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel_path = str(file_path.relative_to(skill_dir))
            findings.extend(self._scan_file(content, rel_path))

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["category"], f["file"], f["line"], f["evidence"][:40])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _scan_file(self, content: str, rel_path: str) -> list[dict[str, Any]]:
        """Scan single file content."""
        findings = []

        # 1. Prompt injection
        for pattern in injection.INJECTION_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "prompt_injection",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Potential prompt injection pattern detected",
                    "evidence": m.group(0)[:100],
                })

        # 2. Code execution
        for pattern in execution.EXECUTION_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "code_execution",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Dynamic code execution detected",
                    "evidence": m.group(0)[:100],
                })

        for pattern in execution.SHELL_EXECUTION_PATTERNS:
            for m in re.finditer(pattern, content):
                findings.append({
                    "severity": "HIGH",
                    "category": "shell_execution",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Shell command execution pattern",
                    "evidence": m.group(0)[:100],
                })

        # 3. Network patterns
        for imp in network.NETWORK_IMPORTS:
            if re.search(rf"\bimport\s+{re.escape(imp)}\b|\bfrom\s+{re.escape(imp)}\b", content):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "network_import",
                    "file": rel_path,
                    "line": 1,
                    "description": f"Network-capable module imported: {imp}",
                    "evidence": f"import {imp}",
                })

        for pattern in network.NETWORK_FUNCTIONS:
            for m in re.finditer(pattern, content):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "network_function",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Network function call detected",
                    "evidence": m.group(0)[:100],
                })

        for pattern in network.PHONE_HOME_PATTERNS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "severity": "HIGH",
                    "category": "phone_home",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Potential outbound network request",
                    "evidence": m.group(0)[:100],
                })

        # 4. Secret detection
        for pattern in secrets.SECRET_KEYWORDS:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "secret_leakage",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Hardcoded secret or credential detected",
                    "evidence": m.group(0)[:60] + "...[REDACTED]",
                })

        for token, ent in find_high_entropy_strings(content):
            if ent >= 5.0:
                findings.append({
                    "severity": "HIGH",
                    "category": "secret_leakage",
                    "file": rel_path,
                    "line": 1,
                    "description": f"High-entropy string (entropy={ent:.2f}) may be a secret",
                    "evidence": token[:20] + "...",
                })

        # 5. Obfuscation
        for pattern in obfuscation.OBFUSCATION_PATTERNS:
            for m in re.finditer(pattern, content):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "obfuscation",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Obfuscated or encoded content detected",
                    "evidence": m.group(0)[:80],
                })

        # 6. Dangerous bash
        for cmd in execution.DANGEROUS_BASH:
            if cmd.lower() in content.lower():
                findings.append({
                    "severity": "CRITICAL",
                    "category": "dangerous_command",
                    "file": rel_path,
                    "line": 1,
                    "description": f"Dangerous system command detected: {cmd}",
                    "evidence": cmd,
                })

        # 7. Privilege escalation
        priv_patterns = [
            r"\bsudo\b", r"chmod\s+\+s", r"setuid", r"setgid",
            r"chmod\s+777", r"chmod\s+4755",
        ]
        for pattern in priv_patterns:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    "severity": "CRITICAL",
                    "category": "privilege_escalation",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "Potential privilege escalation attempt",
                    "evidence": m.group(0),
                })

        # 8. Filesystem operations
        fs_patterns = [
            r"\bos\.remove\s*\(", r"\bos\.rmdir\s*\(",
            r"\bos\.unlink\s*\(", r"\bshutil\.rmtree\s*\(",
            r"\bPath\(.*\)\.unlink\s*\(", r"\bopen\s*\(\s*['\"`]/",
        ]
        for pattern in fs_patterns:
            for m in re.finditer(pattern, content):
                findings.append({
                    "severity": "MEDIUM",
                    "category": "filesystem_operation",
                    "file": rel_path,
                    "line": _line_number(content, m.start()),
                    "description": "File system operation detected",
                    "evidence": m.group(0)[:80],
                })

        return findings

    @classmethod
    def score(cls, findings: list[dict]) -> int:
        """Calculate security score from findings."""
        return sum(cls.SEVERITY_SCORES.get(f.get("severity", "LOW"), 1) for f in findings)

    @classmethod
    def verdict(cls, score: int) -> str:
        """Determine verdict from score."""
        if score >= 20:
            return "BLOCK"
        elif score >= 10:
            return "WARNING"
        return "PASS"
