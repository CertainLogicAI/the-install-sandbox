"""User security policy configuration."""
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Policy:
    """User-configurable security policy."""

    # Auto-approve if score below this threshold
    auto_approve_threshold: int = 5

    # Always block these categories regardless of score
    block_categories: list[str] = field(default_factory=lambda: [
        "prompt_injection",
        "code_execution",
        "hardcoded_secret",
        "dangerous_command",
        "privilege_escalation",
    ])

    # Require manual approval for these categories
    warn_categories: list[str] = field(default_factory=lambda: [
        "shell_execution",
        "phone_home",
        "high_entropy_string",
    ])

    # Network policy
    allow_network: bool = False
    allowed_hosts: list[str] = field(default_factory=list)

    # File system policy
    allow_file_write: bool = False
    allowed_paths: list[str] = field(default_factory=lambda: ["."])

    # Max sandbox resources
    max_sandbox_size_mb: int = 50
    max_sandbox_timeout_sec: int = 300

    @classmethod
    def default(cls) -> "Policy":
        return cls()

    @classmethod
    def from_file(cls, path: Path) -> "Policy":
        """Load policy from JSON file."""
        if not path.exists():
            return cls.default()
        data = json.loads(path.read_text())
        return cls(**data)

    def to_file(self, path: Path) -> None:
        """Save policy to JSON file."""
        path.write_text(json.dumps(self.__dict__, indent=2))

    @classmethod
    def load(cls, path: Path) -> "Policy":
        """Load policy from JSON file (alias for from_file)."""
        return cls.from_file(path)

    def save(self, path: Path) -> None:
        """Save policy to JSON file (alias for to_file)."""
        self.to_file(path)

    def evaluate(self, report) -> tuple[str, str]:
        """Evaluate a report against this policy. Returns (verdict, reason)."""
        # Check block categories first
        for finding in report.findings:
            if finding.category in self.block_categories:
                return "BLOCK", f"Blocked: {finding.category} is in block list"

        # Check score threshold
        if report.score <= self.auto_approve_threshold:
            return "PASS", f"Score {report.score} <= threshold {self.auto_approve_threshold}"

        # Check warning categories
        for finding in report.findings:
            if finding.category in self.warn_categories:
                return "WARNING", f"Warning: {finding.category} requires review"

        # Default to report verdict
        return report.verdict, "Policy evaluation complete"
