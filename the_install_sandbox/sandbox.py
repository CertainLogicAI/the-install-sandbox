"""Sandbox management — isolated environment for skill testing."""
import os
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .scanner import Scanner


@dataclass
class SandboxConfig:
    """Configuration for sandbox behavior."""
    use_namespaces: bool = True
    size_mb: int = 50
    timeout_sec: int = 300


class Sandbox:
    """Create an isolated tmpfs sandbox with optional Linux namespaces."""

    BASE_DIR = Path(tempfile.gettempdir()) / "the_install_sandbox-sandbox"

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._logs: dict[str, list[str]] = {}

    def _log(self, sid: str, msg: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._logs.setdefault(sid, []).append(f"[{ts}] {msg}")

    def create(self) -> str:
        """Create sandbox directory. Returns sandbox ID."""
        self.BASE_DIR.mkdir(parents=True, exist_ok=True)
        sid = f"cg-{uuid.uuid4().hex[:8]}"
        sandbox_dir = self.BASE_DIR / sid
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        self._log(sid, f"Sandbox created: {sandbox_dir}")
        return sid

    def destroy(self, sid: str) -> None:
        """Destroy sandbox and cleanup."""
        sandbox_dir = self.BASE_DIR / sid
        if sandbox_dir.exists():
            shutil.rmtree(sandbox_dir, ignore_errors=True)
            self._log(sid, f"Sandbox destroyed: {sandbox_dir}")
        self._logs.pop(sid, None)

    def copy_local(self, source: str, sid: str) -> bool:
        """Copy local skill directory into sandbox."""
        sandbox_dir = self.BASE_DIR / sid
        if not sandbox_dir.exists():
            return False
        source_path = Path(source)
        dest = sandbox_dir / "skill"
        if source_path.is_dir():
            shutil.copytree(source_path, dest, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("*.pyc", "__pycache__", ".git"))
        else:
            shutil.copy2(source_path, dest)
        self._log(sid, f"Skill copied: {dest}")
        return True

    def run_scan(self, sid: str) -> list[dict]:
        """Run security scan on sandboxed skill."""
        sandbox_dir = self.BASE_DIR / sid
        skill_dir = sandbox_dir / "skill"
        if not skill_dir.exists():
            self._log(sid, "ERROR: No skill to scan")
            return []
        scanner = Scanner()
        findings = scanner.scan_directory(skill_dir)
        self._log(sid, f"Scan complete: {len(findings)} findings")
        return findings

    def get_logs(self, sid: str) -> list[str]:
        return self._logs.get(sid, []).copy()
