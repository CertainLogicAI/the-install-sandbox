"""Test suite for CertainGuard."""

import json
import shutil
from pathlib import Path

import pytest

from the_install_sandbox.scanner import Scanner
from the_install_sandbox.sandbox import Sandbox, SandboxConfig
from the_install_sandbox.reporter import Reporter


FIXTURES = Path(__file__).parent / "fixtures"
BAD_SKILL = FIXTURES / "bad_skill"
GOOD_SKILL = FIXTURES / "good_skill"


# ---------------------------------------------------------------------------
# Scanner tests
# ---------------------------------------------------------------------------
class TestScanner:
    def test_detects_exec(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        assert any(f["category"] == "code_execution" for f in findings)

    def test_detects_api_key(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        assert any(f["category"] == "secret_leakage" for f in findings)

    def test_detects_prompt_injection(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        assert any(f["category"] == "prompt_injection" for f in findings)

    def test_detects_privilege_escalation(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        assert any(f["category"] == "privilege_escalation" for f in findings)

    def test_bad_skill_is_blocked(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        score = Scanner.score(findings)
        verdict = Scanner.verdict(score)
        assert verdict == "BLOCK", f"Expected BLOCK, got {verdict} (score={score})"
        assert score > 20

    def test_good_skill_passes(self):
        s = Scanner()
        findings = s.scan_directory(GOOD_SKILL)
        score = Scanner.score(findings)
        verdict = Scanner.verdict(score)
        assert verdict == "PASS", f"Expected PASS, got {verdict} (score={score})"
        assert score <= 10

    def test_entropy_scan_flags_high_entropy_secret(self):
        s = Scanner()
        findings = s.scan_directory(BAD_SKILL)
        secret_findings = [f for f in findings if f["category"] == "secret_leakage"]
        assert len(secret_findings) >= 2


# ---------------------------------------------------------------------------
# Sandbox tests
# ---------------------------------------------------------------------------
class TestSandbox:
    def test_create_and_destroy(self):
        sb = Sandbox(SandboxConfig(use_namespaces=False))
        sid = sb.create()
        assert (Sandbox.BASE_DIR / sid).exists()
        sb.destroy(sid)
        assert not (Sandbox.BASE_DIR / sid).exists()

    def test_copy_local_and_scan(self):
        sb = Sandbox(SandboxConfig(use_namespaces=False))
        sid = sb.create()
        sb.copy_local(str(BAD_SKILL), sid)
        findings = sb.run_scan(sid)
        assert any(f["category"] == "code_execution" for f in findings)
        sb.destroy(sid)

    def test_logs_recorded(self):
        sb = Sandbox(SandboxConfig(use_namespaces=False))
        sid = sb.create()
        sb.copy_local(str(GOOD_SKILL), sid)
        sb.run_scan(sid)
        logs = sb.get_logs(sid)
        assert any("Scan complete" in log for log in logs)
        sb.destroy(sid)


# ---------------------------------------------------------------------------
# Reporter tests
# ---------------------------------------------------------------------------
class TestReporter:
    def test_generate_block_report(self):
        r = Reporter()
        findings = Scanner().scan_directory(BAD_SKILL)
        report = r.generate("test/bad", findings, ["log1", "log2"])
        assert report["verdict"] == "BLOCK"
        assert report["score"] > 20
        assert "recommendation" in report
        assert report["skill"] == "test/bad"

    def test_generate_pass_report(self):
        r = Reporter()
        findings = Scanner().scan_directory(GOOD_SKILL)
        report = r.generate("test/good", findings, ["log1"])
        assert report["verdict"] == "PASS"
        assert report["score"] <= 10

    def test_report_json_serializable(self):
        r = Reporter()
        findings = Scanner().scan_directory(BAD_SKILL)
        report = r.generate("test/bad", findings, ["log1"])
        # Should not raise
        json.dumps(report)


# ---------------------------------------------------------------------------
# Integration: end-to-end via CLI helpers
# ---------------------------------------------------------------------------
class TestIntegration:
    def test_bad_skill_end_to_end(self):
        sb = Sandbox(SandboxConfig(use_namespaces=False))
        reporter = Reporter()
        sid = sb.create()
        try:
            sb.copy_local(str(BAD_SKILL), sid)
            findings = sb.run_scan(sid)
            report = reporter.generate("evil/bad-skill", findings, sb.get_logs(sid))
            assert report["verdict"] == "BLOCK"
            # Ensure critical findings are surfaced
            crits = [f for f in report["findings"] if f["severity"] == "CRITICAL"]
            assert len(crits) >= 5
        finally:
            sb.destroy(sid)

    def test_good_skill_end_to_end(self):
        sb = Sandbox(SandboxConfig(use_namespaces=False))
        reporter = Reporter()
        sid = sb.create()
        try:
            sb.copy_local(str(GOOD_SKILL), sid)
            findings = sb.run_scan(sid)
            report = reporter.generate("safe/good-skill", findings, sb.get_logs(sid))
            assert report["verdict"] == "PASS"
            assert report["findings"] == []
        finally:
            sb.destroy(sid)
