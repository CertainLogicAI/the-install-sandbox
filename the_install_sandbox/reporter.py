"""Report generation — human-readable and JSON output."""
import json
from typing import Any

from .scanner import Scanner


class Reporter:
    """Generate security reports from scan findings."""

    def generate(self, skill_name: str, findings: list[dict], logs: list[str]) -> dict[str, Any]:
        """Generate a report dict from findings and logs."""
        import datetime
        score = Scanner.score(findings)
        verdict = Scanner.verdict(score)

        if verdict == "BLOCK":
            recommendation = f"BLOCKED: Score {score}/20+ — Critical security risks. Do not install."
        elif verdict == "WARNING":
            recommendation = f"WARNING: Score {score}/10+ — Review findings before installing."
        else:
            recommendation = f"APPROVED: Score {score} — No significant concerns."

        return {
            "skill": skill_name,
            "version": "",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "verdict": verdict,
            "score": score,
            "findings": findings,
            "sandbox_logs": logs,
            "recommendation": recommendation,
        }

    def to_json(self, report: dict) -> str:
        return json.dumps(report, indent=2)

    def print_human(self, report: dict) -> None:
        """Print human-readable report to stdout via typer."""
        import typer
        typer.echo(self.to_text(report))

    def to_text(self, report: dict) -> str:
        """Human-readable text report."""
        lines = []
        lines.append("=" * 60)
        lines.append("  CERTAINGUARD SECURITY REPORT")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"  Skill:     {report['skill']}")
        lines.append(f"  Timestamp: {report['timestamp']}")
        lines.append("")

        if report["verdict"] == "BLOCK":
            lines.append(f"  VERDICT:   ❌ BLOCK (Score: {report['score']})")
        elif report["verdict"] == "WARNING":
            lines.append(f"  VERDICT:   ⚠️  WARNING (Score: {report['score']})")
        else:
            lines.append(f"  VERDICT:   ✅ PASS (Score: {report['score']})")
        lines.append("")

        if report["findings"]:
            lines.append("-" * 60)
            lines.append("  FINDINGS")
            lines.append("-" * 60)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                sev_f = [f for f in report["findings"] if f.get("severity") == sev]
                if sev_f:
                    lines.append(f"\n  [{sev}] — {len(sev_f)} finding(s)")
                    for f in sev_f:
                        lines.append(f"    📁 {f['file']}:{f['line']}")
                        lines.append(f"       {f['description']}")
        else:
            lines.append("  No findings detected.")

        lines.append("")
        lines.append("-" * 60)
        lines.append("  RECOMMENDATION")
        lines.append("-" * 60)
        lines.append(f"  {report['recommendation']}")
        lines.append("")
        lines.append("=" * 60)
        return "\n".join(lines)
