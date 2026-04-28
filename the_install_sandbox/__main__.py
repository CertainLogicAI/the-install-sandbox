#!/usr/bin/env python3
"""CLI entry point for the-install-sandbox."""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer

from .scanner import Scanner
from .sandbox import Sandbox
from .reporter import Reporter
from .policy import Policy

app = typer.Typer(
    help="the-install-sandbox — Sandbox and scan skills before installation",
    rich_markup_mode="rich",
)

DEFAULT_POLICY_PATH = Path.home() / ".config" / "the_install_sandbox" / "policy.json"
DEFAULT_REPORT_PATH = Path.home() / ".config" / "the_install_sandbox" / "last_report.json"


def _ensure_dirs():
    DEFAULT_POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)


def load_last_report() -> Optional[dict]:
    if DEFAULT_REPORT_PATH.exists():
        with open(DEFAULT_REPORT_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


@app.callback()
def callback():
    """the-install-sandbox — sandbox ClawHub skills before you install them."""


@app.command()
def install(
    slug: str = typer.Argument(..., help="Skill slug (author/skill-name)"),
    source: Optional[str] = typer.Option(None, help="Path to local skill directory to install from"),
    auto_approve: bool = typer.Option(False, help="Auto-approve if score below policy threshold"),
):
    """Install a skill after sandboxed scan."""
    _ensure_dirs()
    policy = Policy.load(DEFAULT_POLICY_PATH)
    sandbox = Sandbox()
    reporter = Reporter()

    try:
        typer.echo(f"the-install-sandbox: creating sandbox for {slug}...")
        sandbox_id = sandbox.create()
        typer.echo(f"Sandbox created: {sandbox_id}")

        if source:
            typer.echo(f"Copying local skill from {source} into sandbox...")
            sandbox.copy_local(source, sandbox_id)
        else:
            typer.echo(f"Fetching remote skill {slug} into sandbox...")
            sandbox.install_skill(slug, sandbox_id)

        typer.echo("Running security scan...")
        findings = sandbox.run_scan(sandbox_id)
        report = reporter.generate(slug, findings, sandbox.get_logs(sandbox_id))
        report["version"] = "unknown"  # or parse from manifest

        # Persist
        DEFAULT_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DEFAULT_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        verdict = report["verdict"]
        score = report["score"]

        reporter.print_human(report)

        if verdict == "BLOCK":
            typer.secho(f"\nInstallation BLOCKED (score {score}).", fg=typer.colors.RED, bold=True)
            sandbox.destroy(sandbox_id)
            raise typer.Exit(code=1)
        elif verdict == "WARNING":
            if auto_approve and score <= policy.auto_approve_threshold:
                typer.secho(f"\nWARNING but within auto-approve threshold ({policy.auto_approve_threshold}). Proceeding.", fg=typer.colors.YELLOW)
            else:
                typer.secho(f"\nWARNING (score {score}). Installation requires manual confirmation.", fg=typer.colors.YELLOW, bold=True)
                sandbox.destroy(sandbox_id)
                raise typer.Exit(code=2)
        else:
            typer.secho(f"\nPASS (score {score}). Proceeding with installation.", fg=typer.colors.GREEN, bold=True)

        # Actual install step would go here; for now we just accept the sandbox contents
        sandbox.destroy(sandbox_id)
    except Exception as e:
        sandbox.destroy(sandbox_id)
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=3)


@app.command()
def scan(
    target: str = typer.Argument(..., help="Skill slug or local path to skill directory"),
    json_out: bool = typer.Option(False, help="Output raw JSON report"),
):
    """Scan a skill without installing."""
    _ensure_dirs()
    sandbox = Sandbox()
    reporter = Reporter()

    is_local = os.path.isdir(target)
    slug = Path(target).name if is_local else target

    try:
        sandbox_id = sandbox.create()
        if is_local:
            sandbox.copy_local(target, sandbox_id)
        else:
            sandbox.install_skill(slug, sandbox_id)

        findings = sandbox.run_scan(sandbox_id)
        report = reporter.generate(slug, findings, sandbox.get_logs(sandbox_id))
        report["version"] = "unknown"

        # Persist
        DEFAULT_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(DEFAULT_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        if json_out:
            typer.echo(json.dumps(report, indent=2))
        else:
            reporter.print_human(report)

        sandbox.destroy(sandbox_id)

        if report["verdict"] == "BLOCK":
            raise typer.Exit(code=1)
        elif report["verdict"] == "WARNING":
            raise typer.Exit(code=2)
    except typer.Exit:
        raise
    except Exception as e:
        sandbox.destroy(sandbox_id)
        typer.secho(f"Error: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=3)


@app.command()
def report(
    json_out: bool = typer.Option(False, help="Output raw JSON"),
):
    """View the last generated report."""
    last = load_last_report()
    if not last:
        typer.secho("No report found. Run `the_install_sandbox scan` first.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)

    if json_out:
        typer.echo(json.dumps(last, indent=2))
    else:
        Reporter().print_human(last)


@app.command()
def policy(
    auto_approve: Optional[int] = typer.Option(None, help="Auto-approve threshold (score)", min=0),
    show: bool = typer.Option(False, help="Show current policy"),
):
    """Configure the-install-sandbox policy."""
    _ensure_dirs()
    p = Policy.load(DEFAULT_POLICY_PATH)

    if auto_approve is not None:
        p.auto_approve_threshold = auto_approve
        p.save(DEFAULT_POLICY_PATH)
        typer.secho(f"Policy updated: auto-approve threshold = {auto_approve}", fg=typer.colors.GREEN)

    if show or auto_approve is None:
        typer.echo(f"Auto-approve threshold: {p.auto_approve_threshold}")
        typer.echo(f"Policy file: {DEFAULT_POLICY_PATH}")


def main():
    app()


if __name__ == "__main__":
    main()
