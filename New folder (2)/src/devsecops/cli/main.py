"""CLI entry point using Typer."""

from __future__ import annotations

from devsecops.core.console import configure_stdio_encoding

configure_stdio_encoding()

import json
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.table import Table

from devsecops import __version__
from devsecops.core.console import console
from devsecops.core.config import ConfigManager, DEFAULT_CONFIG
from devsecops.orchestrator import ScanOrchestrator

app = typer.Typer(
    name="devsecops",
    help="Enterprise DevSecOps Pre-Commit Guardian",
    add_completion=False,
    invoke_without_command=True,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"devsecops-guardian {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False, "--version", "-v", help="Show version", callback=_version_callback, is_eager=True
    ),
) -> None:
    if ctx.invoked_subcommand is None and not version:
        console.print(ctx.get_help())
        raise typer.Exit()


@app.command()
def scan(
    path: Optional[Path] = typer.Argument(None, help="Repository path (default: cwd)"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Disable LLM validation"),
    hook: bool = typer.Option(False, "--hook", help="Run in pre-commit hook mode"),
) -> None:
    """Run security scan on staged (or all tracked) files."""
    repo = path or Path.cwd()
    orchestrator = ScanOrchestrator(repo)
    if no_llm:
        orchestrator.config["enable_llm"] = False

    result = orchestrator.run_scan(hook_mode=hook)

    if hook and result.commit_blocked:
        console.print("[red]Commit blocked by DevSecOps Guardian.[/red]")
        raise typer.Exit(code=1)

    if result.commit_blocked:
        raise typer.Exit(code=1)


@app.command()
def report(
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
    format: str = typer.Option("console", "--format", "-f", help="console|json|markdown"),
) -> None:
    """Display the last scan report."""
    repo = path or Path.cwd()
    config_mgr = ConfigManager(repo)
    report_path = config_mgr.devsecops_dir / "last_report.json"

    if not report_path.exists():
        console.print("[yellow]No scan report found. Run 'devsecops scan' first.[/yellow]")
        raise typer.Exit(code=1)

    data = json.loads(report_path.read_text(encoding="utf-8"))

    if format == "json":
        console.print_json(json.dumps(data, indent=2))
    elif format == "markdown":
        reports_dir = config_mgr.devsecops_dir / "reports"
        md_files = sorted(reports_dir.glob("*.md"), reverse=True) if reports_dir.exists() else []
        if md_files:
            console.print(md_files[0].read_text(encoding="utf-8"))
        else:
            console.print("[yellow]No markdown report found.[/yellow]")
    else:
        _print_report_summary(data)


@app.command()
def status(
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
) -> None:
    """Show DevSecOps Guardian status and configuration."""
    repo = path or Path.cwd()
    config_mgr = ConfigManager(repo)
    config = config_mgr.load_config()
    storage_path = config_mgr.devsecops_dir

    table = Table(title="DevSecOps Guardian Status")
    table.add_column("Setting", style="cyan")
    table.add_column("Value")

    table.add_row("Version", __version__)
    table.add_row("Repository", str(config_mgr.git_root))
    table.add_row("Config Dir", str(storage_path))
    env_files = config.get("_env_files_loaded", [])
    table.add_row("Env Files Loaded", ", ".join(env_files) if env_files else "None")
    table.add_row("Baseline", "Yes" if (storage_path / "baseline.json").exists() else "No")
    table.add_row("LLM Enabled", str(config.get("enable_llm", True)))
    table.add_row("LLM Provider", config.get("llm_provider", "gemini"))
    table.add_row("Block Medium", str(config.get("block_medium", False)))

    settings = config.get("_settings")
    gemini_ok = groq_ok = False
    if settings:
        gemini_ok = bool(settings.gemini_api_key)
        groq_ok = bool(settings.groq_api_key)
        table.add_row("Gemini API Key", "Configured" if gemini_ok else "Not set")
        table.add_row("Groq API Key", "Configured" if groq_ok else "Not set")

    llm_enabled = config.get("enable_llm", True)
    has_key = gemini_ok or groq_ok
    if llm_enabled and has_key:
        llm_impact = "AI validates findings, filters false positives, enables full blocking"
    elif llm_enabled and not has_key:
        llm_impact = "Scanner-only mode — only secrets/CVEs block; add API keys for full protection"
    else:
        llm_impact = "Disabled — all scanner findings block directly"
    table.add_row("LLM Impact", llm_impact)

    scanners = config.get("scanners", {})
    enabled = [k for k, v in scanners.items() if v]
    table.add_row("Active Scanners", ", ".join(enabled))

    console.print(table)


@app.command()
def history(
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
    limit: int = typer.Option(10, "--limit", "-n", help="Number of scans to show"),
) -> None:
    """Show scan history."""
    from devsecops.core.storage import JsonStorage

    repo = path or Path.cwd()
    storage = JsonStorage(ConfigManager(repo).devsecops_dir)
    scans = storage.get_history(limit)

    if not scans:
        console.print("[yellow]No scan history found.[/yellow]")
        return

    table = Table(title="Scan History")
    table.add_column("Scan ID")
    table.add_column("Timestamp")
    table.add_column("Files")
    table.add_column("Findings")
    table.add_column("Blocked")

    for scan in reversed(scans):
        table.add_row(
            scan.get("scan_id", "?"),
            scan.get("timestamp", "?")[:19],
            str(scan.get("files_scanned", 0)),
            str(scan.get("findings_count", 0)),
            "Yes" if scan.get("commit_blocked") else "No",
        )
    console.print(table)


@app.command()
def config(
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
    init: bool = typer.Option(False, "--init", help="Initialize default configuration"),
    show: bool = typer.Option(False, "--show", help="Show current configuration"),
) -> None:
    """Manage DevSecOps configuration."""
    repo = path or Path.cwd()
    config_mgr = ConfigManager(repo)

    if init:
        config_path = config_mgr.save_default_config()
        client_path = config_mgr.save_default_client_patterns()
        console.print(f"[green]Created config:[/green] {config_path}")
        console.print(f"[green]Created client patterns:[/green] {client_path}")
        env_example = repo / ".env.example"
        if not (repo / ".env").exists():
            console.print("[yellow]Copy .env.example to .env and add your API keys.[/yellow]")
        return

    if show:
        cfg = config_mgr.load_config()
        cfg.pop("_settings", None)
        console.print(yaml.dump(cfg, default_flow_style=False, sort_keys=False))
        return

    config_path = config_mgr.config_path()
    if config_path.exists():
        console.print(yaml.dump(config_mgr.load_config(), default_flow_style=False))
    else:
        console.print("[yellow]No config found. Run 'devsecops config --init'[/yellow]")


@app.command("install-hook")
def install_hook(
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
    pre_commit: bool = typer.Option(False, "--pre-commit", help="Also add to .pre-commit-config.yaml"),
) -> None:
    """Install Git pre-commit hook."""
    from devsecops.hooks.installer import HookInstaller

    repo = path or Path.cwd()
    installer = HookInstaller(repo)
    hook_path = installer.install_git_hook()
    console.print(f"[green]Installed pre-commit hook:[/green] {hook_path}")

    if pre_commit:
        pc_path = installer.install_pre_commit_config()
        console.print(f"[green]Updated pre-commit config:[/green] {pc_path}")

    config_mgr = ConfigManager(repo)
    config_mgr.save_default_config()
    config_mgr.save_default_client_patterns()
    console.print("[green]DevSecOps Guardian hook installed successfully.[/green]")


@app.command()
def resolve(
    fingerprint: str = typer.Argument(..., help="Issue fingerprint to mark as resolved"),
    path: Optional[Path] = typer.Argument(None, help="Repository path"),
) -> None:
    """Mark a finding as resolved so it won't be re-flagged."""
    repo = path or Path.cwd()
    orchestrator = ScanOrchestrator(repo)
    if orchestrator.mark_resolved(fingerprint):
        console.print(f"[green]Marked issue {fingerprint[:16]}... as resolved.[/green]")
    else:
        console.print("[red]Fingerprint not found in last report.[/red]")
        raise typer.Exit(code=1)


def _print_report_summary(data: dict) -> None:
    console.print(f"\n[bold]Scan ID:[/bold] {data.get('scan_id')}")
    console.print(f"[bold]Timestamp:[/bold] {data.get('timestamp')}")
    console.print(f"[bold]Commit Blocked:[/bold] {data.get('commit_blocked')}")
    findings = data.get("findings", [])
    blocking = [f for f in findings if f.get("blocks_commit") and f.get("llm_valid") is not False]
    console.print(f"[bold]Findings:[/bold] {len(blocking)} blocking / {len(findings)} total\n")

    for f in blocking:
        console.print(f"  [{f.get('severity')}] {f.get('file_path')}:{f.get('line_number')} - {f.get('issue_type')}")


if __name__ == "__main__":
    app()
