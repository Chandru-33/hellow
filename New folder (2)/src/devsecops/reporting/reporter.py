"""Report generation: console, JSON, and Markdown."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from devsecops.core.console import console
from devsecops.core.models import Finding, ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


class ReportGenerator:
    """Generates multi-format scan reports."""

    def __init__(self, devsecops_dir: Path) -> None:
        self.devsecops_dir = devsecops_dir
        self.reports_dir = devsecops_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_all(self, result: ScanResult) -> dict[str, str]:
        paths = {}
        paths["json"] = self.generate_json(result)
        paths["markdown"] = self.generate_markdown(result)
        self.print_console(result)
        return paths

    def print_console(self, result: ScanResult) -> None:
        self._print_llm_status(result)
        blocking = result.blocking_findings()
        unvalidated = result.unvalidated_findings()

        if result.commit_blocked:
            console.print()
            console.print(
                Panel(
                    f"[bold red]COMMIT BLOCKED[/bold red]\n\n"
                    f"{len(blocking)} Issue(s) Found\n\n"
                    f"{result.block_reason or 'Fix issues before committing.'}",
                    title="DevSecOps Guardian",
                    border_style="red",
                )
            )
        elif blocking:
            console.print(
                Panel(
                    f"[yellow]{len(blocking)} issue(s) found (non-blocking)[/yellow]",
                    title="DevSecOps Guardian",
                    border_style="yellow",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green][OK] No blocking issues detected[/bold green]",
                    title="DevSecOps Guardian",
                    border_style="green",
                )
            )

        if not blocking and not unvalidated:
            console.print(f"\n[dim]Scanned {result.files_scanned} file(s) in {result.duration_seconds:.2f}s[/dim]")
            return

        if unvalidated:
            self._print_unvalidated_table(unvalidated)

        if not blocking:
            console.print(f"\n[dim]Scanned {result.files_scanned} file(s) in {result.duration_seconds:.2f}s[/dim]")
            return

        table = Table(title="Security Findings", show_lines=True)
        table.add_column("File", style="cyan", max_width=30)
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Category", max_width=20)
        table.add_column("Issue", max_width=25)
        table.add_column("AI", max_width=8)
        table.add_column("Fix", max_width=30)

        for finding in blocking:
            color = SEVERITY_COLORS.get(finding.severity, "white")
            ai_label = self._ai_label(finding)
            table.add_row(
                finding.file_path,
                str(finding.line_number),
                Text(finding.severity.value, style=color),
                finding.category.value,
                finding.issue_type,
                ai_label,
                finding.recommended_fix[:80] + ("..." if len(finding.recommended_fix) > 80 else ""),
            )

        console.print()
        console.print(table)
        console.print(f"\n[dim]Scanned {result.files_scanned} file(s) in {result.duration_seconds:.2f}s[/dim]")

        for finding in blocking[:3]:
            self._print_finding_detail(finding)

    def _print_finding_detail(self, finding: Finding) -> None:
        console.print()
        console.print(f"[bold]FILE:[/bold] {finding.file_path}")
        console.print(f"[bold]LINE:[/bold] {finding.line_number}")
        console.print(f"[bold]SEVERITY:[/bold] [{SEVERITY_COLORS.get(finding.severity, 'white')}]{finding.severity.value}[/]")
        console.print(f"[bold]CATEGORY:[/bold] {finding.category.value}")
        console.print(f"[bold]WHY:[/bold] {finding.message}")
        console.print(f"[bold]CODE:[/bold] {finding.code_snippet}")
        console.print(f"[bold]FIX:[/bold] {finding.recommended_fix}")
        if finding.llm_validated:
            console.print(
                f"[dim]AI Validated by {finding.llm_provider or 'llm'} "
                f"(confidence: {finding.confidence}%)[/dim]"
            )
        elif finding.metadata.get("validation_status") == "unvalidated":
            console.print("[yellow]Scanner-only — not blocking without API key[/yellow]")

    def _print_llm_status(self, result: ScanResult) -> None:
        if result.llm_status == "validated":
            console.print(
                Panel(
                    f"[green]AI Validation: ACTIVE[/green] via {result.llm_provider}\n"
                    f"Confirmed: {result.llm_validated_count} | "
                    f"False positives removed: {result.llm_rejected_count}",
                    title="LLM Status",
                    border_style="green",
                )
            )
        elif result.llm_status == "skipped_no_api_key":
            env_hint = "Set GEMINI_API_KEY or GROQ_API_KEY in .env or .env.example at repo root"
            console.print(
                Panel(
                    f"[yellow]AI Validation: DISABLED — no API key found[/yellow]\n\n"
                    f"{env_hint}\n"
                    "- Secrets and dependency CVEs still block commits\n"
                    "- PII, vulnerabilities, code smells, and misconfigs are WARNINGS only\n"
                    "- Add API keys to enable AI confirmation and full commit blocking",
                    title="LLM Status",
                    border_style="yellow",
                )
            )
        elif result.llm_status == "disabled":
            console.print(
                Panel(
                    "[dim]AI Validation: OFF (--no-llm or enable_llm=false)[/dim]\n"
                    "All scanner findings block directly without AI review.",
                    title="LLM Status",
                    border_style="dim",
                )
            )

    def _ai_label(self, finding: Finding) -> str:
        if finding.llm_validated and finding.llm_valid:
            return f"{finding.llm_provider or 'AI'} OK"
        if finding.category.value in ("Secret Detection", "Dependency Vulnerability"):
            return "scanner"
        return "-"

    def _print_unvalidated_table(self, findings: list[Finding]) -> None:
        table = Table(title="Unvalidated Findings (Need API Key to Block)", show_lines=True)
        table.add_column("File", style="cyan", max_width=30)
        table.add_column("Line", justify="right")
        table.add_column("Severity")
        table.add_column("Issue", max_width=30)
        for finding in findings:
            color = SEVERITY_COLORS.get(finding.severity, "white")
            table.add_row(
                finding.file_path,
                str(finding.line_number),
                Text(finding.severity.value, style=color),
                finding.issue_type,
            )
        console.print()
        console.print(table)

    def generate_json(self, result: ScanResult) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.reports_dir / f"scan_{timestamp}.json"
        report_data = result.to_dict()
        path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        latest = self.devsecops_dir / "last_report.json"
        latest.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
        return str(path)

    def generate_markdown(self, result: ScanResult) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.reports_dir / f"scan_{timestamp}.md"
        lines = [
            "# DevSecOps Guardian Scan Report",
            "",
            f"**Scan ID:** {result.scan_id}",
            f"**Timestamp:** {result.timestamp}",
            f"**Duration:** {result.duration_seconds:.2f}s",
            f"**Files Scanned:** {result.files_scanned}",
            f"**Commit Blocked:** {'Yes' if result.commit_blocked else 'No'}",
            f"**LLM Status:** {result.llm_status}",
            f"**LLM Provider:** {result.llm_provider or 'N/A'}",
            f"**AI Confirmed:** {result.llm_validated_count}",
            f"**False Positives Removed:** {result.llm_rejected_count}",
            f"**Unvalidated (no API key):** {result.unvalidated_count}",
            "",
            "## Summary",
            "",
        ]
        summary = result.summary()
        for sev, count in summary.items():
            lines.append(f"- **{sev}:** {count}")
        lines.extend(["", "## Findings", ""])

        blocking = result.blocking_findings()
        if not blocking:
            lines.append("No blocking issues detected.")
        else:
            for i, finding in enumerate(blocking, 1):
                lines.extend([
                    f"### {i}. {finding.issue_type}",
                    "",
                    f"| Field | Value |",
                    f"|-------|-------|",
                    f"| **File** | `{finding.file_path}` |",
                    f"| **Line** | {finding.line_number} |",
                    f"| **Severity** | {finding.severity.value} |",
                    f"| **Category** | {finding.category.value} |",
                    f"| **Scanner** | {finding.scanner} |",
                    f"| **Confidence** | {finding.confidence}% |",
                    "",
                    f"**Why:** {finding.message}",
                    "",
                    "**Code:**",
                    "```",
                    finding.code_snippet,
                    "```",
                    "",
                    f"**Recommended Fix:** {finding.recommended_fix}",
                    "",
                ])
                if finding.llm_validated:
                    lines.append(f"*Validated by LLM (confidence: {finding.confidence}%)*")
                    lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)
