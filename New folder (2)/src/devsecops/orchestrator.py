"""Main scan orchestrator."""

from __future__ import annotations

import time
import uuid
from pathlib import Path

from devsecops.core.config import ConfigManager
from devsecops.core.fingerprint import generate_fingerprint
from devsecops.core.git_analyzer import GitAnalyzer
from devsecops.core.models import Finding, ScanContext, ScanResult, Severity
from devsecops.core.storage import JsonStorage
from devsecops.llm.validator import FindingValidator
from devsecops.llm.providers import LLMValidator
from devsecops.llm.gating import apply_llm_gating
from devsecops.reporting.reporter import ReportGenerator
from devsecops.scanners import run_scanners


class ScanOrchestrator:
    """Coordinates git analysis, scanning, LLM validation, and reporting."""

    def __init__(self, repo_path: str | Path | None = None) -> None:
        self.repo_path = Path(repo_path or Path.cwd()).resolve()
        self.config_mgr = ConfigManager(self.repo_path)
        self.config = self.config_mgr.load_config()
        self.config["client_patterns"] = self.config_mgr.load_client_patterns()
        git_root = self.config.get("_git_root", str(self.repo_path))
        self.git = GitAnalyzer(git_root)
        self.storage = JsonStorage(self.config_mgr.devsecops_dir)
        self.reporter = ReportGenerator(self.config_mgr.devsecops_dir)

    def run_scan(self, hook_mode: bool = False) -> ScanResult:
        start = time.perf_counter()
        scan_id = str(uuid.uuid4())[:8]

        is_first = self.git.is_first_commit(self.storage.has_baseline())

        if is_first:
            files = self.git.get_tracked_files()
        else:
            files = self.git.get_staged_files()

        if not files:
            result = ScanResult(
                scan_id=scan_id,
                files_scanned=0,
                is_first_commit=is_first,
                duration_seconds=time.perf_counter() - start,
            )
            return result

        context_lines = self.config.get("snippet_context_lines", 20)
        regions, dep_files = self.git.build_regions(
            files,
            is_first_commit=is_first,
            ignore_patterns=self.config.get("ignore_patterns", []),
            context_lines=0 if is_first else 0,
        )

        git_root = self.config.get("_git_root", str(self.repo_path))

        context = ScanContext(
            repo_path=str(git_root),
            is_first_commit=is_first,
            regions=regions,
            dependency_files=dep_files,
            config=self.config,
        )

        findings = run_scanners(context)
        findings = self._apply_fingerprints(findings)
        findings = self._filter_resolved(findings)

        llm_validator = LLMValidator(self.config)
        enable_llm = llm_validator.enabled
        llm_available = llm_validator.has_available_provider()
        llm_ran = False
        llm_status = "disabled"
        llm_provider = ""
        llm_validated_count = 0
        llm_rejected_count = 0
        unvalidated_count = 0

        if enable_llm and llm_available:
            finding_validator = FindingValidator(llm_validator, self.git)
            findings = finding_validator.validate_findings(findings)
            llm_ran = True
            llm_status = "validated"
            llm_provider = llm_validator.active_provider_name()
            llm_validated_count, llm_rejected_count = finding_validator.count_results(findings)
        elif enable_llm and not llm_available:
            llm_status = "skipped_no_api_key"

        findings, unvalidated_count = apply_llm_gating(
            findings,
            enable_llm=enable_llm,
            llm_available=llm_available,
            llm_ran=llm_ran,
        )

        findings = self._apply_block_rules(findings)
        commit_blocked, block_reason = self._evaluate_commit_block(findings)

        if enable_llm and not llm_available and unvalidated_count > 0:
            block_reason = (
                f"{unvalidated_count} finding(s) detected but NOT blocking without AI validation.\n"
                "Add GEMINI_API_KEY or GROQ_API_KEY to .env to enable AI confirmation and blocking.\n"
                + (f"\n{block_reason}" if block_reason else "")
            ).strip()

        result = ScanResult(
            findings=findings,
            scan_id=scan_id,
            duration_seconds=time.perf_counter() - start,
            files_scanned=len(regions),
            is_first_commit=is_first,
            commit_blocked=commit_blocked,
            block_reason=block_reason,
            llm_status=llm_status,
            llm_provider=llm_provider,
            llm_validated_count=llm_validated_count,
            llm_rejected_count=llm_rejected_count,
            unvalidated_count=unvalidated_count,
        )

        report_paths = self.reporter.generate_all(result)
        self.storage.save_last_report(result.to_dict())
        self.storage.append_history({
            "scan_id": scan_id,
            "timestamp": result.timestamp,
            "files_scanned": result.files_scanned,
            "findings_count": len(result.blocking_findings()),
            "commit_blocked": commit_blocked,
            "report_paths": report_paths,
        })

        if is_first:
            self.storage.save_baseline(self.git.get_tracked_files())

        return result

    def _apply_fingerprints(self, findings: list[Finding]) -> list[Finding]:
        for finding in findings:
            finding.fingerprint = generate_fingerprint(
                finding.file_path,
                finding.issue_type,
                finding.line_number,
                finding.code_snippet,
            )
        return findings

    def _filter_resolved(self, findings: list[Finding]) -> list[Finding]:
        return [f for f in findings if not self.storage.is_resolved(f.fingerprint)]

    def _apply_block_rules(self, findings: list[Finding]) -> list[Finding]:
        rules = self.config.get("severity_block_rules", {})
        for finding in findings:
            if finding.llm_valid is False:
                finding.blocks_commit = False
                continue
            if not finding.blocks_commit:
                continue
            sev = finding.severity.value
            finding.blocks_commit = rules.get(sev, finding.severity in (Severity.CRITICAL, Severity.HIGH))
        return findings

    def _evaluate_commit_block(self, findings: list[Finding]) -> tuple[bool, str]:
        blocking = [f for f in findings if f.blocks_commit]
        if not blocking:
            return False, ""

        categories: dict[str, int] = {}
        for f in blocking:
            key = f.issue_type
            categories[key] = categories.get(key, 0) + 1

        parts = [f"{count} {name}" for name, count in categories.items()]
        reason = f"{len(blocking)} Issues Found\n" + "\n".join(f"- {p}" for p in parts)
        reason += "\n\nFix issues before committing."
        return True, reason

    def mark_resolved(self, fingerprint: str) -> bool:
        report = self.storage.load_last_report()
        if not report:
            return False
        for finding_dict in report.get("findings", []):
            if finding_dict.get("fingerprint") == fingerprint:
                self.storage.mark_resolved(fingerprint, finding_dict)
                return True
        return False
