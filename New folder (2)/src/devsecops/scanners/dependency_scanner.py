"""Dependency vulnerability scanning via OSV Scanner."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner


class DependencyScanner(BaseScanner):
    name = "dependencies"

    def scan(self, context: ScanContext) -> list[Finding]:
        if not context.dependency_files:
            return []
        if not context.config.get("external_tools", {}).get("osv_scanner", True):
            return self._basic_check(context)
        if shutil.which("osv-scanner"):
            return self._run_osv_scanner(context)
        return self._basic_check(context)

    def _run_osv_scanner(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for dep_file in context.dependency_files:
            full_path = context.repo_path / dep_file
            if not full_path.is_file():
                continue
            result = subprocess.run(
                ["osv-scanner", "--format", "json", "-L", str(full_path)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode not in (0, 1):
                continue
            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError:
                continue
            for scan_result in data.get("results", []):
                for pkg in scan_result.get("packages", []):
                    pkg_info = pkg.get("package", {})
                    for vuln in pkg.get("vulnerabilities", []):
                        severity = self._map_osv_severity(vuln)
                        findings.append(
                            Finding(
                                file_path=dep_file,
                                line_number=1,
                                severity=severity,
                                category=Category.DEPENDENCY,
                                issue_type=f"CVE: {vuln.get('id', 'Unknown')}",
                                message=(
                                    f"Vulnerable dependency {pkg_info.get('name', '?')} "
                                    f"@{pkg_info.get('version', '?')}: {vuln.get('summary', '')}"
                                ),
                                code_snippet=f"{pkg_info.get('name')}=={pkg_info.get('version')}",
                                recommended_fix=f"Upgrade {pkg_info.get('name')} to a patched version.",
                                scanner="osv-scanner",
                                confidence=95,
                                metadata={"cve_id": vuln.get("id"), "aliases": vuln.get("aliases", [])},
                            )
                        )
        return findings

    def _map_osv_severity(self, vuln: dict) -> Severity:
        db_specific = vuln.get("database_specific", {})
        severity_str = db_specific.get("severity", "").upper()
        if "CRITICAL" in severity_str:
            return Severity.CRITICAL
        if "HIGH" in severity_str:
            return Severity.HIGH
        return Severity.HIGH

    def _basic_check(self, context: ScanContext) -> list[Finding]:
        """Fallback when OSV scanner is unavailable."""
        findings: list[Finding] = []
        known_bad = {
            "django": ["2.0", "2.1", "2.2.0"],
            "lodash": ["4.17.20"],
            "log4j": ["2.14.0", "2.14.1"],
        }
        for dep_file in context.dependency_files:
            full_path = Path(context.repo_path) / dep_file
            if not full_path.is_file():
                continue
            content = full_path.read_text(encoding="utf-8", errors="replace")
            for pkg, bad_versions in known_bad.items():
                for version in bad_versions:
                    if pkg in content.lower() and version in content:
                        findings.append(
                            Finding(
                                file_path=dep_file,
                                line_number=1,
                                severity=Severity.HIGH,
                                category=Category.DEPENDENCY,
                                issue_type=f"Known Vulnerable Package: {pkg}",
                                message=f"Potentially vulnerable version of {pkg} detected.",
                                code_snippet=f"{pkg} {version}",
                                recommended_fix=f"Upgrade {pkg} to latest patched version.",
                                scanner="basic_dep_check",
                                confidence=70,
                            )
                        )
        return findings
