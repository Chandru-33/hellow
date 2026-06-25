"""Client confidential information detection."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner


class ClientConfidentialScanner(BaseScanner):
    name = "client_confidential"

    def scan(self, context: ScanContext) -> list[Finding]:
        patterns = self._load_patterns(context)
        if not patterns:
            return []

        findings: list[Finding] = []
        for region in context.regions:
            lines = region.content.splitlines()
            offset = region.start_line - 1
            for i, line in enumerate(lines):
                line_num = offset + i + 1
                if region.changed_lines and line_num not in region.changed_lines:
                    continue
                for pattern_info in patterns:
                    if pattern_info["value"].lower() in line.lower():
                        findings.append(
                            Finding(
                                file_path=region.file_path,
                                line_number=line_num,
                                severity=Severity.HIGH,
                                category=Category.CLIENT_CONFIDENTIAL,
                                issue_type=pattern_info["type"],
                                message=f"Restricted client reference '{pattern_info['value']}' detected.",
                                code_snippet=line.strip(),
                                recommended_fix="Remove client-specific references or use configuration outside version control.",
                                scanner="client_patterns",
                                confidence=90,
                            )
                        )
                for url_pattern in patterns:
                    if url_pattern["type"] == "Internal URL" and re.search(
                        re.escape(url_pattern["value"]), line, re.IGNORECASE
                    ):
                        findings.append(
                            Finding(
                                file_path=region.file_path,
                                line_number=line_num,
                                severity=Severity.HIGH,
                                category=Category.CLIENT_CONFIDENTIAL,
                                issue_type="Internal URL",
                                message=f"Internal URL/host '{url_pattern['value']}' exposed.",
                                code_snippet=line.strip(),
                                recommended_fix="Use environment variables for internal endpoints.",
                                scanner="client_patterns",
                                confidence=88,
                            )
                        )
        return self._dedupe(findings)

    def _load_patterns(self, context: ScanContext) -> list[dict[str, str]]:
        config_mgr_patterns = context.config.get("client_patterns", [])
        patterns: list[dict[str, str]] = [
            {"value": p, "type": "Restricted Client"} for p in config_mgr_patterns
        ]

        config_path = Path(context.repo_path) / ".devsecops" / "client_patterns.yaml"
        root_path = Path(context.repo_path) / "client_patterns.yaml"
        for path in (root_path, config_path):
            if path.exists():
                with path.open(encoding="utf-8") as fh:
                    data = yaml.safe_load(fh) or {}
                for client in data.get("restricted_clients", []):
                    patterns.append({"value": str(client), "type": "Restricted Client"})
                for url in data.get("internal_urls", []):
                    patterns.append({"value": str(url), "type": "Internal URL"})
                for host in data.get("internal_hostnames", []):
                    patterns.append({"value": str(host), "type": "Internal Hostname"})
                break
        return patterns

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, int, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.issue_type + f.message)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
