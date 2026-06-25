"""Secret detection via regex, entropy, and external tools."""

from __future__ import annotations

import math
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner

SECRET_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*['\"]?([A-Z0-9]{16,20})['\"]?", "AWS Access Key", Severity.CRITICAL),
    (r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", "AWS Secret Key", Severity.CRITICAL),
    (r"(?i)(AZURE[_-]?(?:CLIENT[_-]?SECRET|TENANT[_-]?ID|SUBSCRIPTION[_-]?ID))\s*[:=]\s*['\"]?([^'\"\s]{8,})['\"]?", "Azure Credential", Severity.CRITICAL),
    (r"(?i)(?:AIza[0-9A-Za-z\-_]{35})", "GCP API Key", Severity.CRITICAL),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token", Severity.CRITICAL),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth Token", Severity.CRITICAL),
    (r"glpat-[A-Za-z0-9\-_]{20,}", "GitLab Personal Access Token", Severity.CRITICAL),
    (r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}", "OpenAI API Key", Severity.CRITICAL),
    (r"(?i)(?:gemini[_-]?api[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})['\"]?", "Gemini API Key", Severity.CRITICAL),
    (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key", Severity.CRITICAL),
    (r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?token|bearer)\s*[:=]\s*['\"]([^'\"]{4,})['\"]", "Hardcoded Credential", Severity.CRITICAL),
    (r"(?i)(?:mongodb|mysql|postgres(?:ql)?|redis)://[^\s'\"]+:[^\s'\"@]+@", "Database Connection String", Severity.CRITICAL),
    (r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*", "JWT Token", Severity.HIGH),
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer Token", Severity.HIGH),
]

GENERIC_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(password|secret|api_key|apikey|token|credential)\s*=\s*['\"]([^'\"]{8,})['\"]"
)


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


class SecretScanner(BaseScanner):
    name = "secrets"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region in context.regions:
            findings.extend(self._scan_region(region))
        if context.config.get("external_tools", {}).get("gitleaks", True):
            findings.extend(self._run_gitleaks(context))
        if context.config.get("external_tools", {}).get("trufflehog", False):
            findings.extend(self._run_trufflehog(context))
        return self._dedupe(findings)

    def _scan_region(self, region) -> list[Finding]:
        findings: list[Finding] = []
        lines = region.content.splitlines()
        offset = region.start_line - 1

        for i, line in enumerate(lines):
            line_num = offset + i + 1
            if region.changed_lines and line_num not in region.changed_lines:
                continue

            for pattern, issue_type, severity in SECRET_PATTERNS:
                for match in re.finditer(pattern, line):
                    snippet = match.group(0)
                    if self._is_placeholder(snippet):
                        continue
                    findings.append(
                        Finding(
                            file_path=region.file_path,
                            line_number=line_num,
                            severity=severity,
                            category=Category.SECRET,
                            issue_type=issue_type,
                            message=f"Potential {issue_type} detected in code.",
                            code_snippet=line.strip(),
                            recommended_fix="Remove the secret and use environment variables or a secrets manager.",
                            scanner="regex",
                            confidence=90,
                        )
                    )

            for match in GENERIC_SECRET_ASSIGNMENT.finditer(line):
                value = match.group(2)
                if self._is_placeholder(value) or value.lower() in {"changeme", "password", "secret", "xxx"}:
                    continue
                if shannon_entropy(value) > 3.5 and len(value) >= 12:
                    findings.append(
                        Finding(
                            file_path=region.file_path,
                            line_number=line_num,
                            severity=Severity.CRITICAL,
                            category=Category.SECRET,
                            issue_type="High-Entropy Secret",
                            message="High-entropy string assigned to credential variable.",
                            code_snippet=line.strip(),
                            recommended_fix="Store credentials in environment variables or a vault.",
                            scanner="entropy",
                            confidence=85,
                        )
                    )
        return findings

    def _is_placeholder(self, value: str) -> bool:
        placeholders = {
            "your_api_key_here",
            "xxxxxxxx",
            "changeme",
            "placeholder",
            "example",
            "redacted",
            "<secret>",
            "${",
            "process.env",
            "os.environ",
        }
        lower = value.lower()
        return any(p in lower for p in placeholders)

    def _run_gitleaks(self, context: ScanContext) -> list[Finding]:
        if not shutil.which("gitleaks"):
            return []
        findings: list[Finding] = []
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name
        try:
            files = [context.repo_path / r.file_path for r in context.regions]
            for file_path in files:
                if not file_path.is_file():
                    continue
                subprocess.run(
                    [
                        "gitleaks", "detect",
                        "--source", str(file_path),
                        "--report-path", report_path,
                        "--report-format", "json",
                        "--no-banner",
                    ],
                    capture_output=True,
                    check=False,
                )
                findings.extend(self._parse_gitleaks_report(report_path, context.repo_path))
        finally:
            Path(report_path).unlink(missing_ok=True)
        return findings

    def _parse_gitleaks_report(self, report_path: str, repo_path: Path) -> list[Finding]:
        import json

        path = Path(report_path)
        if not path.exists() or path.stat().st_size == 0:
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []
        findings: list[Finding] = []
        for item in data if isinstance(data, list) else []:
            file_path = item.get("File", "")
            try:
                rel = str(Path(file_path).relative_to(repo_path)).replace("\\", "/")
            except ValueError:
                rel = file_path
            findings.append(
                Finding(
                    file_path=rel,
                    line_number=item.get("StartLine", 1),
                    severity=Severity.CRITICAL,
                    category=Category.SECRET,
                    issue_type=item.get("RuleID", "Gitleaks Secret"),
                    message=item.get("Description", "Secret detected by Gitleaks."),
                    code_snippet=item.get("Match", ""),
                    recommended_fix="Rotate the exposed secret and remove it from source code.",
                    scanner="gitleaks",
                    confidence=95,
                )
            )
        return findings

    def _run_trufflehog(self, context: ScanContext) -> list[Finding]:
        if not shutil.which("trufflehog"):
            return []
        findings: list[Finding] = []
        for region in context.regions:
            file_path = context.repo_path / region.file_path
            if not file_path.is_file():
                continue
            result = subprocess.run(
                ["trufflehog", "filesystem", str(file_path), "--json"],
                capture_output=True,
                text=True,
                check=False,
            )
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                import json
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                findings.append(
                    Finding(
                        file_path=region.file_path,
                        line_number=item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("line", 1),
                        severity=Severity.CRITICAL,
                        category=Category.SECRET,
                        issue_type="Trufflehog Secret",
                        message=item.get("DetectorName", "Secret detected"),
                        code_snippet=item.get("Raw", "")[:200],
                        recommended_fix="Remove and rotate the exposed credential.",
                        scanner="trufflehog",
                        confidence=92,
                    )
                )
        return findings

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, int, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.file_path, f.line_number, f.issue_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
