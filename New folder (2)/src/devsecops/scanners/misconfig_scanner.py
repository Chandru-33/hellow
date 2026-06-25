"""Security misconfiguration detection."""

from __future__ import annotations

import re

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner

MISCONFIG_PATTERNS: list[tuple[str, str, Severity, str, str | None]] = [
    (
        r"(?i)(?:Access-Control-Allow-Origin|cors)\s*[:=]\s*['\"]?\*['\"]?",
        "CORS Allow Any Origin",
        Severity.HIGH,
        "Restrict CORS to specific trusted origins.",
        None,
    ),
    (
        r"(?i)(?:public-read|public_read|acl\s*=\s*['\"]public-read['\"])",
        "Public Storage Bucket",
        Severity.HIGH,
        "Use private ACLs and signed URLs for object storage.",
        None,
    ),
    (
        r"chmod\s+777|0o777|mode\s*=\s*0o777",
        "Overly Permissive File Permissions",
        Severity.HIGH,
        "Use least-privilege file permissions (e.g., 644 or 755).",
        None,
    ),
    (
        r"(?i)(?:anonymous|public)\s*[:=]\s*true",
        "Anonymous Access Enabled",
        Severity.HIGH,
        "Disable anonymous access; require authentication.",
        None,
    ),
    (
        r"(?i)(?:ssl[_-]?verify|verify_ssl)\s*[:=]\s*false",
        "Weak TLS Configuration",
        Severity.HIGH,
        "Enable TLS certificate verification.",
        None,
    ),
    (
        r"(?i)(?:allow_unauthenticated|skip_auth|no_auth)\s*[:=]\s*true",
        "Missing Authentication",
        Severity.HIGH,
        "Require authentication for all protected endpoints.",
        None,
    ),
    (
        r"(?i)(?:max[_-]?upload|file[_-]?size)\s*[:=]\s*\d{9,}",
        "Insecure Upload Configuration",
        Severity.MEDIUM,
        "Set reasonable upload size limits and validate file types.",
        None,
    ),
    (
        r"(?i)privileged\s*:\s*true",
        "Privileged Container",
        Severity.HIGH,
        "Run containers without privileged mode.",
        r"\.ya?ml$|Dockerfile|docker-compose",
    ),
    (
        r"(?i)hostNetwork\s*:\s*true",
        "Host Network Mode",
        Severity.HIGH,
        "Avoid hostNetwork in Kubernetes unless absolutely required.",
        r"\.ya?ml$",
    ),
]


class MisconfigurationScanner(BaseScanner):
    name = "misconfigurations"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region in context.regions:
            lines = region.content.splitlines()
            offset = region.start_line - 1
            for i, line in enumerate(lines):
                line_num = offset + i + 1
                if region.changed_lines and line_num not in region.changed_lines:
                    continue
                for pattern, issue_type, severity, fix, file_filter in MISCONFIG_PATTERNS:
                    if file_filter and not re.search(file_filter, region.file_path, re.IGNORECASE):
                        continue
                    if re.search(pattern, line):
                        findings.append(
                            Finding(
                                file_path=region.file_path,
                                line_number=line_num,
                                severity=severity,
                                category=Category.MISCONFIGURATION,
                                issue_type=issue_type,
                                message=f"Security misconfiguration: {issue_type}.",
                                code_snippet=line.strip(),
                                recommended_fix=fix,
                                scanner="misconfig",
                                confidence=88,
                            )
                        )
        return findings
