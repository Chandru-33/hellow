"""PII detection scanner."""

from __future__ import annotations

import re

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner

PII_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email Address", Severity.CRITICAL),
    (r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "Phone Number", Severity.CRITICAL),
    (r"\b(?:\+?\d{1,3}[-.\s]?)?\d{10,12}\b", "Phone Number (International)", Severity.HIGH),
    (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b", "Credit Card Number", Severity.CRITICAL),
    (r"\b[A-Z]{1,2}\d{6,9}[A-Z]?\b", "Passport/Government ID", Severity.CRITICAL),
    (r"\b\d{3}-\d{2}-\d{4}\b", "SSN Pattern", Severity.CRITICAL),
    (r"\bMRN[-:]?\d{6,12}\b", "Medical Record ID", Severity.CRITICAL),
]

ALLOWLIST_DOMAINS = {"example.com", "test.com", "localhost", "example.org", "company.com"}


class PIIScanner(BaseScanner):
    name = "pii"

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for region in context.regions:
            lines = region.content.splitlines()
            offset = region.start_line - 1
            for i, line in enumerate(lines):
                line_num = offset + i + 1
                if region.changed_lines and line_num not in region.changed_lines:
                    continue
                for pattern, issue_type, severity in PII_PATTERNS:
                    for match in re.finditer(pattern, line):
                        value = match.group(0)
                        if issue_type == "Email Address" and self._is_allowlisted_email(value):
                            continue
                        if issue_type == "Credit Card Number" and not self._luhn_check(value):
                            continue
                        findings.append(
                            Finding(
                                file_path=region.file_path,
                                line_number=line_num,
                                severity=severity,
                                category=Category.PII,
                                issue_type=issue_type,
                                message=f"Potential {issue_type} found in source code.",
                                code_snippet=line.strip(),
                                recommended_fix="Remove PII from code. Use tokenization or secure storage.",
                                scanner="pii_regex",
                                confidence=88,
                            )
                        )
        return findings

    def _is_allowlisted_email(self, email: str) -> bool:
        domain = email.split("@")[-1].lower()
        return domain in ALLOWLIST_DOMAINS or email.startswith("user@") or "example" in email.lower()

    def _luhn_check(self, number: str) -> bool:
        digits = [int(d) for d in re.sub(r"\D", "", number)]
        if len(digits) < 13:
            return False
        checksum = 0
        reverse = digits[::-1]
        for i, d in enumerate(reverse):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0
