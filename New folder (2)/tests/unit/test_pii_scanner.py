"""Unit tests for PII scanner."""

from devsecops.core.models import CodeRegion, ScanContext
from devsecops.scanners.pii_scanner import PIIScanner


def test_detects_email():
    context = ScanContext(
        repo_path=".",
        is_first_commit=True,
        regions=[
            CodeRegion(
                file_path="data.py",
                start_line=1,
                end_line=1,
                content='email = "john.doe@gmail.com"',
                changed_lines=[1],
            )
        ],
        config={"scanners": {"pii": True}},
    )
    scanner = PIIScanner()
    findings = scanner.scan(context)
    assert len(findings) >= 1
    assert any("Email" in f.issue_type for f in findings)


def test_ignores_example_email():
    context = ScanContext(
        repo_path=".",
        is_first_commit=True,
        regions=[
            CodeRegion(
                file_path="data.py",
                start_line=1,
                end_line=1,
                content='email = "user@example.com"',
                changed_lines=[1],
            )
        ],
        config={"scanners": {"pii": True}},
    )
    scanner = PIIScanner()
    findings = scanner.scan(context)
    assert len(findings) == 0


def test_detects_credit_card():
    context = ScanContext(
        repo_path=".",
        is_first_commit=True,
        regions=[
            CodeRegion(
                file_path="payment.py",
                start_line=1,
                end_line=1,
                content='card = "4111111111111111"',
                changed_lines=[1],
            )
        ],
        config={"scanners": {"pii": True}},
    )
    scanner = PIIScanner()
    findings = scanner.scan(context)
    assert len(findings) >= 1
