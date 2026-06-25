"""Unit tests for secret scanner."""

from devsecops.core.models import ScanContext
from devsecops.scanners.secret_scanner import SecretScanner, shannon_entropy


def test_detects_aws_key(sample_scan_context, vulnerable_auth_file):
    scanner = SecretScanner()
    findings = scanner.scan(sample_scan_context)
    issue_types = {f.issue_type for f in findings}
    assert any("AWS" in t or "Credential" in t or "Secret" in t for t in issue_types)


def test_detects_github_token():
    from devsecops.core.models import CodeRegion

    context = ScanContext(
        repo_path=".",
        is_first_commit=True,
        regions=[
            CodeRegion(
                file_path="test.py",
                start_line=1,
                end_line=1,
                content='token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234"',
                changed_lines=[1],
            )
        ],
        config={"scanners": {"secrets": True}, "external_tools": {"gitleaks": False}},
    )
    scanner = SecretScanner()
    findings = scanner.scan(context)
    assert len(findings) >= 1
    assert any("GitHub" in f.issue_type for f in findings)


def test_entropy_calculation():
    assert shannon_entropy("aaaaaaaaaa") < shannon_entropy("aB3$x9!kL2@mN7")


def test_ignores_placeholders():
    from devsecops.core.models import CodeRegion

    context = ScanContext(
        repo_path=".",
        is_first_commit=True,
        regions=[
            CodeRegion(
                file_path="test.py",
                start_line=1,
                end_line=1,
                content='password = "changeme"',
                changed_lines=[1],
            )
        ],
        config={"scanners": {"secrets": True}, "external_tools": {"gitleaks": False, "trufflehog": False}},
    )
    scanner = SecretScanner()
    findings = scanner.scan(context)
    assert len(findings) == 0
