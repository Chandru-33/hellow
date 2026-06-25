"""Tests for LLM gating behavior with and without API keys."""

from devsecops.core.models import Category, Finding, Severity
from devsecops.llm.gating import apply_llm_gating, requires_llm_validation


def _finding(category: Category, issue_type: str = "Test Issue") -> Finding:
    return Finding(
        file_path="test.py",
        line_number=1,
        severity=Severity.HIGH,
        category=category,
        issue_type=issue_type,
        message="Test message",
        code_snippet="bad_code()",
    )


def test_secret_always_blocks_without_api_key():
    findings = [_finding(Category.SECRET, "AWS Access Key")]
    result, unvalidated = apply_llm_gating(
        findings, enable_llm=True, llm_available=False, llm_ran=False
    )
    assert result[0].blocks_commit is True
    assert unvalidated == 0


def test_pii_does_not_block_without_api_key():
    findings = [_finding(Category.PII, "Email Address")]
    result, unvalidated = apply_llm_gating(
        findings, enable_llm=True, llm_available=False, llm_ran=False
    )
    assert result[0].blocks_commit is False
    assert unvalidated == 1
    assert result[0].metadata["validation_status"] == "unvalidated"


def test_vulnerability_blocks_when_llm_confirms():
    finding = _finding(Category.VULNERABILITY, "SQL Injection")
    finding.llm_validated = True
    finding.llm_valid = True
    finding.llm_provider = "gemini"
    result, unvalidated = apply_llm_gating(
        [finding], enable_llm=True, llm_available=True, llm_ran=True
    )
    assert result[0].blocks_commit is True
    assert unvalidated == 0


def test_vulnerability_does_not_block_when_llm_rejects():
    finding = _finding(Category.VULNERABILITY, "SQL Injection")
    finding.llm_validated = True
    finding.llm_valid = False
    result, unvalidated = apply_llm_gating(
        [finding], enable_llm=True, llm_available=True, llm_ran=True
    )
    assert result[0].blocks_commit is False
    assert unvalidated == 0


def test_no_llm_mode_blocks_all_scanner_findings():
    findings = [_finding(Category.PII, "Email Address")]
    result, unvalidated = apply_llm_gating(
        findings, enable_llm=False, llm_available=False, llm_ran=False
    )
    assert result[0].blocks_commit is True
    assert unvalidated == 0


def test_requires_llm_validation_categories():
    assert requires_llm_validation(_finding(Category.PII)) is True
    assert requires_llm_validation(_finding(Category.SECRET)) is False
