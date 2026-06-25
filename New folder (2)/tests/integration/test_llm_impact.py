"""Integration test: API key presence changes blocking behavior."""

import subprocess

import pytest

from devsecops.orchestrator import ScanOrchestrator


def test_without_api_key_pii_does_not_block(vulnerable_repo, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "true")

    orchestrator = ScanOrchestrator(vulnerable_repo)
    orchestrator.config["enable_llm"] = True
    settings = orchestrator.config["_settings"]
    settings.gemini_api_key = ""
    settings.groq_api_key = ""

    result = orchestrator.run_scan()

    assert result.llm_status == "skipped_no_api_key"
    assert result.unvalidated_count > 0

    pii_findings = [f for f in result.findings if f.category.value == "PII Detection"]
    sql_findings = [f for f in result.findings if "SQL" in f.issue_type]
    secret_findings = [f for f in result.findings if f.category.value == "Secret Detection"]

    if pii_findings:
        assert all(not f.blocks_commit for f in pii_findings)
    if sql_findings:
        assert all(not f.blocks_commit for f in sql_findings)
    if secret_findings:
        assert any(f.blocks_commit for f in secret_findings)


def test_no_llm_blocks_everything(vulnerable_repo, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "false")

    orchestrator = ScanOrchestrator(vulnerable_repo)
    orchestrator.config["enable_llm"] = False

    result = orchestrator.run_scan()

    assert result.llm_status == "disabled"
    assert result.commit_blocked is True
    assert len(result.blocking_findings()) >= 1
