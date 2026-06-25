"""Integration tests for full scan workflow."""

import subprocess
from pathlib import Path

import pytest

from devsecops.orchestrator import ScanOrchestrator


def test_scan_vulnerable_repo(vulnerable_repo, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "false")
    orchestrator = ScanOrchestrator(vulnerable_repo)
    orchestrator.config["enable_llm"] = False
    result = orchestrator.run_scan()
    assert result.files_scanned >= 1
    assert len(result.findings) >= 1
    assert result.commit_blocked is True


def test_first_commit_scans_all(vulnerable_repo, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "false")
    orchestrator = ScanOrchestrator(vulnerable_repo)
    orchestrator.config["enable_llm"] = False
    result = orchestrator.run_scan()
    assert result.is_first_commit is True


def test_incremental_scan_staged_only(vulnerable_repo, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "false")

    orchestrator = ScanOrchestrator(vulnerable_repo)
    orchestrator.config["enable_llm"] = False
    orchestrator.run_scan()

    # Establish git history so subsequent scans use incremental mode
    subprocess.run(
        ["git", "commit", "--no-verify", "-m", "initial"],
        cwd=vulnerable_repo,
        check=True,
        capture_output=True,
    )

    safe_file = vulnerable_repo / "safe.py"
    safe_file.write_text("def hello():\n    return 'world'\n", encoding="utf-8")
    subprocess.run(["git", "add", "safe.py"], cwd=vulnerable_repo, check=True)

    result = orchestrator.run_scan()
    assert result.is_first_commit is False
    safe_findings = [f for f in result.findings if f.file_path == "safe.py"]
    assert len(safe_findings) == 0


def test_cli_scan_command(vulnerable_repo, monkeypatch):
    monkeypatch.setenv("DEVSECOPS_ENABLE_LLM", "false")
    result = subprocess.run(
        ["python", "-m", "devsecops", "scan", "--no-llm"],
        cwd=vulnerable_repo,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1  # blocked due to findings
