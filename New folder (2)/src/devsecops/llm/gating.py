"""LLM validation gating — controls which findings require AI confirmation."""

from __future__ import annotations

from devsecops.core.models import Category, Finding

# Findings that always block based on scanner alone (high-confidence patterns)
AUTO_BLOCK_CATEGORIES: frozenset[Category] = frozenset({
    Category.SECRET,
    Category.DEPENDENCY,
})

# Findings that require LLM validation before they can block a commit
LLM_REQUIRED_CATEGORIES: frozenset[Category] = frozenset({
    Category.PII,
    Category.VULNERABILITY,
    Category.CODE_SMELL,
    Category.CLIENT_CONFIDENTIAL,
    Category.MISCONFIGURATION,
})


def requires_llm_validation(finding: Finding) -> bool:
    return finding.category in LLM_REQUIRED_CATEGORIES


def apply_llm_gating(
    findings: list[Finding],
    *,
    enable_llm: bool,
    llm_available: bool,
    llm_ran: bool,
) -> tuple[list[Finding], int]:
    """
    Apply commit-blocking rules based on LLM availability.

    With API keys: only LLM-confirmed findings in required categories block.
    Without API keys: required-category findings are warnings only (secrets/deps still block).
    With --no-llm: scanner results block directly (permissive fallback).
    """
    unvalidated_count = 0

    for finding in findings:
        if finding.llm_valid is False:
            finding.blocks_commit = False
            continue

        if finding.category in AUTO_BLOCK_CATEGORIES:
            continue

        if not enable_llm:
            continue

        if finding.category not in LLM_REQUIRED_CATEGORIES:
            continue

        if llm_ran and finding.llm_validated and finding.llm_valid:
            continue

        if llm_ran and finding.llm_validated and not finding.llm_valid:
            finding.blocks_commit = False
            continue

        # LLM enabled but finding was not validated (no API key or API failure)
        finding.blocks_commit = False
        finding.confidence = min(finding.confidence, 60)
        finding.metadata["validation_status"] = "unvalidated"
        finding.metadata["requires_api_key"] = not llm_available
        finding.message = (
            f"{finding.message} "
            "[Scanner-only — add GEMINI_API_KEY or GROQ_API_KEY to .env for AI validation and commit blocking]"
        )
        unvalidated_count += 1

    return findings, unvalidated_count
