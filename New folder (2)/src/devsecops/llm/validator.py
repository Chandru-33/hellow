"""LLM validation orchestration for findings."""

from __future__ import annotations

from devsecops.core.models import Finding, Severity
from devsecops.llm.providers import LLMValidator


class FindingValidator:
    """Validates findings using LLM with snippet extraction."""

    def __init__(self, validator: LLMValidator, git_analyzer) -> None:
        self.validator = validator
        self.git_analyzer = git_analyzer

    def validate_findings(self, findings: list[Finding]) -> list[Finding]:
        if not self.validator.enabled:
            return findings

        validated: list[Finding] = []
        for finding in findings:
            snippet = self.git_analyzer.extract_snippet(
                finding.file_path,
                finding.line_number,
                context=self.validator.context_lines,
            )
            if not snippet:
                snippet = finding.code_snippet

            result = self.validator.validate(
                issue_type=finding.issue_type,
                category=finding.category.value,
                code_snippet=snippet,
                scanner_message=finding.message,
            )

            if result:
                finding.llm_validated = True
                finding.llm_valid = result.valid
                finding.llm_provider = result.provider
                finding.confidence = result.confidence
                finding.metadata["validation_status"] = "confirmed" if result.valid else "rejected"
                if result.valid:
                    finding.message = result.reason or finding.message
                    if result.fix:
                        finding.recommended_fix = result.fix
                    sev = result.severity.upper()
                    if sev in Severity.__members__:
                        finding.severity = Severity[sev]
                else:
                    finding.llm_valid = False
                    finding.blocks_commit = False
            validated.append(finding)
        return validated

    def count_results(self, findings: list[Finding]) -> tuple[int, int]:
        confirmed = sum(1 for f in findings if f.llm_validated and f.llm_valid is True)
        rejected = sum(1 for f in findings if f.llm_validated and f.llm_valid is False)
        return confirmed, rejected
