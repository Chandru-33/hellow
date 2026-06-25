"""Domain models for scan findings and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @classmethod
    def from_string(cls, value: str) -> Severity:
        normalized = value.upper().strip()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.MEDIUM


class Category(str, Enum):
    SECRET = "Secret Detection"
    PII = "PII Detection"
    CLIENT_CONFIDENTIAL = "Client Confidential Information"
    VULNERABILITY = "Security Vulnerability"
    DEPENDENCY = "Dependency Vulnerability"
    CODE_SMELL = "Code Smell"
    MISCONFIGURATION = "Security Misconfiguration"


@dataclass
class CodeRegion:
    """A region of code to analyze (file + line range + content)."""

    file_path: str
    start_line: int
    end_line: int
    content: str
    changed_lines: list[int] = field(default_factory=list)


@dataclass
class Finding:
    """A single security or quality finding."""

    file_path: str
    line_number: int
    severity: Severity
    category: Category
    issue_type: str
    message: str
    code_snippet: str
    recommended_fix: str = ""
    scanner: str = "builtin"
    confidence: int = 100
    llm_validated: bool = False
    llm_valid: bool | None = None
    llm_provider: str = ""
    fingerprint: str = ""
    blocks_commit: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "severity": self.severity.value,
            "category": self.category.value,
            "issue_type": self.issue_type,
            "message": self.message,
            "code_snippet": self.code_snippet,
            "recommended_fix": self.recommended_fix,
            "scanner": self.scanner,
            "confidence": self.confidence,
            "llm_validated": self.llm_validated,
            "llm_valid": self.llm_valid,
            "llm_provider": self.llm_provider,
            "fingerprint": self.fingerprint,
            "blocks_commit": self.blocks_commit,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            file_path=data["file_path"],
            line_number=data["line_number"],
            severity=Severity.from_string(data["severity"]),
            category=Category(data["category"]),
            issue_type=data["issue_type"],
            message=data["message"],
            code_snippet=data.get("code_snippet", ""),
            recommended_fix=data.get("recommended_fix", ""),
            scanner=data.get("scanner", "builtin"),
            confidence=data.get("confidence", 100),
            llm_validated=data.get("llm_validated", False),
            llm_valid=data.get("llm_valid"),
            llm_provider=data.get("llm_provider", ""),
            fingerprint=data.get("fingerprint", ""),
            blocks_commit=data.get("blocks_commit", True),
            metadata=data.get("metadata", {}),
        )


@dataclass
class ScanContext:
    """Context passed to scanners."""

    repo_path: str
    is_first_commit: bool
    regions: list[CodeRegion]
    dependency_files: list[str] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Aggregated scan output."""

    findings: list[Finding] = field(default_factory=list)
    scan_id: str = ""
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    duration_seconds: float = 0.0
    files_scanned: int = 0
    is_first_commit: bool = False
    commit_blocked: bool = False
    block_reason: str = ""
    llm_status: str = "disabled"
    llm_provider: str = ""
    llm_validated_count: int = 0
    llm_rejected_count: int = 0
    unvalidated_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "files_scanned": self.files_scanned,
            "is_first_commit": self.is_first_commit,
            "commit_blocked": self.commit_blocked,
            "block_reason": self.block_reason,
            "llm_status": self.llm_status,
            "llm_provider": self.llm_provider,
            "llm_validated_count": self.llm_validated_count,
            "llm_rejected_count": self.llm_rejected_count,
            "unvalidated_count": self.unvalidated_count,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            if finding.llm_valid is False:
                continue
            key = finding.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def blocking_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.blocks_commit and f.llm_valid is not False]

    def unvalidated_findings(self) -> list[Finding]:
        return [
            f for f in self.findings
            if f.metadata.get("validation_status") == "unvalidated"
        ]

    def llm_confirmed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.llm_validated and f.llm_valid is True]
