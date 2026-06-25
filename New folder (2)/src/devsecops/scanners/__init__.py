"""Scanner registry and orchestration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from devsecops.core.models import Finding, ScanContext
from devsecops.scanners.base import BaseScanner
from devsecops.scanners.client_scanner import ClientConfidentialScanner
from devsecops.scanners.code_smell_scanner import CodeSmellScanner
from devsecops.scanners.dependency_scanner import DependencyScanner
from devsecops.scanners.misconfig_scanner import MisconfigurationScanner
from devsecops.scanners.pii_scanner import PIIScanner
from devsecops.scanners.secret_scanner import SecretScanner
from devsecops.scanners.vulnerability_scanner import VulnerabilityScanner

ALL_SCANNERS: list[type[BaseScanner]] = [
    SecretScanner,
    PIIScanner,
    ClientConfidentialScanner,
    VulnerabilityScanner,
    DependencyScanner,
    CodeSmellScanner,
    MisconfigurationScanner,
]


def get_scanners() -> list[BaseScanner]:
    return [cls() for cls in ALL_SCANNERS]


def run_scanners(context: ScanContext) -> list[Finding]:
    """Execute all enabled scanners, optionally in parallel."""
    scanners = [s for s in get_scanners() if s.is_enabled(context)]
    if not scanners:
        return []

    parallel = context.config.get("parallel_scanners", True)
    max_workers = context.config.get("max_workers", 4)

    if parallel and len(scanners) > 1:
        findings: list[Finding] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(s.scan, context): s.name for s in scanners}
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception:
                    pass
        return findings

    findings = []
    for scanner in scanners:
        try:
            findings.extend(scanner.scan(context))
        except Exception:
            pass
    return findings
