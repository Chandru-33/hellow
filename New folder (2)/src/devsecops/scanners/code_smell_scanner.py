"""Code smell detection."""

from __future__ import annotations

import re

from devsecops.core.models import Category, Finding, ScanContext, Severity
from devsecops.scanners.base import BaseScanner


class CodeSmellScanner(BaseScanner):
    name = "code_smells"

    MAX_FUNCTION_LINES = 80
    MAX_COMPLEXITY_INDICATORS = 8

    def scan(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        block_medium = context.config.get("block_medium", False)

        for region in context.regions:
            lines = region.content.splitlines()
            offset = region.start_line - 1

            for i, line in enumerate(lines):
                line_num = offset + i + 1
                if region.changed_lines and line_num not in region.changed_lines:
                    continue

                if re.search(r"\b(?:print|console\.log|debugger|pdb\.set_trace)\s*\(", line):
                    findings.append(
                        Finding(
                            file_path=region.file_path,
                            line_number=line_num,
                            severity=Severity.MEDIUM,
                            category=Category.CODE_SMELL,
                            issue_type="Debug Statement",
                            message="Debug statement found in code.",
                            code_snippet=line.strip(),
                            recommended_fix="Remove debug statements before committing.",
                            scanner="code_smell",
                            confidence=95,
                            blocks_commit=block_medium,
                        )
                    )

                if re.search(r"#.*(?:password|secret|api_key|token)\s*=", line, re.IGNORECASE):
                    findings.append(
                        Finding(
                            file_path=region.file_path,
                            line_number=line_num,
                            severity=Severity.HIGH,
                            category=Category.CODE_SMELL,
                            issue_type="Commented Secret",
                            message="Commented-out credential detected.",
                            code_snippet=line.strip(),
                            recommended_fix="Remove commented secrets entirely from source.",
                            scanner="code_smell",
                            confidence=85,
                        )
                    )

                if re.search(r"\b(?:password|secret|api_key)\s*=\s*['\"][^'\"]+['\"]", line, re.IGNORECASE):
                    if "#" not in line.split("=")[0]:
                        pass  # handled by secret scanner

            findings.extend(self._check_long_functions(region))

        return findings

    def _check_long_functions(self, region) -> list[Finding]:
        findings: list[Finding] = []
        func_pattern = re.compile(
            r"^\s*(?:def|function|func|public|private|protected|async\s+function)\s+(\w+)"
        )
        lines = region.content.splitlines()
        offset = region.start_line - 1
        i = 0
        while i < len(lines):
            match = func_pattern.match(lines[i])
            if match:
                func_name = match.group(1)
                func_start = offset + i + 1
                brace_count = 0
                func_lines = 1
                j = i + 1
                while j < len(lines) and func_lines < self.MAX_FUNCTION_LINES + 5:
                    if "{" in lines[j]:
                        brace_count += lines[j].count("{") - lines[j].count("}")
                    func_lines += 1
                    if func_pattern.match(lines[j]) and j > i + 1:
                        func_lines -= 1
                        break
                    if brace_count <= 0 and j > i + 2 and lines[j].strip() == "":
                        break
                    j += 1
                if func_lines > self.MAX_FUNCTION_LINES:
                    if not region.changed_lines or any(
                        func_start <= ln <= func_start + func_lines for ln in region.changed_lines
                    ):
                        findings.append(
                            Finding(
                                file_path=region.file_path,
                                line_number=func_start,
                                severity=Severity.MEDIUM,
                                category=Category.CODE_SMELL,
                                issue_type="Very Long Function",
                                message=f"Function '{func_name}' exceeds {self.MAX_FUNCTION_LINES} lines.",
                                code_snippet=lines[i].strip(),
                                recommended_fix="Break function into smaller, focused units.",
                                scanner="code_smell",
                                confidence=75,
                                blocks_commit=False,
                            )
                        )
                i = j
            else:
                i += 1
        return findings
