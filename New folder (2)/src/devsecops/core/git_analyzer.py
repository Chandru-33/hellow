"""Git diff analysis for incremental scanning."""

from __future__ import annotations

import fnmatch
import subprocess
from pathlib import Path

from devsecops.core.models import CodeRegion

DEPENDENCY_FILES = {
    "requirements.txt",
    "requirements-dev.txt",
    "pyproject.toml",
    "package.json",
    "package-lock.json",
    "pom.xml",
    "go.mod",
    "go.sum",
    "Cargo.toml",
    "Cargo.lock",
    "composer.json",
    "composer.lock",
    "Gemfile",
    "Gemfile.lock",
    "build.gradle",
    "build.gradle.kts",
}


class GitAnalyzer:
    """Analyzes git state and extracts scannable code regions."""

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path).resolve()

    def is_git_repo(self) -> bool:
        return (self.repo_path / ".git").exists()

    def is_first_commit(self, has_baseline: bool) -> bool:
        if not self.is_git_repo():
            return True
        if not has_baseline:
            return True
        try:
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=False,
            )
            return result.returncode != 0
        except FileNotFoundError:
            return True

    def get_tracked_files(self) -> list[str]:
        if not self.is_git_repo():
            return self._all_files()
        result = subprocess.run(
            ["git", "ls-files"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]

    def get_staged_files(self) -> list[str]:
        if not self.is_git_repo():
            return []
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=True,
        )
        return [f.strip() for f in result.stdout.splitlines() if f.strip()]

    def get_staged_diff(self) -> str:
        result = subprocess.run(
            ["git", "diff", "--cached", "-U0"],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout

    def get_changed_line_numbers(self, file_path: str) -> set[int]:
        """Parse git diff --cached for added/modified line numbers."""
        result = subprocess.run(
            ["git", "diff", "--cached", "-U0", "--", file_path],
            cwd=self.repo_path,
            capture_output=True,
            text=True,
            check=False,
        )
        lines: set[int] = set()
        for line in result.stdout.splitlines():
            if line.startswith("@@"):
                parts = line.split("+")
                if len(parts) < 2:
                    continue
                range_part = parts[1].split(" ")[0].split(",")
                start = int(range_part[0])
                count = int(range_part[1]) if len(range_part) > 1 else 1
                for ln in range(start, start + count):
                    lines.add(ln)
        return lines

    def build_regions(
        self,
        files: list[str],
        is_first_commit: bool,
        ignore_patterns: list[str],
        context_lines: int = 0,
    ) -> tuple[list[CodeRegion], list[str]]:
        """Build code regions for scanning."""
        regions: list[CodeRegion] = []
        dependency_files: list[str] = []

        for rel_path in files:
            if self._should_ignore(rel_path, ignore_patterns):
                continue
            full_path = self.repo_path / rel_path
            if not full_path.is_file():
                continue
            if full_path.name in DEPENDENCY_FILES or full_path.suffix in {".lock"}:
                dependency_files.append(rel_path)

            try:
                content = full_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            file_lines = content.splitlines()
            if is_first_commit:
                changed_lines = list(range(1, len(file_lines) + 1))
            else:
                changed_lines = sorted(self.get_changed_line_numbers(rel_path))
                if not changed_lines:
                    continue

            if is_first_commit or context_lines == 0:
                start = 1
                end = len(file_lines)
                snippet = content
            else:
                start = max(1, min(changed_lines) - context_lines)
                end = min(len(file_lines), max(changed_lines) + context_lines)
                snippet = "\n".join(file_lines[start - 1 : end])

            regions.append(
                CodeRegion(
                    file_path=rel_path,
                    start_line=start,
                    end_line=end,
                    content=snippet,
                    changed_lines=changed_lines,
                )
            )

        return regions, dependency_files

    def _should_ignore(self, path: str, patterns: list[str]) -> bool:
        name = Path(path).name
        for pattern in patterns:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(name, pattern):
                return True
        return False

    def _all_files(self) -> list[str]:
        files: list[str] = []
        for path in self.repo_path.rglob("*"):
            if path.is_file() and ".git" not in path.parts and ".devsecops" not in path.parts:
                files.append(str(path.relative_to(self.repo_path)).replace("\\", "/"))
        return files

    def extract_snippet(
        self,
        file_path: str,
        line_number: int,
        context: int = 20,
    ) -> str:
        """Extract context lines around a finding for LLM validation."""
        full_path = self.repo_path / file_path
        if not full_path.is_file():
            return ""
        try:
            lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        numbered = []
        for i in range(start, end):
            numbered.append(f"{i + 1:4d}| {lines[i]}")
        return "\n".join(numbered)
