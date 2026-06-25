"""Git hook installation."""

from __future__ import annotations

from pathlib import Path

HOOK_SCRIPT = """#!/bin/sh
# DevSecOps Pre-Commit Guardian Hook
# Installed by devsecops install-hook

echo "Running DevSecOps Pre-Commit Guardian..."

# Ensure Python uses UTF-8 on Windows Git Bash / cmd hooks
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8

if command -v devsecops >/dev/null 2>&1; then
    devsecops scan --hook
    exit $?
elif command -v python >/dev/null 2>&1; then
    python -m devsecops scan --hook
    exit $?
else
    echo "ERROR: devsecops not found. Install with: pip install devsecops-guardian"
    exit 1
fi
"""

PRE_COMMIT_CONFIG = """# DevSecOps Pre-Commit Guardian
repos:
  - repo: local
    hooks:
      - id: devsecops-guardian
        name: DevSecOps Pre-Commit Guardian
        entry: devsecops scan --hook
        language: system
        pass_filenames: false
        always_run: true
        stages: [pre-commit]
"""


class HookInstaller:
    """Installs git hooks and pre-commit config."""

    def __init__(self, repo_path: Path) -> None:
        self.repo_path = Path(repo_path).resolve()

    def install_git_hook(self) -> Path:
        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            raise FileNotFoundError(f"Not a git repository: {self.repo_path}")

        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-commit"
        hook_path.write_text(HOOK_SCRIPT, encoding="utf-8", newline="\n")

        try:
            hook_path.chmod(0o755)
        except OSError:
            pass

        return hook_path

    def install_pre_commit_config(self) -> Path:
        config_path = self.repo_path / ".pre-commit-config.yaml"
        if config_path.exists():
            content = config_path.read_text(encoding="utf-8")
            if "devsecops-guardian" not in content:
                content = content.rstrip() + "\n\n" + PRE_COMMIT_CONFIG
                config_path.write_text(content, encoding="utf-8")
        else:
            config_path.write_text(PRE_COMMIT_CONFIG, encoding="utf-8")
        return config_path
