"""Configuration management."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_CONFIG: dict[str, Any] = {
    "block_medium": False,
    "enable_llm": True,
    "llm_provider": "gemini",
    "llm_model_gemini": "gemini-2.5-flash",
    "llm_model_groq": "llama-3.3-70b-versatile",
    "snippet_context_lines": 20,
    "parallel_scanners": True,
    "max_workers": 4,
    "scanners": {
        "secrets": True,
        "pii": True,
        "client_confidential": True,
        "vulnerabilities": True,
        "dependencies": True,
        "code_smells": True,
        "misconfigurations": True,
    },
    "external_tools": {
        "gitleaks": True,
        "trufflehog": False,
        "semgrep": True,
        "osv_scanner": True,
    },
    "ignore_patterns": [
        "*.min.js",
        "*.min.css",
        "package-lock.json",
        "yarn.lock",
        "poetry.lock",
        "*.png",
        "*.jpg",
        "*.gif",
        "*.ico",
        "*.woff",
        "*.woff2",
        "*.pdf",
        "*.zip",
        "*.tar.gz",
    ],
    "severity_block_rules": {
        "CRITICAL": True,
        "HIGH": True,
        "MEDIUM": False,
        "LOW": False,
    },
}


class Settings(BaseSettings):
    """Environment-based settings (populated after load_env_files)."""

    model_config = SettingsConfigDict(
        env_file_encoding="utf-8",
        extra="ignore",
    )

    gemini_api_key: str = Field(default="", alias="GEMINI_API_KEY")
    groq_api_key: str = Field(default="", alias="GROQ_API_KEY")
    devsecops_llm_provider: str = Field(default="gemini", alias="DEVSECOPS_LLM_PROVIDER")
    devsecops_block_medium: bool = Field(default=False, alias="DEVSECOPS_BLOCK_MEDIUM")
    devsecops_enable_llm: bool = Field(default=True, alias="DEVSECOPS_ENABLE_LLM")


def find_git_root(start: Path) -> Path:
    """Walk up from start to locate the Git repository root."""
    current = start.resolve()
    for _ in range(20):
        if (current / ".git").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return start.resolve()


def load_env_files(repo_path: Path) -> tuple[Path, list[str]]:
    """
    Load environment variables from repo root.

    Priority (later overrides earlier):
      1. .env.example  (template / local dev fallback)
      2. .env          (primary secrets file)

    Returns git root and list of loaded file names.
    """
    root = find_git_root(repo_path)
    loaded: list[str] = []

    example = root / ".env.example"
    env = root / ".env"

    if example.exists():
        load_dotenv(example, override=False)
        loaded.append(".env.example")

    if env.exists():
        load_dotenv(env, override=True)
        loaded.append(".env")

    return root, loaded


def load_settings(repo_path: Path) -> tuple[Settings, list[str]]:
    """Load settings from repo env files and process environment."""
    _, loaded_files = load_env_files(repo_path)
    settings = Settings()
    return settings, loaded_files


class ConfigManager:
    """Loads and merges YAML config with environment overrides."""

    DEVSECOPS_DIR = ".devsecops"
    CONFIG_FILE = "config.yaml"
    CLIENT_PATTERNS_FILE = "client_patterns.yaml"

    def __init__(self, repo_path: str | Path) -> None:
        self.repo_path = Path(repo_path).resolve()
        self.git_root = find_git_root(self.repo_path)
        self.devsecops_dir = self.git_root / self.DEVSECOPS_DIR
        self._loaded_env_files: list[str] = []

    def ensure_dirs(self) -> None:
        self.devsecops_dir.mkdir(parents=True, exist_ok=True)

    def load_env(self) -> list[str]:
        """Load .env / .env.example from git root. Returns loaded file names."""
        _, self._loaded_env_files = load_env_files(self.repo_path)
        return self._loaded_env_files

    def config_path(self) -> Path:
        return self.devsecops_dir / self.CONFIG_FILE

    def client_patterns_path(self) -> Path:
        root_patterns = self.git_root / "client_patterns.yaml"
        devsecops_patterns = self.devsecops_dir / self.CLIENT_PATTERNS_FILE
        if root_patterns.exists():
            return root_patterns
        return devsecops_patterns

    def load_config(self) -> dict[str, Any]:
        self.ensure_dirs()
        self.load_env()
        config = DEFAULT_CONFIG.copy()
        path = self.config_path()
        if path.exists():
            with path.open(encoding="utf-8") as fh:
                user_config = yaml.safe_load(fh) or {}
            config = _deep_merge(config, user_config)
        settings, _ = load_settings(self.repo_path)
        if settings.devsecops_block_medium:
            config["block_medium"] = True
            config["severity_block_rules"]["MEDIUM"] = True
        if not settings.devsecops_enable_llm:
            config["enable_llm"] = False
        if settings.devsecops_llm_provider:
            config["llm_provider"] = settings.devsecops_llm_provider
        config["_settings"] = settings
        config["_env_files_loaded"] = self._loaded_env_files
        config["_git_root"] = str(self.git_root)
        return config

    def save_default_config(self) -> Path:
        self.ensure_dirs()
        path = self.config_path()
        if not path.exists():
            with path.open("w", encoding="utf-8") as fh:
                yaml.dump(DEFAULT_CONFIG, fh, default_flow_style=False, sort_keys=False)
        return path

    def load_client_patterns(self) -> list[str]:
        path = self.client_patterns_path()
        if not path.exists():
            return []
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        patterns = data.get("restricted_clients", [])
        return [str(p) for p in patterns]

    def save_default_client_patterns(self) -> Path:
        path = self.devsecops_dir / self.CLIENT_PATTERNS_FILE
        self.ensure_dirs()
        if not path.exists():
            default = {
                "restricted_clients": [
                    "ClientABC",
                    "ClientXYZ",
                    "InternalCustomer",
                ],
                "internal_urls": [
                    "internal.company.com",
                    "vpn.corp.local",
                ],
                "internal_hostnames": [
                    "prod-db-internal",
                    "staging-internal",
                ],
            }
            with path.open("w", encoding="utf-8") as fh:
                yaml.dump(default, fh, default_flow_style=False, sort_keys=False)
        return path


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result
