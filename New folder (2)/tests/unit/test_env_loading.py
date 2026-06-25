"""Tests for environment file loading."""

from devsecops.core.config import ConfigManager, load_env_files, load_settings


def test_loads_gemini_key_from_env_example(tmp_path):
    env_example = tmp_path / ".env.example"
    env_example.write_text("GEMINI_API_KEY=test-gemini-key-12345\n", encoding="utf-8")

    loaded = load_env_files(tmp_path)
    settings, files = load_settings(tmp_path)

    assert ".env.example" in loaded[1]
    assert settings.gemini_api_key == "test-gemini-key-12345"


def test_env_overrides_env_example(tmp_path):
    (tmp_path / ".env.example").write_text("GEMINI_API_KEY=from-example\n", encoding="utf-8")
    (tmp_path / ".env").write_text("GEMINI_API_KEY=from-env\n", encoding="utf-8")

    settings, _ = load_settings(tmp_path)
    assert settings.gemini_api_key == "from-env"


def test_config_manager_reports_loaded_files(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    (tmp_path / ".env.example").write_text("GEMINI_API_KEY=abc123\n", encoding="utf-8")
    mgr = ConfigManager(tmp_path)
    config = mgr.load_config()
    assert ".env.example" in config["_env_files_loaded"]
    assert config["_settings"].gemini_api_key == "abc123"
