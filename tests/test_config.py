"""Tests for the env/config loader — mirrors the target's data-quality discipline
(treat ``''`` as unknown) and the locked per-layer model defaults."""

from agentforge.config import load_settings

_ALL_KEYS = [
    "MOONSHOT_API_KEY", "MOONSHOT_BASE_URL", "REDTEAM_MODEL",
    "ANTHROPIC_API_KEY", "JUDGE_MODEL", "DOC_MODEL",
    "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_HOST",
    "TARGET_BASE_URL", "TARGET_OAUTH_CLIENT_ID", "TARGET_OAUTH_CLIENT_SECRET",
]


def _clear(monkeypatch):
    for k in _ALL_KEYS:
        monkeypatch.delenv(k, raising=False)


def test_defaults_when_env_absent(monkeypatch):
    _clear(monkeypatch)
    s = load_settings(load_env=False)
    assert s.redteam_model == "kimi-k2.6"
    assert s.judge_model == "claude-sonnet-5"
    assert s.doc_model == "claude-opus-4-8"
    assert s.moonshot_base_url == "https://api.moonshot.ai/v1"
    assert s.langfuse_host == "http://localhost:3000"
    assert s.moonshot_api_key is None
    assert s.redteam_ready is False


def test_empty_string_is_treated_as_unset(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MOONSHOT_API_KEY", "")
    s = load_settings(load_env=False)
    assert s.moonshot_api_key is None  # '' -> unknown, mirrors target D1 rule
    assert s.redteam_ready is False


def test_env_overrides_are_read(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("MOONSHOT_API_KEY", "sk-test")
    monkeypatch.setenv("REDTEAM_MODEL", "kimi-k2.6-turbo")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    s = load_settings(load_env=False)
    assert s.moonshot_api_key == "sk-test"
    assert s.redteam_model == "kimi-k2.6-turbo"
    assert s.redteam_ready is True
    assert s.judge_ready is True
