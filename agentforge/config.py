"""Environment/config loader.

Keys live in env vars only (never hardcoded, never in a prompt or trace) — read
via :func:`load_settings`. Mirrors the target's data-quality discipline: an empty
string is treated as *unknown*, not as a value.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

_REPO_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Settings:
    """Resolved platform configuration. Per-layer model defaults are the locked
    D3 choices (Kimi K2.6 Red Team · Sonnet 5 Judge · Opus 4.8 Documentation)."""

    moonshot_api_key: str | None
    moonshot_base_url: str
    redteam_model: str
    anthropic_api_key: str | None
    judge_model: str
    doc_model: str
    langfuse_public_key: str | None
    langfuse_secret_key: str | None
    langfuse_host: str
    target_base_url: str | None
    target_oauth_client_id: str | None
    target_oauth_client_secret: str | None

    @property
    def redteam_ready(self) -> bool:
        return self.moonshot_api_key is not None

    @property
    def judge_ready(self) -> bool:
        return self.anthropic_api_key is not None

    @property
    def documentation_ready(self) -> bool:
        return self.anthropic_api_key is not None


def _opt(key: str) -> str | None:
    """Read an optional var; ``''`` and missing both resolve to ``None``."""
    value = os.getenv(key)
    return value if value else None


def _req(key: str, default: str) -> str:
    """Read a var that always resolves to a value (default when unset/empty)."""
    value = os.getenv(key)
    return value if value else default


def load_settings(
    env_file: str | os.PathLike[str] | None = None,
    *,
    load_env: bool = True,
) -> Settings:
    """Build :class:`Settings` from the environment.

    ``load_env`` reads a ``.env`` file first (repo-root ``.env`` by default);
    pass ``load_env=False`` in tests to read only the process environment.
    """
    if load_env:
        load_dotenv(env_file if env_file is not None else _REPO_ROOT / ".env", override=False)
    return Settings(
        moonshot_api_key=_opt("MOONSHOT_API_KEY"),
        moonshot_base_url=_req("MOONSHOT_BASE_URL", "https://api.moonshot.ai/v1"),
        redteam_model=_req("REDTEAM_MODEL", "kimi-k2.6"),
        anthropic_api_key=_opt("ANTHROPIC_API_KEY"),
        judge_model=_req("JUDGE_MODEL", "claude-sonnet-5"),
        doc_model=_req("DOC_MODEL", "claude-opus-4-8"),
        langfuse_public_key=_opt("LANGFUSE_PUBLIC_KEY"),
        langfuse_secret_key=_opt("LANGFUSE_SECRET_KEY"),
        langfuse_host=_req("LANGFUSE_HOST", "http://localhost:3000"),
        target_base_url=_opt("TARGET_BASE_URL"),
        target_oauth_client_id=_opt("TARGET_OAUTH_CLIENT_ID"),
        target_oauth_client_secret=_opt("TARGET_OAUTH_CLIENT_SECRET"),
    )
