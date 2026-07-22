"""Anthropic Messages client (Opus 4.8 for Documentation) — STUB (TRO-126).

Thin wrapper over Anthropic's ``/v1/messages`` endpoint, mirroring the injected-
transport pattern in ``agentforge.redteam.kimi_client``: the caller passes a
``transport(url, headers, json_body) -> dict`` so it can be exercised without the
network. The coding agent replaces the ``NotImplementedError`` bodies.
"""

from __future__ import annotations

from typing import Any, Callable

Transport = Callable[[str, dict[str, Any], dict[str, Any]], dict[str, Any]]


class AnthropicError(Exception):
    """Raised when the Anthropic API returns an error or an unusable response."""


class AnthropicClient:
    """Minimal Anthropic Messages client (single system+user turn -> text)."""

    def __init__(self, *, api_key: str, base_url: str, model: str, transport: Transport) -> None:
        self._api_key = api_key
        self._base_url = base_url
        self._model = model
        self._transport = transport

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> str:
        raise NotImplementedError
