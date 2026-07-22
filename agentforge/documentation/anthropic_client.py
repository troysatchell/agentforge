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
        if not api_key:
            raise ValueError("api_key must not be empty")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._transport = transport

    def complete(self, *, system: str, user: str, max_tokens: int = 2048) -> str:
        """Send a single system/user turn and return the assistant's reply text."""
        url = f"{self._base_url}/v1/messages"
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }

        response = self._transport(url, headers, body)

        if "error" in response:
            raise AnthropicError(f"Anthropic API returned an error: {response['error']!r}")
        if "content" not in response:
            raise AnthropicError(f"Anthropic API response is missing 'content': {response!r}")

        try:
            return response["content"][0]["text"]
        except (IndexError, KeyError, TypeError) as exc:
            raise AnthropicError(f"Malformed Anthropic API response: {response!r}") from exc
