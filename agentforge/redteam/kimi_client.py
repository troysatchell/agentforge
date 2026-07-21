"""Kimi client (T3 / TRO-135) — Moonshot OpenAI-compatible chat client.

A thin wrapper over Moonshot's ``/chat/completions`` endpoint. The HTTP
transport is INJECTED rather than owned by this client, so it can be
exercised in tests without touching the network: callers pass a callable
``transport(url, headers, json_body) -> dict`` that performs the actual
request and returns the parsed JSON response. The real transport (e.g. a
``requests``-backed one) is wired up elsewhere.
"""

from __future__ import annotations

from typing import Any, Callable

Transport = Callable[[str, dict[str, Any], dict[str, Any]], dict[str, Any]]


class KimiError(Exception):
    """Raised when the Moonshot API returns an error or an unusable response."""


class KimiClient:
    """Minimal OpenAI-compatible chat client for Moonshot's Kimi models."""

    def __init__(self, *, api_key: str, base_url: str, model: str, transport: Transport) -> None:
        if not api_key:
            raise ValueError("api_key must not be empty")
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._transport = transport

    def complete(
        self,
        *,
        system: str,
        user: str,
        response_format: dict[str, Any] | None = None,
        temperature: float | None = None,
    ) -> str:
        """Send a single system/user turn and return the assistant's reply text."""
        url = f"{self._base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        body: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        if response_format is not None:
            body["response_format"] = response_format
        if temperature is not None:
            body["temperature"] = temperature

        response = self._transport(url, headers, body)

        if "error" in response:
            raise KimiError(f"Moonshot API returned an error: {response['error']!r}")
        if "choices" not in response:
            raise KimiError(f"Moonshot API response is missing 'choices': {response!r}")

        try:
            return response["choices"][0]["message"]["content"]
        except (IndexError, KeyError, TypeError) as exc:
            raise KimiError(f"Malformed Moonshot API response: {response!r}") from exc
