"""InputKeyedReplayTransport — deterministic replay seam — STUB (TRO-124).

Determinism at the eval boundary comes from input-keyed replay, not temperature.
This transport keys recorded responses by a sha256 over the canonicalized request
body (sorted keys, tight separators) — the same canonicalization the Red Team uses
for ``sequence_hash`` — so an identical request always replays an identical
response, and an unrecorded request raises rather than fabricating one.

The coding agent replaces the ``NotImplementedError`` bodies.
"""

from __future__ import annotations

from typing import Any


class ReplayMiss(KeyError):
    """Raised when no recorded response exists for the given input key."""


def input_key(body: dict[str, Any]) -> str:
    """Deterministic, order-insensitive key for a request body."""
    raise NotImplementedError


class InputKeyedReplayTransport:
    """Callable transport that replays recorded responses by input key."""

    def __init__(self, recordings: dict[str, dict[str, Any]]) -> None:
        self._recordings = recordings

    def __call__(
        self, url: str, headers: dict[str, Any], body: dict[str, Any]
    ) -> dict[str, Any]:
        raise NotImplementedError
