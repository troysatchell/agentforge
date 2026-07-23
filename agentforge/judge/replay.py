"""InputKeyedReplayTransport — deterministic replay seam — STUB (TRO-124).

Determinism at the eval boundary comes from input-keyed replay, not temperature.
This transport keys recorded responses by a sha256 over the canonicalized request
body (sorted keys, tight separators) — the same canonicalization the Red Team uses
for ``sequence_hash`` — so an identical request always replays an identical
response, and an unrecorded request raises rather than fabricating one.

The coding agent replaces the ``NotImplementedError`` bodies.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from typing import Any


class ReplayMiss(KeyError):
    """Raised when no recorded response exists for the given input key."""


def input_key(body: dict[str, Any]) -> str:
    """Deterministic, order-insensitive key for a request body.

    A sha256 over the canonical JSON of ``body`` (sorted keys, tight
    separators) — the same canonicalization the Red Team uses for
    ``sequence_hash`` — so the key is independent of dict insertion order.
    """
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class InputKeyedReplayTransport:
    """Callable transport that replays recorded responses by input key."""

    def __init__(self, recordings: dict[str, dict[str, Any]]) -> None:
        # Snapshot at construction so a later mutation of the caller's dict
        # can't change what we replay — determinism is the whole point.
        self._recordings = deepcopy(recordings)

    def __call__(
        self, url: str, headers: dict[str, Any], body: dict[str, Any]
    ) -> dict[str, Any]:
        key = input_key(body)
        try:
            # Return a copy so a caller mutating the response can't corrupt a
            # later identical replay.
            return deepcopy(self._recordings[key])
        except KeyError as exc:
            raise ReplayMiss(key) from exc
