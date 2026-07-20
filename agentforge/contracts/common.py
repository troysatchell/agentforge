"""Shared contract models — mirrors ``common.schema.json`` ``$defs``.

Every message contract references these. ``StrictModel`` (``extra='forbid'``) is
the Python analogue of ``additionalProperties: false`` and is the base class
every contract model should inherit.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict


class AttackCategory(str, Enum):
    """The canonical six Week-3 Stage-2 threat categories.

    OWASP ids never live here — they belong in :class:`OwaspMapping`.
    """

    PROMPT_INJECTION = "prompt_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    STATE_CORRUPTION = "state_corruption"
    TOOL_MISUSE = "tool_misuse"
    DENIAL_OF_SERVICE = "denial_of_service"
    IDENTITY_ROLE_EXPLOITATION = "identity_role_exploitation"


class StrictModel(BaseModel):
    """Base model that rejects unknown fields (``additionalProperties: false``)."""

    model_config = ConfigDict(extra="forbid")


class OwaspMapping(StrictModel):
    """OWASP dual-Top-10 mapping. Both keys required; either value may be null."""

    web: str | None
    llm: str | None


class OracleResult(StrictModel):
    """One deterministic oracle's observation. Generic by design — a new finding
    class adds a new ``oracle_id`` string, never a new field."""

    oracle_id: str
    fired: bool | None
    evidence: str | None = None
