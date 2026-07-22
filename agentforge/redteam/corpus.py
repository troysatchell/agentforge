"""RT3 / TRO-123 — seed-corpus ingestion (Garak/PyRIT converters).

Normalizes external red-team seed records (Garak reports, PyRIT datasets) into
the platform's category-tagged ``SeedAttack`` shape: each record becomes a
single-turn ``InputTurn`` sequence hard-mapped into the closed six-category set
(:class:`AttackCategory`), ready to be assembled into a schema-valid
``AttackResult`` (contract edge ③). Records with no prompt text, or with a
probe/harm label that can't be mapped into the closed set, are rejected loudly
with :class:`CorpusError` rather than silently dropped or mis-categorized.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Literal

from agentforge.contracts.common import AttackCategory
from agentforge.contracts.result import InputTurn


class CorpusError(Exception):
    """Raised when a seed record can't be normalized (missing prompt text, or a
    probe/harm label that doesn't map into the closed attack-category set)."""


@dataclass
class SeedAttack:
    attack_category: AttackCategory
    input_sequence: list[InputTurn]
    provenance: str


# Garak probe modules -> closed six-category set, keyed by the LEADING dotted
# segment of ``probe_classname`` (e.g. "promptinject.HijackHateHumans" ->
# "promptinject"). Grouped by intent, not by the exact upstream taxonomy, so
# related probes land in the same platform category.
_GARAK_MODULE_TO_CATEGORY: dict[str, AttackCategory] = {
    # Injection-style probes.
    "promptinject": AttackCategory.PROMPT_INJECTION,
    "latentinjection": AttackCategory.PROMPT_INJECTION,
    "encoding": AttackCategory.PROMPT_INJECTION,
    "injection": AttackCategory.PROMPT_INJECTION,
    "goodside": AttackCategory.PROMPT_INJECTION,
    "suffix": AttackCategory.PROMPT_INJECTION,
    "visual_jailbreak": AttackCategory.PROMPT_INJECTION,
    # Data-leak / exfiltration probes.
    "leakreplay": AttackCategory.DATA_EXFILTRATION,
    "xss": AttackCategory.DATA_EXFILTRATION,
    "leak": AttackCategory.DATA_EXFILTRATION,
    "exfil": AttackCategory.DATA_EXFILTRATION,
    "divergence": AttackCategory.DATA_EXFILTRATION,
    "replay": AttackCategory.DATA_EXFILTRATION,
    # Jailbreak / roleplay / identity-role probes.
    "dan": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "jailbreak": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "roleplay": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "grandma": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "persona": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "impersonation": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    # Tool / capability-misuse probes.
    "malwaregen": AttackCategory.TOOL_MISUSE,
    "packagehallucination": AttackCategory.TOOL_MISUSE,
    "exploitation": AttackCategory.TOOL_MISUSE,
    "toolmisuse": AttackCategory.TOOL_MISUSE,
    "tool": AttackCategory.TOOL_MISUSE,
    "av_spam_scanning": AttackCategory.TOOL_MISUSE,
    # Denial-of-service / resource-flood probes.
    "dos": AttackCategory.DENIAL_OF_SERVICE,
    "flood": AttackCategory.DENIAL_OF_SERVICE,
    "glitch": AttackCategory.DENIAL_OF_SERVICE,
    "denialofservice": AttackCategory.DENIAL_OF_SERVICE,
    # Memory / persisted-state corruption probes.
    "memory": AttackCategory.STATE_CORRUPTION,
    "state": AttackCategory.STATE_CORRUPTION,
    "poison": AttackCategory.STATE_CORRUPTION,
    "corruption": AttackCategory.STATE_CORRUPTION,
}

# PyRIT harm_categories label -> closed six-category set. PyRIT tags each seed
# with one or more free-form harm strings; we take the first one that maps.
_PYRIT_HARM_TO_CATEGORY: dict[str, AttackCategory] = {
    "data_leakage": AttackCategory.DATA_EXFILTRATION,
    "data_exfiltration": AttackCategory.DATA_EXFILTRATION,
    "privacy": AttackCategory.DATA_EXFILTRATION,
    "pii": AttackCategory.DATA_EXFILTRATION,
    "prompt_injection": AttackCategory.PROMPT_INJECTION,
    "injection": AttackCategory.PROMPT_INJECTION,
    "jailbreak": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "impersonation": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "identity": AttackCategory.IDENTITY_ROLE_EXPLOITATION,
    "harmful_tool_use": AttackCategory.TOOL_MISUSE,
    "malware": AttackCategory.TOOL_MISUSE,
    "tool_misuse": AttackCategory.TOOL_MISUSE,
    "denial_of_service": AttackCategory.DENIAL_OF_SERVICE,
    "dos": AttackCategory.DENIAL_OF_SERVICE,
    "state_corruption": AttackCategory.STATE_CORRUPTION,
    "memory_poisoning": AttackCategory.STATE_CORRUPTION,
}


def _single_turn(prompt: str, *, route: str) -> list[InputTurn]:
    """Wrap a raw prompt string as a one-turn ``input_sequence``. The payload
    carries the prompt under ``question`` — the request-body shape the copilot
    turn route expects."""
    return [InputTurn(turn_index=0, route=route, payload={"question": prompt})]


def from_garak(record: dict, *, route: str) -> SeedAttack:
    """Normalize one Garak report record into a :class:`SeedAttack`.

    Requires a non-empty ``prompt``; maps ``probe_classname`` into the closed
    category set by its leading dotted module segment. An unknown module raises
    :class:`CorpusError`.
    """
    prompt = record.get("prompt")
    if not prompt or not isinstance(prompt, str) or not prompt.strip():
        raise CorpusError("garak record has no non-empty 'prompt'")

    probe_classname = record.get("probe_classname")
    if not probe_classname or not isinstance(probe_classname, str):
        raise CorpusError("garak record has no 'probe_classname'")

    module = probe_classname.split(".", 1)[0].strip().lower()
    category = _GARAK_MODULE_TO_CATEGORY.get(module)
    if category is None:
        raise CorpusError(
            f"garak probe '{probe_classname}' (module {module!r}) does not map "
            "into the closed attack-category set"
        )

    provenance = f"garak:{probe_classname}"
    return SeedAttack(
        attack_category=category,
        input_sequence=_single_turn(prompt, route=route),
        provenance=provenance,
    )


def from_pyrit(record: dict, *, route: str) -> SeedAttack:
    """Normalize one PyRIT dataset record into a :class:`SeedAttack`.

    Requires ``value`` (the seed prompt); maps the first mappable entry of
    ``harm_categories`` into the closed category set. No mappable harm label
    raises :class:`CorpusError`.
    """
    value = record.get("value")
    if not value or not isinstance(value, str) or not value.strip():
        raise CorpusError("pyrit record has no non-empty 'value'")

    raw_harm_categories = record.get("harm_categories")
    if raw_harm_categories is None:
        harm_categories = []
    elif isinstance(raw_harm_categories, str):
        harm_categories = [raw_harm_categories]
    elif isinstance(raw_harm_categories, list):
        harm_categories = raw_harm_categories
    else:
        raise CorpusError(
            f"pyrit record has invalid 'harm_categories': {raw_harm_categories!r}"
        )

    category: AttackCategory | None = None
    for harm in harm_categories:
        if not isinstance(harm, str):
            continue
        category = _PYRIT_HARM_TO_CATEGORY.get(harm.strip().lower())
        if category is not None:
            break
    if category is None:
        raise CorpusError(
            f"pyrit harm_categories {harm_categories!r} do not map into the "
            "closed attack-category set"
        )

    provenance = f"pyrit:{','.join(str(h) for h in harm_categories)}"
    return SeedAttack(
        attack_category=category,
        input_sequence=_single_turn(value, route=route),
        provenance=provenance,
    )


def ingest(
    records: Iterable[dict], *, source: Literal["garak", "pyrit"], route: str
) -> list[SeedAttack]:
    """Convert an iterable of raw seed records into ``SeedAttack``s, dispatching
    by ``source``. Input order is preserved and conversion is deterministic."""
    if source == "garak":
        convert = from_garak
    elif source == "pyrit":
        convert = from_pyrit
    else:  # pragma: no cover - guarded by Literal at call sites
        raise CorpusError(f"unknown corpus source: {source!r}")

    return [convert(record, route=route) for record in records]
