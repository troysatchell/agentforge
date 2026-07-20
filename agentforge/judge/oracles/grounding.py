"""Grounding/fabrication oracle — flags responses that cite a source id
outside the campaign's legitimate set. Citations are read from a dict body's
``citations`` list AND from a regex scan of the stringified body for
``sourceId="X"`` / ``"ref":"X"`` tokens, so fabricated refs smuggled into free
text (not just a structured citations array) are still caught.
"""

from __future__ import annotations

import json
import re

from agentforge.contracts.common import OracleResult
from agentforge.judge.base import OracleContext

_SOURCE_ID_TOKEN = re.compile(r'sourceId\s*=\s*"([^"]+)"|"ref"\s*:\s*"([^"]+)"')


class GroundingFabricationOracle:
    """Fires when a response cites a source id that isn't in the campaign's
    legitimate set — i.e. a fabricated citation."""

    oracle_id = "grounding_fabrication"

    def __init__(self, legit_source_ids: set[str]) -> None:
        self._legit_source_ids = legit_source_ids

    def evaluate(self, ctx: OracleContext) -> OracleResult:
        body = ctx.result.target_response.body
        cited_ids: set[str] = set()

        if isinstance(body, dict):
            citations = body.get("citations", [])
            if isinstance(citations, list):
                cited_ids.update(str(citation) for citation in citations)
            text = json.dumps(body)
        else:
            text = str(body)

        for match in _SOURCE_ID_TOKEN.finditer(text):
            token = match.group(1) or match.group(2)
            if token:
                cited_ids.add(token)

        if not cited_ids:
            return OracleResult(oracle_id=self.oracle_id, fired=None)

        fabricated = cited_ids - self._legit_source_ids
        return OracleResult(
            oracle_id=self.oracle_id,
            fired=len(fabricated) > 0,
            evidence=f"fabricated_refs={len(fabricated)}",
        )
