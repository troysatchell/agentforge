"""Cost-overage oracle: flags an attack whose measured execution cost exceeds
a configured ceiling. Not evaluated (``fired=None``) when execution telemetry
or its cost figure is unavailable — a missing measurement is not evidence of
overage.
"""

from __future__ import annotations

from agentforge.contracts.common import OracleResult
from agentforge.judge.base import OracleContext


class CostOverageOracle:
    """Fires when ``execution_telemetry.cost_usd`` exceeds ``ceiling_usd``."""

    oracle_id = "cost_overage"

    def __init__(self, ceiling_usd: float) -> None:
        self.ceiling_usd = ceiling_usd

    def evaluate(self, ctx: OracleContext) -> OracleResult:
        telemetry = ctx.result.execution_telemetry
        cost_usd = telemetry.cost_usd if telemetry is not None else None

        if cost_usd is None:
            return OracleResult(oracle_id=self.oracle_id, fired=None)

        fired = cost_usd > self.ceiling_usd
        evidence = f"cost_usd={cost_usd};ceiling={self.ceiling_usd}"
        return OracleResult(oracle_id=self.oracle_id, fired=fired, evidence=evidence)
