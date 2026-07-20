"""The Judge — deterministic-first adjudication.

Tier 1 (here, keyless): pure deterministic oracles + a Judge that turns their
results into a Verdict. Tier 2 (the Sonnet-5 semantic layer) is deferred — it
needs an API key and is governed by a labeled ground-truth set plus the
never-approve-a-confirmed-exploit invariant.
"""

from agentforge.judge.base import Oracle, OracleContext
from agentforge.judge.deterministic import DeterministicJudge

__all__ = ["Oracle", "OracleContext", "DeterministicJudge"]
