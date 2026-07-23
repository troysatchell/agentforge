"""Regression re-issue harness (E7 / TRO-127).

Re-fires a stored exploit's persisted attack bytes at the live target and asserts
the success predicate still fires (or no longer fires after a fix). STUB: public
surface only — the frozen tests in ``tests/test_regression_runner.py`` are the
contract.
"""

from __future__ import annotations

from agentforge.regression.runner import (
    RegressionNotReproduced,
    RegressionOutcome,
    gate_red_proof,
    reissue,
)

__all__ = [
    "RegressionNotReproduced",
    "RegressionOutcome",
    "gate_red_proof",
    "reissue",
]
