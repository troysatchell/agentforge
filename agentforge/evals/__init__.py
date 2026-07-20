"""Deterministic eval replay suite — the reproducible, keyless MVP gate.

Cases live in the repo-root ``evals/cases/*.json``; each is replayed through the
Judge oracles and compared to its ``expected`` verdict.
"""

from agentforge.evals.case import EvalCase, ExpectedVerdict, OracleConfig
from agentforge.evals.runner import (
    CASES_DIR,
    EvalResult,
    load_case,
    run_case,
    run_suite,
)

__all__ = [
    "EvalCase",
    "ExpectedVerdict",
    "OracleConfig",
    "EvalResult",
    "CASES_DIR",
    "load_case",
    "run_case",
    "run_suite",
]
