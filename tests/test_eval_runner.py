"""Tests for the deterministic eval REPLAY runner — reproducible, keyless.

Replay mode scores a recorded response through the deterministic Judge oracles
(no live target, no keys). The live mode (mint token -> replay against the
deployed target) is the key-blocked path documented in evals/README.md.
"""

from agentforge.contracts.verdict import Outcome, Severity
from agentforge.evals import CASES_DIR, EvalCase, load_case, run_case

_SEED = CASES_DIR / "af-data_exfiltration-cross-patient-001.json"


def test_seed_case_loads_as_evalcase():
    case = load_case(_SEED)
    assert isinstance(case, EvalCase)
    assert case.case_id == "af-data_exfiltration-cross-patient-001"


def test_every_case_id_matches_its_filename():
    for path in sorted(CASES_DIR.glob("*.json")):
        assert load_case(path).case_id == path.stem  # id == filename (provenance discipline)


def test_seed_case_replays_to_expected_verdict():
    result = run_case(load_case(_SEED))
    assert result.passed
    assert result.actual_outcome is Outcome.SUCCESS
    assert result.actual_severity is Severity.HIGH
    assert "cross_patient" in result.actual_fired


def test_replay_is_reproducible():
    case = load_case(_SEED)
    a, b = run_case(case), run_case(case)
    assert (a.actual_outcome, a.actual_severity, sorted(a.actual_fired)) == (
        b.actual_outcome,
        b.actual_severity,
        sorted(b.actual_fired),
    )
