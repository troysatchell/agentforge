"""Frozen tests (PERF2 / TRO-131) — load/baseline profiling harness.

`run_load` drives n iterations of generate -> judge -> persist through an
injected timer (no real sleeping), and reports per-stage latency, throughput, and
the bottleneck stage. Frozen contract for PERF2.
"""

from __future__ import annotations

from agentforge.perf import LoadProfile, run_load


class ScriptedTimer:
    """timer(fn) -> (result, elapsed_ms); elapsed cycles through the per-stage script."""

    def __init__(self, cycle_ms):
        self._cycle = cycle_ms
        self._i = 0

    def __call__(self, fn):
        result = fn()
        elapsed = self._cycle[self._i % len(self._cycle)]
        self._i += 1
        return result, float(elapsed)


def _gen():
    return {"attack": 1}


def _judge(attack):
    return {"verdict": "fail"}


def _persist(verdict):
    return True


def _run(n, cycle=(3.0, 5.0, 1.0)):
    return run_load(n, generate=_gen, judge=_judge, persist=_persist, timer=ScriptedTimer(list(cycle)))


def test_run_load_profiles_each_stage():
    profile = _run(100)  # generate=3ms, judge=5ms, persist=1ms
    assert isinstance(profile, LoadProfile)
    assert profile.attacks == 100
    assert profile.stages["generate"].mean_ms == 3.0
    assert profile.stages["judge"].mean_ms == 5.0
    assert profile.stages["persist"].mean_ms == 1.0
    assert profile.stages["judge"].count == 100


def test_bottleneck_is_slowest_stage():
    assert _run(10).bottleneck == "judge"


def test_throughput_and_wall_ms():
    profile = _run(100)  # 9ms total work per attack
    assert profile.wall_ms == 900.0
    assert round(profile.throughput_per_s, 2) == round(100 / 0.9, 2)


def test_percentiles_constant_workload():
    profile = _run(20)
    assert profile.stages["judge"].p50_ms == 5.0
    assert profile.stages["judge"].p95_ms == 5.0


def test_deterministic():
    assert _run(50) == _run(50)
