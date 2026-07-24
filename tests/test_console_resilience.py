"""A per-probe failure (Kimi/target timeout, transport/parse error) must degrade
to a labeled error attempt — it must NOT kill the whole campaign.

Regression: a `TimeoutError` on the 2nd probe (cross-patient data_exfiltration)
aborted the entire 6-category sweep after only one attempt.
"""

from __future__ import annotations

import asyncio

from agentforge.web.runner import STATE, run_campaign


def _ok(seq: int, spec: tuple) -> dict:
    return {
        "seq": seq, "attack_id": f"a{seq}", "category": spec[0], "subcategory": spec[1],
        "owasp": spec[2], "route": "/r", "http_status": 200, "verdict": "fail",
        "severity": "low", "predicate": None, "cost_usd": 0.0, "agent_path": [], "ts": "t",
    }


def _drive(fake, **kw) -> list[dict]:
    async def go():
        return [e async for e in run_campaign("tok", run_one=fake, **kw)]

    return asyncio.run(go())


def test_probe_timeout_degrades_to_error_attempt_and_sweep_continues() -> None:
    calls = {"n": 0}

    def flaky(token, spec, seq):
        calls["n"] += 1
        if calls["n"] == 1:
            raise TimeoutError("the target took too long")
        return _ok(seq, spec)

    STATE.stop = False
    events = _drive(flaky, categories=["prompt_injection", "tool_misuse"])
    kinds = [e["event"] for e in events]

    # the campaign did NOT die with a top-level error event
    assert "error" not in kinds
    assert kinds[-1] == "done"

    attempts = [e["data"] for e in events if e["event"] == "attempt"]
    assert len(attempts) == 2  # both categories still swept
    assert attempts[0]["verdict"] == "error"
    assert "timed out" in attempts[0]["predicate"].lower()
    assert attempts[1]["verdict"] == "fail"  # the second probe ran normally
