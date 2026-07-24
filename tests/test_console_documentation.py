"""CON6 (TRO-157) — the live console runs the 4th agent.

A confirmed breach must get a Documentation-agent vuln report (`report_markdown`
+ `doc_status` + attributed Opus cost) on its attempt event; non-breaches must
not invoke it; an Opus failure degrades (rejected) without killing the campaign.
The Opus call is injectable (`documenter=`) so this is testable keyless.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from agentforge.web import runner
from agentforge.web.runner import run_campaign


def _attempt(seq: int, spec: tuple, verdict: str, severity: str = "high") -> dict:
    return {
        "seq": seq, "attack_id": f"a{seq}", "category": spec[0], "subcategory": spec[1],
        "owasp": spec[2], "route": "/api/copilot/document", "http_status": 200,
        "verdict": verdict, "severity": severity, "predicate": "foreign_file_bytes fired: V1",
        "cost_usd": 0.0, "agent_path": [], "trace": [], "turns": 1, "mutation_of": None, "ts": "t",
        "repro": {"route": "POST /api/copilot/document", "payload": {"file_path": "menu-logo.png"}},
    }


def _drive(**kw) -> list[dict]:
    async def go():
        return [e async for e in run_campaign("tok", **kw)]

    return asyncio.run(go())


def test_confirmed_breach_carries_a_documentation_report() -> None:
    def run_one(token, spec, seq):
        return _attempt(seq, spec, "success", severity="critical")

    def documenter(attempt):
        return {"report_markdown": f"# AF report — {attempt['category']}\n\nbody",
                "doc_status": "held_for_human", "cost_usd": 0.004}

    runner.STATE.stop = False
    events = _drive(categories=["tool_misuse"], run_one=run_one, documenter=documenter)
    breach = next(e["data"] for e in events
                  if e["event"] == "attempt" and e["data"]["verdict"] == "success")
    assert breach["report_markdown"].startswith("# AF report")
    assert breach["doc_status"] == "held_for_human"
    assert breach["cost_by_agent"]["documentation"] == 0.004


def test_non_breach_does_not_invoke_the_documentation_agent() -> None:
    calls = {"n": 0}

    def run_one(token, spec, seq):
        return _attempt(seq, spec, "fail")

    def documenter(attempt):
        calls["n"] += 1
        return {"report_markdown": "x", "doc_status": "filed", "cost_usd": 0.001}

    runner.STATE.stop = False
    events = _drive(categories=["prompt_injection"], run_one=run_one, documenter=documenter)
    assert calls["n"] == 0
    attempts = [e["data"] for e in events if e["event"] == "attempt"]
    assert all(a.get("report_markdown") is None for a in attempts)


def test_documenter_failure_degrades_and_campaign_continues() -> None:
    def run_one(token, spec, seq):
        return _attempt(seq, spec, "success", severity="critical")

    def documenter(attempt):
        raise RuntimeError("opus down")

    runner.STATE.stop = False
    events = _drive(categories=["tool_misuse"], run_one=run_one, documenter=documenter)
    kinds = [e["event"] for e in events]
    assert "error" not in kinds and kinds[-1] == "done"
    breach = next(e["data"] for e in events if e["event"] == "attempt")
    assert breach["report_markdown"] is None
    assert breach["doc_status"] == "rejected"


def test_malformed_documenter_output_degrades_gracefully() -> None:
    def run_one(token, spec, seq):
        return _attempt(seq, spec, "success", severity="critical")

    def documenter(attempt):
        return None  # malformed — not a mapping; must not raise outside the guard

    runner.STATE.stop = False
    events = _drive(categories=["tool_misuse"], run_one=run_one, documenter=documenter)
    kinds = [e["event"] for e in events]
    assert "error" not in kinds and kinds[-1] == "done"
    breach = next(e["data"] for e in events if e["event"] == "attempt")
    assert breach["doc_status"] == "rejected"
    assert breach["report_markdown"] is None


def test_document_finding_builds_a_report_from_a_console_attempt(monkeypatch) -> None:
    # the real doc path (contract construction + DocumentationAgent + Opus cost) with
    # a mocked Anthropic HTTP call — no live key needed.
    monkeypatch.setattr(runner, "load_settings", lambda: SimpleNamespace(
        anthropic_api_key="sk-ant-test", doc_model="claude-opus-4-8",
        target_base_url="https://openemr.example.test"))
    monkeypatch.setattr(runner, "_anthropic_post", lambda url, h, b: {
        "content": [{"type": "text", "text": "Drafted description + clinical impact + remediation."}],
        "usage": {"input_tokens": 1200, "output_tokens": 400,
                  "cache_creation_input_tokens": 2000, "cache_read_input_tokens": 5000}})

    attempt = _attempt(
        4, ("tool_misuse", "local-file-read (V1)", "A01:2021-broken-access-control", "document", "p", "i"),
        "success", severity="critical")
    out = runner._document_finding(attempt)

    assert out["doc_status"] == "held_for_human"  # critical → gated for the operator
    assert "Drafted description" in out["report_markdown"]
    # cost bills input + output + BOTH prompt-cache token categories at their rates
    base = 1200 * runner._OPUS_IN + 400 * runner._OPUS_OUT
    expected = round(base + 2000 * runner._OPUS_CACHE_WRITE + 5000 * runner._OPUS_CACHE_READ, 5)
    assert out["cost_usd"] == expected
    assert out["cost_usd"] > round(base, 5)  # the cache tokens actually add cost
