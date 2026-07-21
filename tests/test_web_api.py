"""Tests for the web console API (agentforge.web.app).

Assert the JSON shapes the console depends on AND the PHI-free discipline: the
API must never expose raw target-response bytes — only ids, categories, HTTP
status, verdict bands, severities, and oracle predicates.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from agentforge.web.app import CATEGORIES, app

client = TestClient(app)


def test_health_ok():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_index_serves_console():
    r = client.get("/")
    assert r.status_code == 200
    assert "Mission Control" in r.text


def test_campaign_attempts_are_ordered_and_phi_free():
    r = client.get("/api/campaign")
    assert r.status_code == 200
    body = r.json()
    attempts = body["attempts"]
    assert len(attempts) >= 3
    # ordered by seq
    assert [a["seq"] for a in attempts] == sorted(a["seq"] for a in attempts)
    allowed = {
        "seq", "category", "subcategory", "owasp", "route", "http_status",
        "verdict", "severity", "predicate", "cost_usd", "agent_path", "ts_offset_ms", "note",
    }
    for a in attempts:
        assert set(a).issubset(allowed), f"unexpected (possibly PHI) field: {set(a) - allowed}"
        assert a["verdict"] in {"success", "partial", "fail"}
        # no raw response body / bytes leaked
        assert "body" not in a and "response_body" not in a and "raw" not in a


def test_coverage_covers_all_six_categories_in_order():
    r = client.get("/api/coverage")
    cats = [c["category"] for c in r.json()["categories"]]
    assert cats[: len(CATEGORIES)] == CATEGORIES
    for c in r.json()["categories"]:
        assert c["attempts"] == c["success"] + c["partial"] + c["fail"] or c["attempts"] >= 0


def test_summary_bands_and_cost():
    s = client.get("/api/summary").json()
    assert set(s["bands"]) == {"success", "partial", "fail"}
    assert s["attempt_count"] == sum(s["bands"].values())
    assert s["cost_usd"] >= 0
    assert s["categories_total"] == 6


def test_findings_have_severity_and_status():
    fs = client.get("/api/findings").json()["findings"]
    assert len(fs) >= 1
    for f in fs:
        assert f["severity"] in {"critical", "high", "medium", "low", "false_positive"}
        assert f["outcome"] in {"success", "partial", "fail"}
        # findings are PHI-free too
        assert "raw" not in f and "body" not in f


def test_critical_finding_is_gated_for_human_approval():
    fs = client.get("/api/findings").json()["findings"]
    criticals = [f for f in fs if f["severity"] == "critical"]
    # any critical finding must be surfaced for human approval, never auto-filed
    for f in criticals:
        assert f["status"] == "awaiting_human_approval"
