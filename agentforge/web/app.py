"""AgentForge web console — FastAPI service.

Read-only, replay-first mission control over the platform's PHI-free telemetry.
It serves the dark SOC console (``static/index.html``) plus a small JSON API
computed from a recorded campaign dataset. By design it exposes only PHI-free
fields — ids, attack category, HTTP status, verdict band, severity, oracle
predicate, cost — and never raw target-response bytes (the ``OBSERVABILITY.md``
discipline, applied to the UI).

Run locally:  ``uvicorn agentforge.web.app:app --reload``
Deployed:     ``uvicorn agentforge.web.app:app --host 0.0.0.0 --port $PORT``
"""

from __future__ import annotations

import json
from collections import OrderedDict
from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"
_DATA_FILE = _WEB_DIR / "data" / "recorded_campaign.json"

# Canonical six-category taxonomy (mirrors AttackCategory) — fixes coverage-grid order.
CATEGORIES = [
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "denial_of_service",
    "identity_role_exploitation",
]
VERDICTS = ["success", "partial", "fail"]  # breach / progress / defense-held

app = FastAPI(title="AgentForge Console", docs_url="/api/docs")


@lru_cache(maxsize=1)
def _campaign() -> dict:
    return json.loads(_DATA_FILE.read_text())


def _coverage(campaign: dict) -> list[dict]:
    """Per-category attempt/verdict counts, in canonical order."""
    buckets: OrderedDict[str, dict] = OrderedDict(
        (c, {"category": c, "attempts": 0, "success": 0, "partial": 0, "fail": 0}) for c in CATEGORIES
    )
    for a in campaign["attempts"]:
        b = buckets.setdefault(
            a["category"], {"category": a["category"], "attempts": 0, "success": 0, "partial": 0, "fail": 0}
        )
        b["attempts"] += 1
        if a["verdict"] in b:
            b[a["verdict"]] += 1
    return list(buckets.values())


def _summary(campaign: dict) -> dict:
    attempts = campaign["attempts"]
    bands = {v: sum(1 for a in attempts if a["verdict"] == v) for v in VERDICTS}
    spent = round(sum(a.get("cost_usd", 0.0) for a in attempts), 4)
    return {
        "campaign_id": campaign["campaign_id"],
        "label": campaign["label"],
        "mode": campaign["mode"],
        "target_base_url": campaign["target_base_url"],
        "target_version": campaign["target_version"],
        "attempt_count": len(attempts),
        "bands": bands,
        "categories_covered": len({a["category"] for a in attempts}),
        "categories_total": len(CATEGORIES),
        "cost_usd": spent,
        "budget_usd": campaign.get("budget_usd"),
        "open_findings": sum(1 for f in campaign.get("findings", []) if f["status"] != "resolved"),
        "awaiting_approval": sum(
            1 for f in campaign.get("findings", []) if f["status"] == "awaiting_human_approval"
        ),
        "resilience_history": campaign.get("resilience_history", []),
    }


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "campaign": _campaign()["campaign_id"]}


@app.get("/api/campaign")
def campaign() -> JSONResponse:
    """The recorded campaign: attempts (in order) + meta. Already PHI-free."""
    c = _campaign()
    return JSONResponse(
        {
            "campaign_id": c["campaign_id"],
            "label": c["label"],
            "mode": c["mode"],
            "provenance": c.get("provenance"),
            "target_base_url": c["target_base_url"],
            "target_version": c["target_version"],
            "started_at": c.get("started_at"),
            "budget_usd": c.get("budget_usd"),
            "attempts": c["attempts"],
        }
    )


@app.get("/api/coverage")
def coverage() -> JSONResponse:
    return JSONResponse({"categories": _coverage(_campaign())})


@app.get("/api/findings")
def findings() -> JSONResponse:
    return JSONResponse({"findings": _campaign().get("findings", [])})


@app.get("/api/summary")
def summary() -> JSONResponse:
    return JSONResponse(_summary(_campaign()))


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
