"""AgentForge operator console — FastAPI service.

A live operator surface: the operator supplies a launch-bound token, picks
categories, and starts a REAL campaign that runs server-side (Kimi generates ->
TargetClient fires at the live co-pilot -> deterministic verdict) and streams
each attempt over SSE. Stop halts it. The token is the gate: no valid
launch-bound token, no attacks — so the public URL cannot fire on its own.

Everything exposed is PHI-free — ids, category, HTTP status, verdict band,
severity, oracle predicate, cost — never raw target-response bytes.

Local:     ``uvicorn agentforge.web.app:app --reload``
Deployed:  ``python -m agentforge.web``  (reads $PORT)
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from fastapi import Body, FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from agentforge.web.runner import CATEGORIES, STATE, run_campaign, token_is_valid

_WEB_DIR = Path(__file__).resolve().parent
_STATIC_DIR = _WEB_DIR / "static"

app = FastAPI(title="AgentForge Operator Console", docs_url="/api/docs")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "active": STATE.active}


@app.get("/api/status")
def status() -> dict:
    return {"active": STATE.active, "categories": CATEGORIES}


@app.post("/api/stop")
def stop() -> dict:
    STATE.stop = True
    return {"stopping": True}


@app.post("/api/run", response_model=None)
async def run(payload: dict = Body(...)) -> StreamingResponse | JSONResponse:
    token = (payload.get("token") or "").strip()
    categories = payload.get("categories") or None
    if STATE.active:
        return JSONResponse({"error": "A campaign is already running."}, status_code=409)
    if not token:
        return JSONResponse({"error": "A launch-bound token is required to launch attacks."}, status_code=400)
    if not await asyncio.to_thread(token_is_valid, token):
        return JSONResponse(
            {"error": "Invalid or expired launch-bound token. Re-launch the Co-Pilot from a patient chart to get a fresh one."},
            status_code=401,
        )

    async def sse():
        try:
            async for ev in run_campaign(token, categories):
                yield f"event: {ev['event']}\ndata: {json.dumps(ev['data'])}\n\n"
        except Exception as exc:  # surface a clean error event, never a raw stack to the browser
            yield f"event: error\ndata: {json.dumps({'message': type(exc).__name__})}\n\n"

    return StreamingResponse(
        sse(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no", "Connection": "keep-alive"},
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")
