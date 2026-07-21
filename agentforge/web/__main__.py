"""Console launcher — ``python -m agentforge.web``.

Reads the port from ``$PORT`` (Railway injects it; falls back to 8000 locally)
in Python, so there is no shell-expansion ambiguity in the container start
command. Binds 0.0.0.0 and logs the resolved port.
"""

from __future__ import annotations

import os

import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"[agentforge.web] starting uvicorn on 0.0.0.0:{port}", flush=True)
    uvicorn.run("agentforge.web.app:app", host="0.0.0.0", port=port)
