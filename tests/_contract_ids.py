"""Canonical ``$id`` URIs for the v1 contract schemas — one place so tests and
swarm-authored modules agree on the exact reference strings."""

BASE = "https://agentforge/contracts/v1"

COMMON = f"{BASE}/common.schema.json"
DIRECTIVE = f"{BASE}/orchestrator_to_redteam.schema.json"
RESULT = f"{BASE}/redteam_to_judge.schema.json"
VERDICT = f"{BASE}/judge_to_documentation.schema.json"
ERRORS = f"{BASE}/errors.schema.json"
