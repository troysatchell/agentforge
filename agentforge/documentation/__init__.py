"""Documentation Agent (E6 / TRO-126) — confirmed exploits -> vuln reports.

STUB: public surface only. The coding agent fills in the behavior; the frozen
tests in ``tests/test_documentation_agent.py`` are the contract.
"""

from __future__ import annotations

from agentforge.documentation.agent import (
    DocLLMClient,
    DocumentationAgent,
    DocumentationOutcome,
)
from agentforge.documentation.anthropic_client import AnthropicClient, AnthropicError

__all__ = [
    "DocLLMClient",
    "DocumentationAgent",
    "DocumentationOutcome",
    "AnthropicClient",
    "AnthropicError",
]
