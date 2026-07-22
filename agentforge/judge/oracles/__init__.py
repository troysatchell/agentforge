"""Deterministic oracles — pure functions over an AttackResult that fire when a
finding condition is met. Each returns a PHI-free OracleResult.
"""

from agentforge.judge.oracles.cost_overage import CostOverageOracle
from agentforge.judge.oracles.cross_patient import CrossPatientOracle
from agentforge.judge.oracles.foreign_file_bytes import ForeignFileBytesOracle
from agentforge.judge.oracles.grounding import GroundingFabricationOracle
from agentforge.judge.oracles.phi_pattern import PhiPatternOracle
from agentforge.judge.oracles.tool_misuse import ToolMisuseOracle

__all__ = [
    "PhiPatternOracle",
    "CrossPatientOracle",
    "GroundingFabricationOracle",
    "CostOverageOracle",
    "ForeignFileBytesOracle",
    "ToolMisuseOracle",
]
