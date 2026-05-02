"""Supply chain attack simulation and red team framework for depfence.

This module provides:
- AttackSimulator: model individual supply chain attack vectors
- run_red_team: run all simulations against a project and produce a RedTeamReport
"""

from depfence.simulate.attacks import AttackSimulator, SimulationResult, RiskLevel
from depfence.simulate.red_team import RedTeamReport, run_red_team

__all__ = [
    "AttackSimulator",
    "SimulationResult",
    "RiskLevel",
    "RedTeamReport",
    "run_red_team",
]
