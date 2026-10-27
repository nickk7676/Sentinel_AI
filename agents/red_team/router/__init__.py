"""
Step 8.1/8.2 - Technique Router.

A shared "which-technique-next" decision point that sits above the per-
technique specialists (agents/techniques/*.py). Architecturally a peer of
blue (one shared adapter doing a generalizable job), not a peer of a red
technique (a specialized exploit skill) - see agents/red_team/router/router.py.

This package is purely additive: nothing in agents/techniques/,
agents/safety/, agents/red_team/live_tools.py, agents/red_team/agent.py, or
training/battle_loop.py is changed by its existence.
"""

from agents.red_team.router.schema import BattleState, ReconFinding, RouterDecision

__all__ = ["BattleState", "ReconFinding", "RouterDecision"]
