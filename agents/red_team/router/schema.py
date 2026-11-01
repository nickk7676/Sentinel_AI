"""
Shared data shapes for the Step 8 router: the unit recon tools produce
(ReconFinding), the running memory the router reasons over (BattleState),
and the router's own output (RouterDecision).

Kept as plain dataclasses (not pydantic) to match the rest of this codebase's
convention (see agents/techniques/base.py's Technique) - no new dependency
needed for something this small.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ROUTER_ACTIONS = ("invoke_technique", "recon_more", "stop")


@dataclass(frozen=True)
class ReconFinding:
    """One atomic observation about the target - the unit both recon tools
    (agents/red_team/router/recon.py) and the router (router.py) consume."""

    endpoint: str
    method: str = "GET"
    params: tuple[str, ...] = ()
    response_shape: str = ""
    notes: str = ""

    def to_line(self) -> str:
        params_str = f" params={list(self.params)}" if self.params else ""
        notes_str = f" - {self.notes}" if self.notes else ""
        return f"{self.method} {self.endpoint}{params_str} [{self.response_shape}]{notes_str}"


@dataclass
class BattleState:
    """Turn-by-turn planning/memory for one router-driven battle (Step 8.2).

    Deliberately holds distilled facts, not the raw conversation transcript -
    to_prompt_block() renders this at a roughly constant size regardless of
    how long the battle has run, which is what keeps the router's own
    context window bounded across a long, chained battle (8.3).
    """

    recon_findings: list[ReconFinding] = field(default_factory=list)
    # Each entry: {"technique_id": str, "turn_range": [int, int], "outcome": dict}
    techniques_tried: list[dict] = field(default_factory=list)
    turn_count: int = 0
    # Freeform breadcrumbs about reusable artifacts a technique's outcome
    # surfaced (a leaked token, a discovered credential, an id). Rendered into
    # the router's prompt so a later decision can reason about what earlier
    # steps found - this is how the router recognizes a chain is half-done and
    # picks the follow-on technique (Step 8.3).
    chain_notes: list[str] = field(default_factory=list)
    # Structured form of the same reusable artifacts (key -> value), as
    # opposed to chain_notes' human-readable lines. battle_runner.py hands
    # this dict to the next technique's run_live_attack(chain_context=...) so
    # the follow-on step can actually use a stolen token/id, not just read
    # about it. Kept structured (not parsed back out of chain_notes) so the
    # value passed downstream is exact.
    artifacts: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RouterDecision:
    action: Literal["invoke_technique", "recon_more", "stop"]
    technique_id: str | None = None
    reasoning: str = ""
