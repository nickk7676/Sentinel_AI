"""
BattleState construction/update (Step 8.2's "simple planning/memory
mechanism") and its rendering into the router's prompt.

to_prompt_block() is deliberately a *summary*, not a transcript: it always
renders the same rough shape (a handful of counts plus the most recent few
findings/notes) regardless of how many turns or techniques a battle has
gone through, so the router's own context window stays bounded across a
long, chained battle instead of growing with it.
"""

from __future__ import annotations

import json

from agents.red_team.router.schema import BattleState, ReconFinding

# How many of the most recent findings/notes to render in full - older ones
# are summarized as a count only, so to_prompt_block()'s output size stays
# roughly constant no matter how long the battle has run.
_MAX_RENDERED_FINDINGS = 8
_MAX_RENDERED_CHAIN_NOTES = 5


def new_state() -> BattleState:
    return BattleState()


def update_state(state: BattleState, event: ReconFinding | dict) -> BattleState:
    """event is either a ReconFinding (from a recon tool call, recon.py) or
    a technique outcome dict shaped like agents.red_team.live_tools.
    run_live_attack()'s return value (battle_runner.py passes that dict
    through here unchanged after a technique adapter finishes its turns)."""
    if isinstance(event, ReconFinding):
        state.recon_findings.append(event)
        return state

    outcome = event
    technique_id = outcome.get("attack_type", "unknown")
    turns_used = len(outcome.get("tool_calls", []))
    start_turn = state.turn_count
    state.turn_count += turns_used
    state.techniques_tried.append({
        "technique_id": technique_id,
        "turn_range": [start_turn, state.turn_count],
        "outcome": {
            "success": bool(outcome.get("success", False)),
            "payload": outcome.get("payload", ""),
        },
    })

    if outcome.get("success"):
        winning_call = next(
            (c for c in outcome.get("tool_calls", []) if c.get("success")), None,
        )
        note = f"{technique_id} succeeded: {outcome.get('payload', '')}"
        if winning_call:
            note += f" | raw result: {json.dumps(winning_call, default=str)[:300]}"
        state.chain_notes.append(note)

    return state


def to_prompt_block(state: BattleState) -> str:
    lines = [
        f"Turns used so far: {state.turn_count}",
        f"Recon findings: {len(state.recon_findings)}",
        f"Techniques tried: {len(state.techniques_tried)}",
    ]

    findings = state.recon_findings[-_MAX_RENDERED_FINDINGS:]
    omitted = len(state.recon_findings) - len(findings)
    header = "Recon findings:"
    if omitted > 0:
        header = f"Recon findings (most recent {len(findings)}, {omitted} earlier omitted):"
    lines.append("")
    lines.append(header)
    if findings:
        for f in findings:
            lines.append(f"  - {f.to_line()}")
    else:
        lines.append("  (none yet)")

    lines.append("")
    lines.append("Techniques tried so far:" if state.techniques_tried else "Techniques tried so far: (none yet)")
    for t in state.techniques_tried:
        outcome = t["outcome"]
        lines.append(
            f"  - {t['technique_id']} (turns {t['turn_range'][0]}-{t['turn_range'][1]}): "
            f"success={outcome['success']} payload={outcome['payload']!r}"
        )

    notes = state.chain_notes[-_MAX_RENDERED_CHAIN_NOTES:]
    notes_omitted = len(state.chain_notes) - len(notes)
    lines.append("")
    lines.append(
        "Chain notes (reusable artifacts found so far)"
        + (f" (most recent {len(notes)}, {notes_omitted} earlier omitted)" if notes_omitted > 0 else "")
        + ":"
    )
    if notes:
        for n in notes:
            lines.append(f"  - {n}")
    else:
        lines.append("  (none yet)")

    return "\n".join(lines)
