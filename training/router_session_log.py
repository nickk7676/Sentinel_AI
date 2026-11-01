"""
Full-record logging for router-driven battles (agents/red_team/router/
battle_runner.py) - mirrors training/battle_log.py's shape and rationale,
just for the router instead of a whole red/blue/judge battle: one JSON line
per session, holding every decision point's state snapshot (not just the
final one), so agents/red_team/router/build_router_dataset.py can later
reconstruct "what did the router see right before it made the choice that
turned out correct" training examples.

Unlike training/dataset.py (which only ever saves *winning*, already-
distilled examples for fine-tuning), this logs every session regardless of
outcome - a session where nothing succeeded is still useful signal (it's
just not a positive example for supervised technique selection).

Stored under DATA_DIR (training/dataset.py) rather than inside the repo,
same OneDrive/Defender append-lock rationale as battle_log.py.
"""

import json
import time

from agents.safety.redact import redact_value
from training.dataset import DATA_DIR

ROUTER_SESSIONS_FILE = DATA_DIR / "router_sessions.jsonl"

# How many of ROUTER_SESSIONS_FILE's lines (from the top) have already been
# mined into training examples - agents/red_team/router/build_router_dataset.py
# reads this before mining and advances it after, so re-running the dataset
# builder (e.g. once per round of a training loop) never re-mines the same
# session twice. Not folded into training/progress_state.py's per-technique
# state, since mining is a standalone step that can run independently of any
# particular loop/round-counting scheme.
_MINING_STATE_FILE = DATA_DIR / "router_sessions_mining_state.json"


def load_mined_line_count() -> int:
    if not _MINING_STATE_FILE.exists():
        return 0
    try:
        return json.loads(_MINING_STATE_FILE.read_text(encoding="utf-8")).get("mined_line_count", 0)
    except (json.JSONDecodeError, OSError):
        return 0


def save_mined_line_count(count: int) -> None:
    _MINING_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _MINING_STATE_FILE.write_text(json.dumps({"mined_line_count": count}), encoding="utf-8")


def log_router_session(
    *,
    target_url: str,
    decision_log: list[dict],
    techniques_tried: list[dict],
    chain_notes: list[str],
) -> None:
    """decision_log: one entry per decision point, each
    {"state_prompt_block": str, "available_techniques": list[str],
    "decision": dict (a RouterDecision, as dataclasses.asdict)} - captured
    BEFORE that decision's action was dispatched, so it reflects exactly
    what the router saw at that moment, not the battle's final state."""
    ROUTER_SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "target_url": target_url,
        # Step 6.3 - scrub secret-shaped values (a real live target could in
        # principle return something real-looking) before this hits disk,
        # same as every other saved training/audit record in this codebase.
        "decision_log": redact_value(decision_log),
        "techniques_tried": redact_value(techniques_tried),
        "chain_notes": redact_value(chain_notes),
    }
    with open(ROUTER_SESSIONS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
