"""
Persists per-technique training progress across process restarts.

battle_loop.py's round number and cumulative battle counters used to live
only in local Python variables, reset to zero every time the process
started. Since TensorBoard and training_stats.jsonl are both append-only
and keyed on those numbers, restarting training (a new process) made the
round counter and cumulative rates restart from scratch while still writing
into the same run/file - so a second session's "round 1" landed on top of
the first session's "round 1", and a fresh `total_battles_seen` of 1, 2, 3...
got plotted right next to an earlier session's already-large cumulative
count. That's what produced overlapping, "wonky" TensorBoard lines.

This file makes the round number and cumulative counters durable: loaded
once at the start of a run, saved after every battle, so a new process
picks up exactly where the last one left off instead of resetting.
"""

import json

from training.dataset import DATA_DIR

PROGRESS_DIR = DATA_DIR / "progress"

_DEFAULT_STATE = {
    "global_round": 0,
    "total_attack_battles": 0,
    "total_attack_successes": 0,
    "total_detections": 0,
    "total_normal_battles": 0,
    "total_false_positives": 0,
}


def _state_file(technique: str):
    return PROGRESS_DIR / f"{technique}.json"


def load_progress(technique: str) -> dict:
    f = _state_file(technique)
    if not f.exists():
        return dict(_DEFAULT_STATE)
    try:
        state = json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULT_STATE)
    return {**_DEFAULT_STATE, **state}  # tolerate old files missing a newer key


def save_progress(technique: str, state: dict) -> None:
    PROGRESS_DIR.mkdir(parents=True, exist_ok=True)
    _state_file(technique).write_text(json.dumps(state), encoding="utf-8")
