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
    # Step 7.3 - cumulative counts of battles where blue proposed a fix that
    # was actually checked (fix_proposed) vs. checked and confirmed to close
    # the hole (fix_verified). fix_proposed <= total_detections, since
    # verification only ever runs on a real, successfully-detected attack.
    "total_fix_proposed": 0,
    "total_fix_verified": 0,
    # Distractor targets (training/targets.py) are deliberately unexploitable
    # (patched vuln, alarming-looking logs) so blue learns precision, not so
    # red has something to succeed against - counting them toward red's own
    # success-rate denominator structurally caps it below 100% regardless of
    # red's real skill. These track attack battles/successes against
    # non-distractor targets only, which is what red_attack_success_rate
    # should actually be computed from; total_attack_battles/successes above
    # keep counting every attack round (including distractor) since that's
    # the right denominator for blue's detection rate.
    "total_real_attack_battles": 0,
    "total_real_attack_successes": 0,
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
