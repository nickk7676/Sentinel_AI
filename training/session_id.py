"""
Tracks a monotonic counter for --technique all overnight sessions
(training/battle_loop.py:run_loop_all), used to label the automatic
before/after eval_harness snapshots with small, ordered round numbers -
consistent with how eval_harness.py's own --round flag is normally used
(small integers), rather than injecting raw timestamps into the same
eval_summary.jsonl / TensorBoard "eval" series. Mirrors
training/adapter_version.py's file-based counter pattern.
"""

import json

from training.dataset import DATA_DIR

_SESSION_FILE = DATA_DIR / "overnight_session_id.json"


def next_session_id() -> int:
    """Increments and persists the session counter, returning the new
    value. Call once per --technique all run (not once per technique)."""
    current = 0
    if _SESSION_FILE.exists():
        try:
            current = json.loads(_SESSION_FILE.read_text(encoding="utf-8")).get("session_id", 0)
        except (json.JSONDecodeError, OSError):
            current = 0
    new_id = current + 1
    _SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    _SESSION_FILE.write_text(json.dumps({"session_id": new_id}), encoding="utf-8")
    return new_id
