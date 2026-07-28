"""Step 6.2 - automatic pause/kill-switch on anomalous target behavior.

Tracks consecutive failed/errored actions per target. A real error storm
(e.g. a lab target crashing, or - once this ever points at something less
disposable - a target actually breaking under attack) trips an automatic
pause for that target: every further action against it is refused until a
human calls reset() after checking what happened. Both the paused state
*and* the in-progress consecutive-error count are persisted to disk (not
just the trip itself) so a training-loop restart mid-error-streak doesn't
hand a genuinely broken target a fresh count - a target at 7/8 right before
a crash resumes at 7/8, not 0/8.

Locking here (threading.Lock) only guards concurrent callers within one
process. If battle_loop.py's training loop and the backend API server ever
run as separate OS processes hitting the same target/state file at the
same time, the read-modify-write of killswitch_state.json can still race
between them - known limitation, not addressed here, since today's actual
usage is one process at a time.
"""

from __future__ import annotations

import json
from pathlib import Path
from threading import Lock

STATE_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "killswitch_state.json"

# Consecutive errored actions against the same target before auto-pausing it.
CONSECUTIVE_ERROR_LIMIT = 8


class KillSwitchTripped(Exception):
    """Raised when an action targets a paused target."""


_lock = Lock()
_consecutive_errors: dict[str, int] = {}
_paused: dict[str, str] = {}  # target_url -> reason
_loaded = False


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    if STATE_PATH.exists():
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            _paused.update(data.get("paused", {}))
            _consecutive_errors.update(data.get("consecutive_errors", {}))
        except (json.JSONDecodeError, OSError):
            pass


def _save() -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(
        json.dumps({"paused": _paused, "consecutive_errors": _consecutive_errors}, indent=2),
        encoding="utf-8",
    )


def check(target_url: str) -> None:
    """Call before dispatching any real action at target_url. Raises
    KillSwitchTripped if this target is currently paused."""
    _load()
    with _lock:
        if target_url in _paused:
            raise KillSwitchTripped(f"{target_url} is paused: {_paused[target_url]}")


def record(target_url: str, *, errored: bool) -> None:
    """Call after every real action completes. Trips the kill-switch once
    CONSECUTIVE_ERROR_LIMIT errors in a row have been seen for this target.
    Persists the counter itself (not just the eventual trip) so a restart
    mid-streak doesn't lose progress toward the limit - but only writes to
    disk when the count actually changes away from 0, so a long run of
    ordinary successful actions costs no extra disk I/O."""
    _load()
    with _lock:
        if not errored:
            if _consecutive_errors.get(target_url, 0) != 0:
                _consecutive_errors[target_url] = 0
                _save()
            return
        count = _consecutive_errors.get(target_url, 0) + 1
        _consecutive_errors[target_url] = count
        if count >= CONSECUTIVE_ERROR_LIMIT and target_url not in _paused:
            _paused[target_url] = f"{count} consecutive errored actions"
        _save()


def reset(target_url: str) -> None:
    """Manual resume after a human has verified it's safe to continue."""
    _load()
    with _lock:
        _paused.pop(target_url, None)
        _consecutive_errors[target_url] = 0
        _save()


def is_paused(target_url: str) -> bool:
    _load()
    return target_url in _paused
