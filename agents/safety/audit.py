"""Step 6.4 - hash-chained, append-only audit log.

One record per real action red/blue take against a live target (tool call,
telemetry fetch, or a scope/kill-switch denial) - separate from
training/battle_log.py, which logs at the whole-battle level for training
analysis, not individual actions with authorization-state metadata. Each
record's hash covers its own content plus the previous record's hash, so
editing any existing line (or any line after it) breaks the chain;
verify_chain() recomputes it end to end to detect that.

Precise about what this does and doesn't guarantee: it's edit-evident, not
deletion/truncation-evident. Someone with file access can truncate the log
at any point and keep appending validly from there - verify_chain() has no
way to know lines are missing, only that the lines present are internally
consistent. Treat "immutable" in the project plan's Step 6.4 as aspirational
for this stdlib-only implementation; a real tamper-evidence guarantee would
need an external anchor (e.g. periodically hashing-and-timestamping off-box,
or shipping the log to write-once storage) - not built here, since nothing
today needs to survive an adversary with local file access, only accidental
edits and the "nothing was silently changed" question for a later review.

Deliberately not named audit.py at the repo root - that's an unrelated
training-data-quality script.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from threading import Lock

from agents.safety.redact import redact_value

LOG_PATH = Path(__file__).resolve().parent.parent.parent / "logs" / "audit_log.jsonl"
_GENESIS_HASH = "0" * 64

_lock = Lock()
_last_hash: str | None = None  # cached so appends don't rescan the whole file


def _read_last_hash() -> str:
    if not LOG_PATH.exists():
        return _GENESIS_HASH
    last = _GENESIS_HASH
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line)["hash"]
            except (json.JSONDecodeError, KeyError):
                continue
    return last


def _entry_hash(prev_hash: str, entry_without_hash: dict) -> str:
    digest_input = json.dumps(entry_without_hash, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(prev_hash.encode("utf-8") + digest_input).hexdigest()


def record_action(
    actor: str,
    action: str,
    target: str,
    *,
    technique: str | None = None,
    args: dict | None = None,
    outcome: str = "ok",
    detail: dict | None = None,
) -> dict:
    """Append one tamper-evident audit record.

    actor:    "red" | "blue" | "system"
    outcome:  "ok", or a short machine-readable denial reason
              ("ScopeViolationError", "KillSwitchTripped", ...)
    """
    global _last_hash
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if _last_hash is None:
            _last_hash = _read_last_hash()

        entry = {
            "ts": time.time(),
            "actor": actor,
            "action": action,
            "target": target,
            "technique": technique,
            "args": redact_value(args or {}),
            "outcome": outcome,
            "detail": redact_value(detail or {}),
            "prev_hash": _last_hash,
        }
        entry["hash"] = _entry_hash(_last_hash, entry)

        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")

        _last_hash = entry["hash"]
        return entry


def verify_chain() -> tuple[bool, int]:
    """Recompute the hash chain from scratch. Returns (intact, record_count).
    Use this to detect whether the audit log has been edited or truncated
    since it was written."""
    if not LOG_PATH.exists():
        return True, 0
    prev_hash = _GENESIS_HASH
    count = 0
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            claimed_hash = entry.pop("hash")
            recomputed = _entry_hash(prev_hash, entry)
            if recomputed != claimed_hash:
                return False, count
            prev_hash = claimed_hash
            count += 1
    return True, count
