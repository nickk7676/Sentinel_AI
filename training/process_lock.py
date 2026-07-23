"""
Prevents two processes from training/battling the same technique at once.

This is the actual root cause behind TensorBoard charts and
training_stats.jsonl looking corrupted after a restart: it wasn't just that
round numbers reset to zero (training/progress_state.py fixes that) - a
second process left running concurrently keeps writing its own stale,
non-persisted round numbers into the same shared files for as long as it's
alive, undoing the fix in real time. Two processes hitting the same lab
target at once also corrupt each other's "log lines since my last read"
window, since the lab targets keep log state in plain module-level buffers
with no per-client isolation.

Uses an OS-level advisory file lock (msvcrt) rather than a "does a lock file
exist" check, specifically so the lock releases itself even if the process
is killed forcibly (Stop-Process -Force, a crash, Ctrl+C) - a lock that only
gets cleaned up in a `finally` block would be left stale forever by a hard
kill, permanently blocking every future run for that technique.
"""

import contextlib
import msvcrt

from training.dataset import DATA_DIR

LOCKS_DIR = DATA_DIR / "locks"


@contextlib.contextmanager
def technique_lock(technique: str):
    """Raises RuntimeError immediately if another process already holds
    this technique's lock, instead of silently corrupting shared data."""
    LOCKS_DIR.mkdir(parents=True, exist_ok=True)
    path = LOCKS_DIR / f"{technique}.lock"

    # A second handle on an already-locked region can fail as early as the
    # open/read/write here (Windows mandatory locking), not just at the
    # msvcrt.locking() call below - so the whole acquisition sequence is
    # treated as "lock is held" on any OSError, not just that one call.
    f = None
    try:
        f = open(path, "a+b")
        f.seek(0)
        if f.read(1) == b"":
            f.write(b"0")
            f.flush()
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        if f is not None:
            f.close()
        raise RuntimeError(
            f"Another process is already running battles for technique {technique!r} "
            f"(lock file: {path}). Running two at once corrupts shared target state "
            f"and produces colliding round numbers in training_stats.jsonl/TensorBoard - "
            f"stop the other process first, or wait for it to finish."
        ) from None

    try:
        yield
    finally:
        f.seek(0)
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        f.close()
