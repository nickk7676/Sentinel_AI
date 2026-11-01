"""
Compute/cost tracking for the self-play loop (Step 9.4).

As technique and target counts grow, so does the GPU time spent playing
battles and training adapters - and that's the real cost of running this
system. This records, per phase (a round's battles, a red training run, a
blue training run), the wall-clock time, the GPU peak memory, and a count of
units done (battles or training examples), appended as one JSON line per
phase to DATA_DIR/cost_log.jsonl. It never changes what the loop does - it
only measures it - so it's safe to leave on always.

GPU-seconds here is approximated as wall-clock seconds of the phase: this is
a single-GPU setup and these phases run the GPU effectively end-to-end, so
wall-clock is a close enough proxy without per-kernel profiling. Peak memory
comes from torch.cuda.max_memory_allocated when CUDA is available.
"""

from __future__ import annotations

import json
import time
from contextlib import contextmanager

from training.dataset import DATA_DIR

COST_LOG = DATA_DIR / "cost_log.jsonl"


def _gpu_peak_mb_reset() -> bool:
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.reset_peak_memory_stats()
            return True
    except Exception:  # noqa: BLE001 - cost tracking must never break a run
        pass
    return False


def _gpu_peak_mb() -> float | None:
    try:
        import torch
        if torch.cuda.is_available():
            return round(torch.cuda.max_memory_allocated() / (1024 * 1024), 1)
    except Exception:  # noqa: BLE001
        pass
    return None


def record(phase: str, technique: str, seconds: float, **fields) -> None:
    """Append one cost record. `fields` carries phase-specific counts such as
    battles=.. or examples=.. ."""
    entry = {
        "timestamp": time.time(),
        "phase": phase,
        "technique": technique,
        "seconds": round(seconds, 2),
        "gpu_peak_mb": _gpu_peak_mb(),
        **fields,
    }
    COST_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(COST_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


@contextmanager
def track(phase: str, technique: str, **fields):
    """Time a phase and record it on exit (even if the phase raises), e.g.
    `with track("round_battles", technique, battles=n): ...`."""
    _gpu_peak_mb_reset()
    start = time.time()
    try:
        yield
    finally:
        record(phase, technique, time.time() - start, **fields)


def summarize(technique: str | None = None) -> dict:
    """Aggregate totals from the cost log (optionally for one technique):
    total seconds and per-phase seconds. For a quick 'what has this cost so
    far' readout - overnight_report.py or the console can print it."""
    if not COST_LOG.exists():
        return {"total_seconds": 0.0, "by_phase": {}}
    total = 0.0
    by_phase: dict[str, float] = {}
    with open(COST_LOG, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if technique is not None and e.get("technique") != technique:
                continue
            secs = float(e.get("seconds", 0) or 0)
            total += secs
            by_phase[e.get("phase", "?")] = round(by_phase.get(e.get("phase", "?"), 0.0) + secs, 2)
    return {"total_seconds": round(total, 2), "by_phase": by_phase}
