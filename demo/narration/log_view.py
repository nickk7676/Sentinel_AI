"""Live log view with blue-driven highlighting (the zero-false-positive demo).

The portal's telemetry is a mix of REAL benign traffic and the REAL attack.
This view feeds each log event through BLUE and highlights in red ONLY the
events blue itself flags as malicious — benign lines stay dim. The red/benign
split is therefore blue's real verdict, not a pre-labeled list.

An "event" is one logical action's log line(s). Classification is done once
(blue inference is slow), cached, then rendered — so the on-screen playback is
smooth while remaining blue's genuine output.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from demo.narration import demo_mode as ui


@dataclass
class LogEvent:
    """One logical event: its raw telemetry line(s) and, after classification,
    blue's verdict."""
    raw_lines: list[str]
    source: str = "unknown"          # "benign" or "attack" — provenance, for the summary only
    flagged: bool | None = None       # blue's verdict (set by classify)
    category: str = ""
    verdict: dict = field(default_factory=dict)


# A classifier takes a chunk of telemetry text and returns blue's verdict dict
# ({"threat_detected": bool, "threat_category": str, ...}). The orchestrator
# injects the real BlueTeamAgent.defend_live; tests can inject a stub.
Classifier = Callable[[str], dict]


def classify_events(events: list[LogEvent], classify: Classifier) -> list[LogEvent]:
    """Run blue over each event once; record its real verdict. Cached on the
    event so rendering doesn't re-invoke blue."""
    for ev in events:
        text = "\n".join(ev.raw_lines)
        verdict = classify(text) or {}
        ev.verdict = verdict
        ev.flagged = bool(verdict.get("threat_detected"))
        ev.category = verdict.get("threat_category", "")
    return events


def render(events: list[LogEvent], type_delay: float = 0.0) -> dict:
    """Print the log with blue-driven highlighting. Returns a small summary
    dict for the no-false-positive claim."""
    ui.rule("LIVE TELEMETRY — blue highlights only what IT flags", ui.CYAN)
    fp = fn = tp = tn = 0
    for ev in events:
        for raw in ev.raw_lines:
            ui.log_line(raw, bool(ev.flagged))
            if type_delay:
                time.sleep(type_delay)
        # bookkeeping vs provenance (for the honest summary line only)
        if ev.source == "attack":
            if ev.flagged:
                tp += 1
            else:
                fn += 1
        elif ev.source == "benign":
            if ev.flagged:
                fp += 1
            else:
                tn += 1
    total = tp + tn + fp + fn
    summary = {
        "attacks_flagged": tp,
        "attacks_missed": fn,
        "benign_flagged_false_positives": fp,
        "benign_correctly_ignored": tn,
        "total_events": total,
    }
    ui.rule("SUMMARY", ui.GREY)
    ui._emit(
        f"  {ui.BOLD}attacks flagged: {ui.GREEN}{tp}{ui.RESET}{ui.BOLD}  |  "
        f"benign false positives: {ui.RED if fp else ui.GREEN}{fp}{ui.RESET}",
        delay=0,
    )
    return summary
