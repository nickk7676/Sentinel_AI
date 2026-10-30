"""Clean, scripted-feeling terminal narration for the demo.

Pure presentation: every value printed here comes from a REAL router/red/blue
event captured during the run. This module only formats and colors it. It does
not decide outcomes.

Sections: RECON (what the scanner found) -> ROUTER (what it chose, and why)
-> RED (the live attack, streamed action-by-action) -> BLUE (detection + fix).
"""

from __future__ import annotations

import sys
import time

# --- ANSI colors (enable on Windows terminals) -----------------------------
try:  # pragma: no cover - cosmetic
    import colorama
    colorama.just_fix_windows_console()
except Exception:  # noqa: BLE001
    import os
    os.system("")  # enables ANSI on modern Windows consoles

# Windows consoles / redirected stdout default to cp1252, which can't encode the
# box-drawing/arrow/✓ glyphs used below (and breaks on `> file` redirection).
# Force UTF-8 so the narration renders (and logs) correctly everywhere.
try:  # pragma: no cover - cosmetic
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GREY = "\033[90m"
RED_BG = "\033[41m\033[97m"

RED_TAG = f"{BOLD}{RED}"
BLUE_TAG = f"{BOLD}{CYAN}"

# Typing speed for the "scripted-feeling" effect. Set TYPE_DELAY=0 for instant.
TYPE_DELAY = 0.012


def _emit(text: str, newline: bool = True, delay: float | None = None) -> None:
    d = TYPE_DELAY if delay is None else delay
    if d <= 0:
        sys.stdout.write(text)
    else:
        for ch in text:
            sys.stdout.write(ch)
            sys.stdout.flush()
            time.sleep(d)
    if newline:
        sys.stdout.write("\n")
    sys.stdout.flush()


def rule(label: str, color: str = GREY) -> None:
    bar = "─" * max(2, 40 - len(label))
    _emit(f"\n{color}── {BOLD}{label}{RESET}{color} {bar}{RESET}", delay=0)


def section_recon(lines: list[str]) -> None:
    rule("RECON", CYAN)
    for ln in lines:
        _emit(f"  {GREY}{ln}{RESET}")


def section_router(technique: str, reason: str) -> None:
    rule("ROUTER", YELLOW)
    _emit(f"  {YELLOW}selected: {BOLD}{technique}{RESET}")
    if reason:
        _emit(f"  {DIM}{reason}{RESET}")


def red_header(adapter: str) -> None:
    rule(f"RED · {adapter} adapter", RED)


def red_action(line: str, hit: bool = False) -> None:
    mark = f"{GREEN}✓{RESET}" if hit else f"{GREY}→{RESET}"
    color = GREEN if hit else GREY
    _emit(f"  {mark} {color}{line}{RESET}")


def red_success(msg: str) -> None:
    _emit(f"  {BOLD}{GREEN}✓ {msg}{RESET}")


def blue_header() -> None:
    rule("BLUE · detection & response", BLUE)


def blue_verdict(detected: bool, category: str, fix: str, explanation: str = "") -> None:
    if detected:
        _emit(f"  {BOLD}{RED}⚑ THREAT DETECTED{RESET} {RED}{category}{RESET}")
    else:
        _emit(f"  {GREEN}✓ no threat — benign traffic{RESET}")
    if explanation:
        _emit(f"  {DIM}{explanation}{RESET}")
    if fix:
        _emit(f"  {BOLD}fix:{RESET} {fix}")


def log_line(raw: str, flagged: bool) -> None:
    """One telemetry line in the live log view. Blue-flagged = red highlight;
    benign = dim grey."""
    if flagged:
        _emit(f"  {RED_BG} ATTACK {RESET} {RED}{raw}{RESET}", delay=0)
    else:
        _emit(f"  {GREY}        {raw}{RESET}", delay=0)


def banner(text: str) -> None:
    _emit(f"\n{BOLD}{CYAN}{text}{RESET}\n", delay=0)
