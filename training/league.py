"""
Checkpoint league for self-play (Step 9.3).

Red and blue train against each other, which risks "self-play collapse": each
side co-adapts to the OTHER side's current quirks instead of learning
generalizable skill - red learns to beat this week's blue, blue learns to
catch this week's red, and both look strong while actually being brittle. The
standard defense is a league: keep snapshots of past adapter versions and have
each side occasionally face an OLD opponent, not only the current one, so
neither can overfit to a single moving target.

This module provides the league's mechanics:
  - snapshot(): after a training run bumps an adapter's version, copy that
    adapter's weights into an immutable, versioned archive under
    training/adapters/league/.
  - available_versions(): which past checkpoints exist for an agent/technique.
  - pick_opponent_version(): the matchmaking policy - usually the current
    version (normal self-play), but with probability `p_past` an older one,
    weighted toward recent versions so opponents stay relevant.
  - opponent_adapter_path(): where a chosen snapshot lives, to point the
    opposing agent at it (agents read RED_ADAPTER_PATH_OVERRIDE /
    BLUE_ADAPTER_PATH for exactly this).

Snapshotting is cheap and always safe to run. Actually PLAYING past opponents
is opt-in in battle_loop (the --league flag), since it loads an extra adapter.
"""

from __future__ import annotations

import json
import random
import shutil
from pathlib import Path

from training.train_agent import ADAPTERS_DIR, adapter_path

LEAGUE_DIR = ADAPTERS_DIR / "league"


def _versions_root(agent: str, technique: str | None) -> Path:
    # red is per-technique (league/red/<technique>/), blue is shared (league/blue/).
    if agent == "red":
        if not technique:
            raise ValueError("red league checkpoints are per-technique; technique is required")
        return LEAGUE_DIR / "red" / technique
    return LEAGUE_DIR / "blue"


def opponent_adapter_path(agent: str, technique: str | None, version: int) -> Path:
    return _versions_root(agent, technique) / f"v{version}"


def snapshot(agent: str, technique: str | None, version: int) -> Path | None:
    """Copy the agent's current live adapter into the league as v<version>.
    No-op (returns the existing path) if that version is already archived, or
    returns None if there's no adapter on disk yet. Call right after a
    training run completes and bumps the version."""
    live = adapter_path(agent, technique) if agent == "red" else adapter_path(agent)
    live = Path(live)
    if not (live / "adapter_config.json").exists():
        return None
    dest = opponent_adapter_path(agent, technique, version)
    if (dest / "adapter_config.json").exists():
        return dest  # already archived this version
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(live, dest, dirs_exist_ok=True)
    return dest


def available_versions(agent: str, technique: str | None) -> list[int]:
    root = _versions_root(agent, technique)
    if not root.exists():
        return []
    out = []
    for d in root.iterdir():
        if d.is_dir() and d.name.startswith("v") and (d / "adapter_config.json").exists():
            try:
                out.append(int(d.name[1:]))
            except ValueError:
                continue
    return sorted(out)


def pick_opponent_version(
    current_version: int,
    available: list[int],
    rng: random.Random | None = None,
    p_past: float = 0.5,
) -> int | None:
    """Matchmaking: return None to use the CURRENT live adapter (normal
    self-play), or a past version to face instead. With probability `p_past`
    (and at least one past version archived), pick an older version, weighted
    toward more recent ones (weight = version number) so opponents stay
    relevant rather than ancient. Returns None whenever there's no genuinely
    older checkpoint to use."""
    rng = rng or random
    past = [v for v in available if v < current_version]
    if not past or rng.random() >= p_past:
        return None
    weights = [float(v) for v in past]  # higher (more recent) version -> more likely
    return rng.choices(past, weights=weights, k=1)[0]
