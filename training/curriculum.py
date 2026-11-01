"""
Curriculum learning for the self-play loop (Step 9.1).

Instead of throwing every target at red/blue at full difficulty from battle
one, start on the easiest target for a technique and only UNLOCK harder ones
once performance on the unlocked set has stabilized. Easier structural
variants first (the original Flask app), then a different framework (Express),
then genuinely multi-step targets - so the models build a foundation before
facing the hard cases, which is both faster and steadier than uniform random
sampling from day one.

Difficulty tiers (by target, from training/targets.py):
  tier 1 - the original Flask target (and distractors, which are tier-1 flask)
  tier 2 - the Express/Node target (different framework / DB / auth)
  tier 3 - a multi-step / chained target (the chained_privesc scenario)

The held-out Django targets are never in the training pool (Step 5.4), so they
have no tier here. Distractors (Step 5.3) stay available at every tier - their
job is blue's precision, not difficulty progression.

State is a tiny per-technique JSON file: the highest tier unlocked so far plus
a rolling window of recent real-attack outcomes. When the window is full and
the recent success rate clears PROMOTE_AT, the next tier unlocks and the window
resets. Promotion is one-way (never demotes) and capped at the hardest tier a
technique actually has, so a technique with only one target just stays at tier 1.
"""

from __future__ import annotations

import json
import random

from training.dataset import DATA_DIR
from training.targets import DISTRACTOR_PROBABILITY, training_targets_for

_CURRICULUM_DIR = DATA_DIR / "curriculum"

_FRAMEWORK_TIER = {"flask": 1, "express": 2, "django": 3}

# Targets that are inherently multi-step get bumped to the top tier regardless
# of framework - clearing a chained target is a harder skill than any
# single-shot one.
_MULTISTEP_TARGET_IDS = {"chained_privesc"}

WINDOW = 20          # recent real-attack outcomes considered for promotion
PROMOTE_AT = 0.70    # unlock the next tier once the recent success rate clears this


def target_difficulty(target) -> int:
    if target.id in _MULTISTEP_TARGET_IDS:
        return 3
    return _FRAMEWORK_TIER.get(target.framework, 1)


def _max_tier(technique: str) -> int:
    reals = [t for t in training_targets_for(technique) if t.role == "train"]
    return max((target_difficulty(t) for t in reals), default=1)


def _state_file(technique: str):
    return _CURRICULUM_DIR / f"{technique}.json"


def _load(technique: str) -> dict:
    f = _state_file(technique)
    if not f.exists():
        return {"unlocked_tier": 1, "recent": []}
    try:
        s = json.loads(f.read_text(encoding="utf-8"))
        return {"unlocked_tier": int(s.get("unlocked_tier", 1)), "recent": list(s.get("recent", []))}
    except (json.JSONDecodeError, OSError, ValueError):
        return {"unlocked_tier": 1, "recent": []}


def _save(technique: str, state: dict) -> None:
    _CURRICULUM_DIR.mkdir(parents=True, exist_ok=True)
    _state_file(technique).write_text(json.dumps(state), encoding="utf-8")


def unlocked_tier(technique: str) -> int:
    return _load(technique)["unlocked_tier"]


def record_outcome(technique: str, real_attack_success: bool) -> int:
    """Feed one real-attack outcome (distractor/normal-traffic rounds are not
    real attacks and must not be passed here). Promotes to the next tier when
    the recent window is full and its success rate clears PROMOTE_AT. Returns
    the (possibly newly-raised) unlocked tier."""
    state = _load(technique)
    state["recent"].append(1 if real_attack_success else 0)
    state["recent"] = state["recent"][-WINDOW:]

    if (
        len(state["recent"]) >= WINDOW
        and state["unlocked_tier"] < _max_tier(technique)
        and sum(state["recent"]) / len(state["recent"]) >= PROMOTE_AT
    ):
        state["unlocked_tier"] += 1
        state["recent"] = []  # fresh window for the newly-unlocked, harder tier
    _save(technique, state)
    return state["unlocked_tier"]


def pick_curriculum_target(technique: str, rng: random.Random | None = None):
    """Like training/targets.pick_training_target, but restricted to the tiers
    unlocked so far: a DISTRACTOR_PROBABILITY chance of the distractor (always
    available - it's for blue precision), otherwise a uniform pick among the
    real training targets whose difficulty is within the unlocked tier."""
    rng = rng or random
    tier = unlocked_tier(technique)
    pool = training_targets_for(technique)
    distractors = [t for t in pool if t.role == "distractor"]
    allowed = [t for t in pool if t.role == "train" and target_difficulty(t) <= tier]
    if not allowed:  # safety net - never return nothing
        allowed = [t for t in pool if t.role == "train"]
    if distractors and rng.random() < DISTRACTOR_PROBABILITY:
        return distractors[0]
    return rng.choice(allowed)
