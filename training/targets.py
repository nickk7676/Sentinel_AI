"""
Step 5 - target diversity registry.

Every technique now has 4 lab targets instead of 1, each speaking the exact
same HTTP contract (same vulnerable route/request/response shape, same
CANARY) as the original Flask target, but implemented on a structurally
different stack:

  - <technique>          (flask)   - original Step 3 target. Training pool.
  - <technique>_express  (express) - new framework/DB/auth. Training pool.
  - <technique>_django   (django)  - new framework/DB/auth. Held out from
                                      training entirely - eval-harness-only
                                      generalization test (plan step 5.4).
  - <technique>_distractor (flask) - vuln patched, logging kept alarming-
                                      looking, to build blue's precision
                                      instead of keyword-matching (5.3).

agents/techniques/*.py and agents/judge/ground_truth.py need no changes -
both are already target-agnostic (they only ever receive target_url as a
plain string), so this registry is the only new piece of plumbing needed.
"""

import random
from dataclasses import dataclass

_TECHNIQUE_IDS = (
    "sql_injection",
    "command_injection",
    "idor",
    "path_traversal",
    "broken_auth",
    "ssrf",
)

# Fixed port per (technique, framework) - matches each lab/<dir>/docker-compose.yml.
_FLASK_PORTS = {"sql_injection": 5001, "command_injection": 5002, "idor": 5003,
                "path_traversal": 5004, "broken_auth": 5005, "ssrf": 5006}
_EXPRESS_PORTS = {"sql_injection": 5101, "command_injection": 5102, "idor": 5103,
                   "path_traversal": 5104, "broken_auth": 5105, "ssrf": 5106}
_DJANGO_PORTS = {"sql_injection": 5201, "command_injection": 5202, "idor": 5203,
                  "path_traversal": 5204, "broken_auth": 5205, "ssrf": 5206}
_DISTRACTOR_PORTS = {"sql_injection": 5301, "command_injection": 5302, "idor": 5303,
                      "path_traversal": 5304, "broken_auth": 5305, "ssrf": 5306}

# Chance a training battle is pointed at the distractor instead of a real
# vulnerable training target - low enough that red still gets plenty of
# real practice, high enough that both sides see it regularly (5.3).
DISTRACTOR_PROBABILITY = 0.15


@dataclass(frozen=True)
class LabTarget:
    id: str
    technique_id: str
    framework: str  # "flask" | "express" | "django"
    port: int
    vulnerable: bool
    role: str  # "train" | "heldout" | "distractor"

    @property
    def url(self) -> str:
        return f"http://localhost:{self.port}"


def _build_targets() -> list[LabTarget]:
    targets = []
    for tech in _TECHNIQUE_IDS:
        targets.append(LabTarget(tech, tech, "flask", _FLASK_PORTS[tech], True, "train"))
        targets.append(LabTarget(f"{tech}_express", tech, "express", _EXPRESS_PORTS[tech], True, "train"))
        targets.append(LabTarget(f"{tech}_django", tech, "django", _DJANGO_PORTS[tech], True, "heldout"))
        targets.append(LabTarget(f"{tech}_distractor", tech, "flask", _DISTRACTOR_PORTS[tech], False, "distractor"))
    return targets


TARGETS: list[LabTarget] = _build_targets()
_BY_ID: dict[str, LabTarget] = {t.id: t for t in TARGETS}


def get_target(target_id: str) -> LabTarget:
    try:
        return _BY_ID[target_id]
    except KeyError:
        raise KeyError(f"No such lab target {target_id!r} - known ids: {sorted(_BY_ID)}") from None


def targets_for(technique_id: str, role: str | None = None) -> list[LabTarget]:
    return [t for t in TARGETS if t.technique_id == technique_id and (role is None or t.role == role)]


def training_targets_for(technique_id: str) -> list[LabTarget]:
    """Targets eligible during battle_loop.py training: the real training-pool
    targets plus the distractor. Never the held-out django target (5.4)."""
    return targets_for(technique_id, role="train") + targets_for(technique_id, role="distractor")


def heldout_targets_for(technique_id: str) -> list[LabTarget]:
    """Targets battle_loop.py never sees - eval_harness.py's generalization
    check (5.4): the never-trained-on django target, plus the distractor
    (also useful held out, to measure precision on unseen alarming-but-safe
    traffic)."""
    return targets_for(technique_id, role="heldout") + targets_for(technique_id, role="distractor")


def pick_training_target(technique_id: str, rng: random.Random | None = None) -> LabTarget:
    """Weighted per-battle pick for battle_loop.py (5.2): DISTRACTOR_PROBABILITY
    chance of the distractor, otherwise a uniform pick among the real
    training-pool targets (flask + express)."""
    rng = rng or random
    train_pool = targets_for(technique_id, role="train")
    distractor = targets_for(technique_id, role="distractor")
    if distractor and rng.random() < DISTRACTOR_PROBABILITY:
        return distractor[0]
    return rng.choice(train_pool)
