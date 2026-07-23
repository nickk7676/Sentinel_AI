"""
Step 4.2 - full per-battle logging.

Unlike training/dataset.py (which only ever saves *winning* examples, scoped
per technique, for fine-tuning) this logs every battle - win, loss, or draw -
with the full transcript, reward/verdict, and the adapter version each side
was running at the time. This is what later analysis (and the eval harness)
reads to answer "is round 50 better than round 10."

One JSON line per battle. Stored under DATA_DIR (see training/dataset.py)
rather than inside the repo, for the same reason training examples are:
avoids OneDrive/Defender append-lock issues on Windows.
"""

import json
import time

from training.dataset import DATA_DIR

BATTLE_LOG_FILE = DATA_DIR / "battle_log.jsonl"


def log_battle(
    *,
    source: str,
    technique: str,
    round_num: int | None,
    battle_num: int | None,
    target_url: str,
    attack: dict,
    defense: dict,
    verdict: dict,
    red_adapter_version: int,
    blue_adapter_version: int,
    target_id: str | None = None,
    target_role: str | None = None,
    target_framework: str | None = None,
) -> None:
    """Append one battle's full record.

    source:      "train" (battle_loop.py) or "eval" (eval_harness.py) - lets
                 later analysis exclude held-out eval battles from anything
                 that's meant to describe training-time behavior, and vice versa.
    round_num:   training round number, or None for a standalone eval run.
    battle_num:  position within the round/run, or None if not applicable.
    target_id/target_role/target_framework: Step 5 target diversity (see
                 training/targets.py) - which of a technique's several lab
                 targets this battle actually ran against, so later analysis
                 can slice by target (e.g. "train" vs "heldout"), not just
                 by technique. None for any caller that hasn't been updated
                 to pass a LabTarget (e.g. an ad hoc --target-url override).
    """
    BATTLE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp": time.time(),
        "source": source,
        "technique": technique,
        "round": round_num,
        "battle": battle_num,
        "target_url": target_url,
        "target_id": target_id,
        "target_role": target_role,
        "target_framework": target_framework,
        "was_attack": attack.get("was_attack", True),
        "attack": attack,
        "defense": defense,
        "verdict": verdict,
        "red_adapter_version": red_adapter_version,
        "blue_adapter_version": blue_adapter_version,
    }
    with open(BATTLE_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
