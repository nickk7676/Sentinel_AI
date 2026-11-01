"""
Baseline measurement for the Step 8 router.

Per the project plan: measure plain-base-model technique-selection accuracy
BEFORE building any router training pipeline - agents/red_team/router/'s
build_router_dataset.py / train_router.py are deliberately deferred until
this number says they're needed (no router adapter exists yet, so
agents.red_team.router.router.decide() already runs on the plain base model
automatically).

Mines real completed battles from training/dataset.py's DATA_DIR/
battle_log.jsonl, hides the technique label, and asks decide() to pick a
technique from target metadata alone - there's no retroactive recon for
these historical battles (Step 8's recon tools didn't exist when they were
logged), so this measures a harder, information-poorer version of the task
than agents/red_team/router/battle_runner.py's actual live behavior. Treat
the number this prints as a lower bound, not the real ceiling.

Usage:
  python -m training.router_baseline_eval --sample 40
"""

import argparse
import collections
import json
import os
import random

from agents.red_team.router.router import decide, unload_router_model
from agents.red_team.router.schema import BattleState
from agents.techniques import list_techniques
from training.dataset import DATA_DIR
from training.targets import TARGETS

BATTLE_LOG_FILE = DATA_DIR / "battle_log.jsonl"


def _target_metadata(target_url: str) -> tuple[str | None, str | None]:
    for t in TARGETS:
        if t.url == target_url:
            return t.role, t.framework
    return None, None


def _load_successful_battles() -> list[dict]:
    battles = []
    if not BATTLE_LOG_FILE.exists():
        return battles
    with BATTLE_LOG_FILE.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("was_attack") and entry.get("verdict", {}).get("attack_success"):
                battles.append(entry)
    return battles


def _state_for_battle(entry: dict) -> BattleState:
    """Target-metadata-only state - no recon findings, matching the fact
    that these historical battles predate Step 8's recon tools entirely."""
    state = BattleState()
    role, framework = _target_metadata(entry.get("target_url", ""))
    note = f"Target metadata only (no recon available for this historical battle): url={entry.get('target_url')}"
    if framework:
        note += f", framework={framework}"
    if role:
        note += f", role={role}"
    state.chain_notes.append(note)
    return state


def run_baseline_eval(sample: int = 40, seed: int = 0) -> dict:
    battles = _load_successful_battles()
    if not battles:
        raise SystemExit(f"No successful battles found in {BATTLE_LOG_FILE} - run training.battle_loop first.")

    rng = random.Random(seed)
    picked = rng.sample(battles, min(sample, len(battles)))

    available_techniques = [t.id for t in list_techniques()]
    matches = 0
    confusion: collections.Counter = collections.Counter()  # (actual, predicted) -> count
    per_technique_total: collections.Counter = collections.Counter()
    per_technique_match: collections.Counter = collections.Counter()

    for i, entry in enumerate(picked, 1):
        actual = entry["technique"]
        state = _state_for_battle(entry)
        decision = decide(state, available_techniques, recon_exhausted=True)
        predicted = decision.technique_id if decision.action == "invoke_technique" else None

        is_match = predicted == actual
        matches += int(is_match)
        confusion[(actual, predicted)] += 1
        per_technique_total[actual] += 1
        per_technique_match[actual] += int(is_match)

        print(f"  [{i:02d}/{len(picked)}] actual={actual:<20} predicted={str(predicted):<20} action={decision.action:<16} match={is_match}")

    total = len(picked)
    print("\n" + "=" * 60)
    print(f"  BASELINE ROUTER ACCURACY: {matches}/{total} ({matches / total:.1%})")
    print("=" * 60)
    print("  Per-technique:")
    for tech in sorted(per_technique_total):
        t = per_technique_total[tech]
        m = per_technique_match[tech]
        print(f"    {tech:<20} {m}/{t} ({m / t:.1%})")
    print("\n  Confusion (actual -> predicted):")
    for (actual, predicted), count in sorted(confusion.items(), key=lambda kv: -kv[1]):
        print(f"    {actual:<20} -> {str(predicted):<20} x{count}")

    print(
        "\n  NOTE: this measures the router against a harder, information-poorer version of "
        "the task than it actually gets at runtime - these historical battles have no recon "
        "findings (Step 8's recon tools didn't exist yet when they were logged), only target "
        "metadata. Treat this number as a LOWER BOUND, not the real ceiling - judge the router "
        "against agents/red_team/router/battle_runner.py's live behavior (with real recon) "
        "before deciding whether training a router adapter is actually needed."
    )

    return {
        "sample": total,
        "matches": matches,
        "accuracy": matches / total,
        "per_technique": {t: per_technique_match[t] / per_technique_total[t] for t in per_technique_total},
    }


if __name__ == "__main__":
    os.environ.setdefault("LLM_PROVIDER", "local")

    parser = argparse.ArgumentParser(
        description="Measure baseline (no-adapter) router technique-selection accuracy against real historical battles",
    )
    parser.add_argument("--sample", type=int, default=40)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    try:
        run_baseline_eval(sample=args.sample, seed=args.seed)
    finally:
        unload_router_model()
