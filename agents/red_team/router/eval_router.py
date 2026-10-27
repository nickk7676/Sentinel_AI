"""
Measure the router's FIRST-PICK accuracy on live front-loaded recon (Step 8).

This is the fast, honest way to see how the router is doing. For each
vulnerable target it runs the exact opening recon pass battle_runner uses,
then asks decide() once (recon_exhausted=True - the real inference shape)
which technique to open with, and scores that first pick against the
target's known true vulnerability.

Why first-pick and not "did the battle eventually win?": a router that cycles
through techniques until one happens to work looks successful end-to-end
while actually just guessing. First-pick isolates the only thing the router
is responsible for - reading the recon clue and choosing correctly on the
first move. Decoding is greedy (see router.py), so one trial is already
deterministic; --trials is only useful if you change that back to sampling.

By default it evaluates the trained targets. --include-heldout also scores
the never-trained django targets (role="heldout"), which is the real
generalization test: those were never in any training data, so getting them
right means the router learned to read clues, not memorize targets.

Requires the lab targets running (recon makes real HTTP probes - the same
docker compose stacks under lab/*/). Does NOT run any attack, so it is much
faster than a full battle_runner battle.

Usage:
  python -m agents.red_team.router.eval_router
  python -m agents.red_team.router.eval_router --include-heldout
  python -m agents.red_team.router.eval_router --trials 3
"""

from __future__ import annotations

import argparse
import os
from collections import defaultdict

from agents.red_team.router.battle_runner import _initial_recon
from agents.red_team.router.router import decide, unload_router_model
from agents.red_team.router.state import new_state
from agents.techniques import list_techniques
from training.targets import TARGETS


def _eval_targets(targets: list, trials: int) -> None:
    all_tech = [t.id for t in list_techniques()]

    print("Gathering front-loaded recon for each target (one HTTP pass each)...", flush=True)
    states = {}
    for t in targets:
        st = new_state()
        _initial_recon(t.url, st)
        states[t.id] = st

    per_tech_correct: dict = defaultdict(int)
    per_tech_total: dict = defaultdict(int)
    first_picks: dict = defaultdict(lambda: defaultdict(int))
    correct = total = 0

    for trial in range(trials):
        if trials > 1:
            print(f"\n=== TRIAL {trial + 1}/{trials} ===", flush=True)
        for t in targets:
            d = decide(states[t.id], list(all_tech), recon_exhausted=True)
            pick = d.technique_id if d.action == "invoke_technique" else f"({d.action})"
            ok = d.action == "invoke_technique" and d.technique_id == t.technique_id
            correct += ok
            total += 1
            per_tech_correct[t.technique_id] += ok
            per_tech_total[t.technique_id] += 1
            first_picks[t.technique_id][pick] += 1
            print(f"  {t.id:30s} true={t.technique_id:16s} picked={pick:18s} {'OK' if ok else 'x  <-- MISS'}", flush=True)

    print("\n" + "=" * 64)
    print(f"  FIRST-PICK ACCURACY: {correct}/{total} = {100 * correct / total:.0f}%" if total else "  (no targets evaluated)")
    print("=" * 64)
    print("\n  Per-technique (and what it actually opened with):")
    for tech in sorted(per_tech_total):
        acc = 100 * per_tech_correct[tech] / per_tech_total[tech]
        picks = dict(first_picks[tech])
        print(f"    {tech:16s} {per_tech_correct[tech]}/{per_tech_total[tech]} = {acc:3.0f}%   picks={picks}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Measure the router's first-pick accuracy on live recon (Step 8)")
    parser.add_argument("--trials", type=int, default=1,
                        help="Repeat the whole pass N times. Greedy decoding makes one trial deterministic, "
                             "so >1 only matters if routing is switched back to sampling. Default 1.")
    parser.add_argument("--include-heldout", action="store_true",
                        help="Also score the never-trained django targets (role=heldout) - the real "
                             "generalization test (clue-reading vs. memorization).")
    args = parser.parse_args()

    os.environ.setdefault("LLM_PROVIDER", "local")

    roles = ("train", "heldout") if args.include_heldout else ("train",)
    targets = [t for t in TARGETS if t.role in roles and getattr(t, "vulnerable", False)]

    try:
        _eval_targets(targets, trials=args.trials)
    finally:
        unload_router_model()
