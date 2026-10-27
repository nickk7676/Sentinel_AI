"""
Builds the router's LoRA training dataset (Step 8) from GROUND TRUTH.

This replaces the earlier "self-play win-mining" approach, which derived each
training label from whichever technique *won* a battle. That was unreliable:
some targets satisfy more than one technique's success check, so the label
could be wrong. Concretely - a broken_auth target's login hands a session
token to any request with no credentials, so SQL-injection's "did I get in?"
check also passes there, and that battle got mined as a *sql_injection win on
a broken_auth target*. 71 of 88 mined "sql_injection" examples turned out to
be this poison, and training on it is exactly what taught the router to guess.

Ground-truth labeling sidesteps the whole problem. We already know what each
lab target is actually vulnerable to - it's declared in training/targets.py
(Target.technique_id). So for each vulnerable training target we:

  1. Run the real front-loaded recon (battle_runner._initial_recon) to get the
     exact opening state the router sees at inference time.
  2. Label that state with the target's TRUE technique_id - never a guess.
  3. Write `--copies` identical copies so every technique is represented
     equally (recon is deterministic, so there is one state per target;
     copies give each class equal training weight without any class
     out-numbering another).

The result is correct labels, perfectly balanced, with no false wins - the
only way the pool is built now. The builder CLEARS the pool first
(dataset.reset_router_examples), so after a run the pool is EXACTLY this
ground-truth set, with nothing stale surviving from an older build.

Requires the lab targets running (recon makes real HTTP probes) - same
requirement as battle_runner.py / the lab/*/docker-compose.yml stacks.

Usage:
  python -m agents.red_team.router.build_router_dataset             # 10 copies/target (default)
  python -m agents.red_team.router.build_router_dataset --copies 15
  python -m agents.red_team.router.build_router_dataset --no-reset  # add to the pool instead of rebuilding it
"""

from __future__ import annotations

import argparse
import os

from agents.red_team.router.battle_runner import _initial_recon
from agents.red_team.router.router import SYSTEM_PROMPT, build_prompt
from agents.red_team.router.state import new_state, to_prompt_block
from agents.techniques import list_techniques
from training.dataset import reset_router_examples, save_router_example
from training.targets import TARGETS


def build_ground_truth_dataset(copies: int = 10, reset: bool = True) -> int:
    """Write `copies` ground-truth examples per vulnerable training target.

    Each example pairs the target's real opening-recon state with the
    technique it is ACTUALLY vulnerable to (Target.technique_id), never a
    battle-derived guess. Returns the number of examples written.

    reset=True (the default) deletes the existing pool first, so the pool
    ends up being exactly this freshly-built ground-truth set.
    """
    all_tech = [t.id for t in list_techniques()]
    vuln_train = [t for t in TARGETS if t.role == "train" and t.vulnerable]

    # Gather every target's recon-derived prompt FIRST, before touching the
    # existing pool. Recon makes real HTTP probes, so if the lab containers
    # are down this is where it fails - and we must not have wiped the pool
    # by then. Only once we have a full set do we reset and write.
    gathered: list[tuple[str, str, dict]] = []
    for t in vuln_train:
        state = new_state()
        _initial_recon(t.url, state)  # real front-loaded recon -> the opening state decide() sees
        user_prompt = build_prompt(to_prompt_block(state), list(all_tech), recon_exhausted=True)
        decision = {
            "action": "invoke_technique",
            "technique_id": t.technique_id,
            "reasoning": f"The recon findings point to {t.technique_id} as the technique that fits this target.",
        }
        gathered.append((t.id, user_prompt, decision))

    if not gathered:
        print("  No vulnerable training targets found - nothing to build, pool left untouched.")
        return 0

    if reset:
        removed = reset_router_examples()
        print(f"  Cleared {removed} existing example(s) - rebuilding pool from ground truth.")

    written = 0
    for target_id, user_prompt, decision in gathered:
        for _ in range(copies):
            save_router_example(SYSTEM_PROMPT, user_prompt, decision, decision["technique_id"])
            written += 1
        print(f"  {target_id:28s} -> {decision['technique_id']:16s} x{copies}")

    return written


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the router's LoRA training dataset from ground truth (Step 8)")
    parser.add_argument("--copies", type=int, default=10,
                        help="Identical copies to write per target (gives each technique equal training "
                             "weight; recon is deterministic so there is one state per target). Default 10.")
    parser.add_argument("--no-reset", action="store_true",
                        help="Append to the existing pool instead of clearing it first. Default is to clear, "
                             "so the pool ends up being exactly this ground-truth set.")
    args = parser.parse_args()

    os.environ.setdefault("LLM_PROVIDER", "local")

    n = build_ground_truth_dataset(copies=args.copies, reset=not args.no_reset)
    vuln_train = [t for t in TARGETS if t.role == "train" and t.vulnerable]
    print(f"\nWrote {n} ground-truth example(s) ({len(vuln_train)} targets x {args.copies} copies).")
    if n == 0:
        print("\nNo examples written. Are the lab targets running? Recon makes real HTTP probes "
              "(see lab/*/docker-compose.yml).")
