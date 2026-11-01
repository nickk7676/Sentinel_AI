"""
Fine-tunes the router's LoRA adapter (Step 8 - deferred until
training/router_baseline_eval.py's baseline check justified it; see
build_router_dataset.py's module docstring for that result).

Reuses training/train_agent.py's train() directly - same base model, same
LoRA config shape, same continue-training-if-adapter-exists behavior, just
pointed at the router's own dataset with agent_name="router". That saves to
training/adapters/router_team/ (train_agent.py's adapter_path("router") -
already generic over agent_name, no change needed there), exactly where
agents/red_team/router/router.py already looks for one - so the very next
decide() call after this finishes picks it up automatically, no other code
to touch.

train_agent.py's own dataset formatting (_format() inside train()) already
handles messages with no tool_calls correctly (tools=None when none are
present) - router training examples are plain system/user/assistant JSON
turns, never tool-calling transcripts, so no changes were needed there
either.

Usage:
  python -m agents.red_team.router.build_router_dataset   # first, to populate data
  python -m agents.red_team.router.train_router
"""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from training.dataset import get_router_data_path
from training.train_agent import train


def _balanced_data_path(max_examples: int, per_technique_cap: int) -> list[str]:
    """Keep at most `per_technique_cap` of the newest examples PER technique,
    so one over-represented technique can't teach a majority-class "when
    unsure, guess this" shortcut. Measured need: sql_injection had 23 mined
    examples vs command_injection's 6, and the router defaulted its first pick
    to sql_injection whenever a target's clue was weak. Capping each technique
    evens the classes out; the newest-first order is preserved within each."""
    all_paths = get_router_data_path(max_examples=None)  # all, newest first
    by_tech: dict[str, list[str]] = defaultdict(list)
    for p in all_paths:
        try:
            tech = json.loads(Path(p).read_text(encoding="utf-8")).get("technique", "?")
        except (OSError, json.JSONDecodeError):
            continue
        by_tech[tech].append(p)
    selected: list[str] = []
    for paths in by_tech.values():
        selected.extend(paths[:per_technique_cap])
    print(f"  Balanced to <= {per_technique_cap}/technique: "
          + ", ".join(f"{t}={min(len(p), per_technique_cap)}" for t, p in sorted(by_tech.items())))
    return selected[:max_examples] if max_examples else selected


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fine-tune the router's LoRA adapter (Step 8)")
    parser.add_argument("--max-examples", type=int, default=200,
                         help="Sliding window: max recent router examples used for this training run.")
    parser.add_argument("--per-technique-cap", type=int, default=None,
                         help="If set, keep at most this many of the newest examples per technique "
                              "before training, to prevent an over-represented technique from teaching "
                              "a majority-class guess bias. Unset = use every example (old behavior).")
    args = parser.parse_args()

    if args.per_technique_cap is not None:
        data_path = _balanced_data_path(args.max_examples, args.per_technique_cap)
    else:
        data_path = get_router_data_path(max_examples=args.max_examples)
    if not data_path:
        print("No router training data found. Run agents.red_team.router.build_router_dataset first "
              "(which itself needs real sessions from agents.red_team.router.battle_runner).")
    else:
        print(f"Training router on {len(data_path)} example(s)...")
        train("router", data_path)
