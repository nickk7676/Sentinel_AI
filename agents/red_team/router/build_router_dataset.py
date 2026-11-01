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
from collections import defaultdict

from agents.red_team.router.battle_runner import _initial_recon
from agents.red_team.router.router import SYSTEM_PROMPT, build_prompt
from agents.red_team.router.state import new_state, to_prompt_block, update_state
from agents.techniques import get_technique, list_techniques
from training.dataset import reset_router_examples, save_router_example
from training.targets import TARGETS

# Step 8.3 - router-orchestrated chained targets. Each needs TWO router
# training states, not one: open the chain with step_a, then - once step_a has
# leaked an artifact into the battle state - pick step_b. The post-leak state
# is reproduced here by actually running step_a's leak read and feeding its
# real result through update_state(), exactly as battle_runner does live, so
# the training state B matches the inference state B.
_CHAINED_TARGETS = {
    "chained_privesc": {
        "step_a": "token_leak",         # opening decision: steal the token
        "step_b": "account_takeover",   # after the leak: reuse it to win
        "leak_request_id": 1,           # the admin reset-request id token_leak reads first
    },
}


def _chain_examples(target, all_tech: list[str], per_technique: int) -> list[tuple[str, str, dict, int]]:
    """The two router-decision examples for one chained target (Step 8.3):
    (opening state -> step_a) and (post-leak state -> step_b)."""
    cfg = _CHAINED_TARGETS[target.id]

    # State A: the opening recon state, before anything is tried.
    state_a = new_state()
    _initial_recon(target.url, state_a)
    prompt_a = build_prompt(to_prompt_block(state_a), list(all_tech), recon_exhausted=True)
    decision_a = {
        "action": "invoke_technique",
        "technique_id": cfg["step_a"],
        "reasoning": f"The recon findings point to {cfg['step_a']} as the first step - disclose the reusable artifact before it can be used.",
    }

    # State B: the same recon, then step_a actually run against the live target
    # and folded in through update_state() - identical to how battle_runner
    # produces the state the router sees for its SECOND decision.
    state_b = new_state()
    _initial_recon(target.url, state_b)
    step_a_tech = get_technique(cfg["step_a"])
    leak_result = step_a_tech.execute_tool_call(
        target.url, step_a_tech.tool_schemas[0]["function"]["name"], {"request_id": cfg["leak_request_id"]},
    )
    update_state(state_b, {
        "attack_type": cfg["step_a"],
        "payload": step_a_tech.describe_attempt(leak_result),
        "success": False,
        "tool_calls": [leak_result],
        "artifacts": leak_result.get("artifacts", {}),
    })
    prompt_b = build_prompt(to_prompt_block(state_b), list(all_tech), recon_exhausted=True)
    decision_b = {
        "action": "invoke_technique",
        "technique_id": cfg["step_b"],
        "reasoning": f"A reusable artifact was leaked in the previous step, so {cfg['step_b']} can now use it to complete the chain.",
    }

    return [
        (f"{target.id}:A", prompt_a, decision_a, per_technique),
        (f"{target.id}:B", prompt_b, decision_b, per_technique),
    ]


def build_ground_truth_dataset(per_technique: int = 20, reset: bool = True) -> int:
    """Write ~`per_technique` ground-truth examples for EACH technique, split
    evenly across that technique's vulnerable training targets.

    Each example pairs a target's real opening-recon state with the technique
    it is ACTUALLY vulnerable to (Target.technique_id), never a battle-derived
    guess. Balancing per technique (not per target) keeps every class equally
    weighted even when techniques have different numbers of targets - e.g. the
    six original techniques have two training targets each (flask + express)
    while the chained_privesc target (Step 8.3) has one, so without this the
    chained class would train on half as many examples and the router could
    learn a "when unsure, don't pick chained" bias. Returns examples written.

    reset=True (the default) deletes the existing pool first, so the pool ends
    up being exactly this freshly-built ground-truth set.
    """
    all_tech = [t.id for t in list_techniques()]
    vuln_train = [t for t in TARGETS if t.role == "train" and t.vulnerable]

    # Chained targets need bespoke two-state handling; everything else is a
    # single opening-state -> true-technique example, balanced per technique.
    chain_targets = [t for t in vuln_train if t.id in _CHAINED_TARGETS]
    simple_targets = [t for t in vuln_train if t.id not in _CHAINED_TARGETS]

    by_tech: dict[str, list] = defaultdict(list)
    for t in simple_targets:
        by_tech[t.technique_id].append(t)

    # Gather every target's recon-derived prompt and its copy count FIRST,
    # before touching the existing pool. Recon makes real HTTP probes, so if
    # the lab containers are down this is where it fails - and we must not have
    # wiped the pool by then. Only once we have a full set do we reset + write.
    gathered: list[tuple[str, str, dict, int]] = []
    for tech_id, targets in by_tech.items():
        k = len(targets)
        base, remainder = divmod(per_technique, k)
        for i, t in enumerate(targets):
            copies_i = base + (1 if i < remainder else 0)  # spread the remainder over the first targets
            state = new_state()
            _initial_recon(t.url, state)  # real front-loaded recon -> the opening state decide() sees
            user_prompt = build_prompt(to_prompt_block(state), list(all_tech), recon_exhausted=True)
            decision = {
                "action": "invoke_technique",
                "technique_id": t.technique_id,
                "reasoning": f"The recon findings point to {t.technique_id} as the technique that fits this target.",
            }
            gathered.append((t.id, user_prompt, decision, copies_i))

    for t in chain_targets:
        gathered.extend(_chain_examples(t, all_tech, per_technique))

    if not gathered:
        print("  No vulnerable training targets found - nothing to build, pool left untouched.")
        return 0

    if reset:
        removed = reset_router_examples()
        print(f"  Cleared {removed} existing example(s) - rebuilding pool from ground truth.")

    written = 0
    for target_id, user_prompt, decision, copies_i in gathered:
        for _ in range(copies_i):
            save_router_example(SYSTEM_PROMPT, user_prompt, decision, decision["technique_id"])
            written += 1
        print(f"  {target_id:28s} -> {decision['technique_id']:16s} x{copies_i}")

    return written


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build the router's LoRA training dataset from ground truth (Step 8)")
    parser.add_argument("--per-technique", type=int, default=20,
                        help="Examples per TECHNIQUE, split evenly across that technique's training targets "
                             "(so every class is equally weighted regardless of how many targets it has). "
                             "Default 20.")
    parser.add_argument("--no-reset", action="store_true",
                        help="Append to the existing pool instead of clearing it first. Default is to clear, "
                             "so the pool ends up being exactly this ground-truth set.")
    args = parser.parse_args()

    os.environ.setdefault("LLM_PROVIDER", "local")

    n = build_ground_truth_dataset(per_technique=args.per_technique, reset=not args.no_reset)
    n_tech = len({t.technique_id for t in TARGETS if t.role == "train" and t.vulnerable})
    print(f"\nWrote {n} ground-truth example(s) across {n_tech} technique(s) (~{args.per_technique} each).")
    if n == 0:
        print("\nNo examples written. Are the lab targets running? Recon makes real HTTP probes "
              "(see lab/*/docker-compose.yml).")
