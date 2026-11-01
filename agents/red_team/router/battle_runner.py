"""
The router-driven battle dispatch loop (Step 8.1/8.2 integration).

Deliberately a NEW, additive entry point - training/battle_loop.py and
agents/red_team/live_tools.py are unmodified. Existing `--technique <id>`
training keeps working exactly as it always has; this is the opt-in path
for a battle where no technique is told to red up front.

Flow: recon (fixed initial pass) -> router.decide() -> either invoke a
technique for one chunk of turns (reusing run_live_attack() unchanged),
gather more recon, or stop -> fold whatever happened back into BattleState
-> re-decide. Chained attacks (8.3) fall out of this for free once a
technique's outcome lands a chain note that a later decide() call can see -
this pass only guarantees that plumbing exists, it doesn't yet add a
concrete follow-on "use this token" tool (see the project plan).
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from urllib.parse import urlparse

from agents.red_team.router import recon
from agents.red_team.router.router import decide, unload_router_model
from agents.red_team.router.schema import RouterDecision
from agents.red_team.router.state import new_state, to_prompt_block, update_state
from agents.red_team.live_tools import run_live_attack
from agents.safety.scope import assert_in_scope
from agents.techniques import list_techniques
from training.router_session_log import log_router_session

# Two consecutive recon_more decisions that add zero new ReconFindings force
# a stop instead of burning the rest of max_decision_points on a router
# that's stuck (hallucinating, or genuinely out of things worth reconning).
_CONSECUTIVE_EMPTY_RECON_LIMIT = 2


def _unload_technique_models() -> None:
    """Frees agents.red_team.agent's own model cache after a technique
    finishes - a router-driven battle can invoke several different
    techniques in sequence within one process (unlike a normal single-
    technique training run), so without this each newly-picked technique's
    model stacks on top of the last instead of being released. Mirrors
    training/battle_loop.py's own _unload_inference_models(), scoped to just
    the red-team cache here (blue never runs in this loop)."""
    import gc

    import agents.red_team.agent as red_agent

    for key in list(red_agent._model_cache.keys()):
        model, tokenizer = red_agent._model_cache.pop(key)
        del model, tokenizer
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.synchronize()
            torch.cuda.empty_cache()
    except ImportError:
        pass


def _known_route_candidates() -> list[str]:
    """Fallback route candidates for targets with no crawlable HTML surface
    at all (confirmed true of every lab target here: they're minimal JSON
    REST apps with no root page, links, or forms, so crawl_links/
    enumerate_forms alone find nothing to fingerprint - a real recon phase
    against a REST-only backend would instead learn routes from an OpenAPI/
    Swagger doc, JS bundle, or common-path brute force; this is the
    synthetic-testbed stand-in for that). Deliberately NOT technique-
    specific: it's every registered technique's own endpoint_path
    (agents/techniques/base.py's Technique.endpoint_path), deduped - the
    router still has to infer which technique fits a given route from its
    id_shape/response signals, not from which technique happened to
    register it."""
    from agents.techniques import list_techniques

    seen: list[str] = []
    for tech in list_techniques():
        if tech.endpoint_path not in seen:
            seen.append(tech.endpoint_path)
    return seen


def _initial_recon(target_url: str, state) -> list[str]:
    """A fixed opening recon pass (8.1), before the router ever has to
    decide anything. Returns the list of same-origin paths discovered but
    not yet individually fingerprinted, so later recon_more decisions have
    somewhere concrete to go."""
    update_state(state, recon.probe_root(target_url))

    html = recon.fetch_page_html(target_url)
    for finding in recon.enumerate_forms(target_url, html):
        update_state(state, finding)

    link_findings = recon.crawl_links(target_url)
    for finding in link_findings:
        update_state(state, finding)

    update_state(state, recon.fingerprint_endpoint(target_url))

    # Front-load the WHOLE recon sweep: fingerprint every candidate route now,
    # before the router makes a single decision. Recon is cheap, deterministic
    # HTTP (no model inference), so there's no reason to dole it out one
    # recon_more decision at a time - doing that made a weak router spend its
    # entire decision budget on recon and barely attack at all (observed in
    # router_sessions.jsonl: 5-6 recon_more decisions, 0-1 techniques tried per
    # battle). With every clue gathered up front, the router's whole decision
    # budget goes to actually trying techniques, and recon_exhausted is True
    # from its very first decision.
    paths = [
        urlparse(f.endpoint).path
        for f in link_findings
        if f.response_shape == "link" and urlparse(f.endpoint).path
    ]
    for path in _known_route_candidates():
        if path not in paths:
            paths.append(path)

    for path in paths:
        update_state(state, recon.fingerprint_endpoint(target_url, path=path))

    # Nothing left to recon incrementally - return an empty pending list so
    # every subsequent decision is invoke_technique-or-stop.
    return []


def run_router_battle(
    target_url: str,
    max_decision_points: int = 6,
    max_turns_per_technique: int | None = None,
    blue_analysis: bool = False,
) -> dict:
    """max_decision_points=6 is a first guess, not a measured value - once
    you've run a handful of real sessions, look at how many decision points
    a real recon -> technique -> chain sequence actually needs and adjust
    the default instead of leaving it as a guess.

    max_turns_per_technique: passed through to run_live_attack() as
    max_turns - leave as None to use each technique's own Technique.max_turns
    default (agents/techniques/base.py).

    blue_analysis: Step 8.4 - when True, after the battle blue reads the whole
    log window this battle produced and returns a correlated assessment
    (BlueTeamAgent.defend_live_window), surfaced as result["blue_assessment"].
    Off by default so a pure red-dispatch run doesn't pay to load the blue
    model."""
    assert_in_scope(target_url)

    # Step 8.4: remember where the target's log stands now, so the post-battle
    # correlation window is exactly THIS battle's events, not every prior
    # battle's against the same long-running target.
    blue_start_offset = 0
    if blue_analysis:
        from agents.blue_team.live_tools import fetch_new_logs
        try:
            _, blue_start_offset = fetch_new_logs(target_url, 0)
        except Exception as exc:  # noqa: BLE001 - telemetry is best-effort
            print(f"  [Blue] could not read starting telemetry offset: {exc}")

    state = new_state()
    pending_paths = _initial_recon(target_url, state)

    available_techniques = [t.id for t in list_techniques()]
    decisions: list[RouterDecision] = []
    # One entry per decision point, captured BEFORE that decision is made -
    # this is what agents/red_team/router/build_router_dataset.py later
    # mines to reconstruct "what did the router see right before it made
    # the choice that turned out correct" training examples.
    decision_log: list[dict] = []
    consecutive_empty_recon = 0

    for _ in range(max_decision_points):
        state_prompt_block = to_prompt_block(state)
        # Recon is fully front-loaded in _initial_recon, so recon_more is never
        # a useful choice here - telling decide() recon is exhausted removes it
        # from the offered actions (router.py), leaving invoke_technique-or-stop.
        decision = decide(state, available_techniques, recon_exhausted=not pending_paths)
        decisions.append(decision)
        decision_log.append({
            "state_prompt_block": state_prompt_block,
            "available_techniques": list(available_techniques),
            "decision": dataclasses.asdict(decision),
        })
        print(f"  [Router] action={decision.action}  technique_id={decision.technique_id}  reasoning={decision.reasoning!r}")

        if decision.action == "stop":
            break

        if decision.action == "invoke_technique":
            # Guard: only ever run a technique that's still on the table. A
            # hallucinated id, or one already tried and removed below, is
            # skipped rather than run - the loop is bounded by
            # max_decision_points, so this can't spin.
            if decision.technique_id not in available_techniques:
                print(f"  [Router] '{decision.technique_id}' is unavailable or already tried - skipping, re-deciding.")
                continue

            consecutive_empty_recon = 0
            # Unload the router's own model before loading a technique's -
            # reproduced a hard process crash (SIGSEGV) with both a
            # quantized base-model load (router) and a quantized adapter
            # load (technique) resident at once on this Windows/CUDA/
            # bitsandbytes stack, matching the same class of issue
            # training/battle_loop.py already documents for its own
            # subprocess-isolated training step (_train_in_subprocess).
            unload_router_model()
            # normal_traffic_probability=0.0: run_live_attack() otherwise has a
            # ~17.5% chance of doing a benign no-op instead of attacking, which
            # exists only to feed blue negative (no-attack) training examples.
            # In a router-driven dispatch the whole point is to actually find
            # what's exploitable, so that dice roll is pure sabotage here: if it
            # lands on the CORRECT technique the attack silently no-ops, the
            # router records a false failure and moves on to wrong techniques.
            # That is exactly what made a correctly-routed command_injection
            # battle look like a total loss. Blue's negative examples come from
            # the training loop (battle_loop.py), not from this dispatch path.
            kwargs = {"normal_traffic_probability": 0.0}
            if max_turns_per_technique is not None:
                kwargs["max_turns"] = max_turns_per_technique
            # Hand this technique whatever earlier steps already stole (Step
            # 8.3 chaining): e.g. a reset_token leaked by token_leak flows into
            # account_takeover here. Empty on a normal single-step battle.
            if state.artifacts:
                kwargs["chain_context"] = dict(state.artifacts)
            outcome = run_live_attack(decision.technique_id, target_url, **kwargs)
            print(f"  [{decision.technique_id}] success={outcome.get('success')}  tool_calls={len(outcome.get('tool_calls', []))}")
            _unload_technique_models()
            update_state(state, outcome)

            if outcome.get("success"):
                # Found a way in. Red is ~100% once it picks correctly, so one
                # confirmed success is this battle's whole signal - no reason
                # to keep attacking. The session is logged after the loop, with
                # this winning technique recorded in state.techniques_tried.
                print(f"  [Router] '{decision.technique_id}' SUCCEEDED - stopping battle, moving on.")
                break

            # Sampling without replacement (only reached on a FAILED attempt):
            # each technique gets exactly one try per battle. Red is ~100% once
            # it picks correctly, so a failure means "this target isn't
            # vulnerable to that" - retrying it only burns turns and (before
            # this) let a biased router loop on one technique forever. decide()
            # is still handed the *remaining* techniques and still chooses among
            # them from the recon clues, so order stays reasoning-driven.
            available_techniques.remove(decision.technique_id)
            if not available_techniques:
                print("  [Router] every technique has been tried once (none succeeded) - stopping.")
                break
            continue

        # recon_more
        before = len(state.recon_findings)
        if pending_paths:
            path = pending_paths.pop(0)
            update_state(state, recon.fingerprint_endpoint(target_url, path=path))
        after = len(state.recon_findings)

        consecutive_empty_recon = 0 if after > before else consecutive_empty_recon + 1
        if consecutive_empty_recon >= _CONSECUTIVE_EMPTY_RECON_LIMIT:
            print(f"  [Router] {consecutive_empty_recon} consecutive recon_more decisions added nothing new - stopping.")
            break

    log_router_session(
        target_url=target_url,
        decision_log=decision_log,
        techniques_tried=state.techniques_tried,
        chain_notes=state.chain_notes,
    )

    # Step 8.4: blue correlates across the whole window this battle produced.
    # Red/router models were already freed above (unload_router_model before
    # each technique, _unload_technique_models after each), so loading blue
    # now doesn't stack a third quantized model against the first two.
    blue_assessment = None
    if blue_analysis:
        from agents.blue_team.agent import BlueTeamAgent
        from agents.blue_team.live_tools import fetch_new_logs
        try:
            window_text, _ = fetch_new_logs(target_url, blue_start_offset)
        except Exception as exc:  # noqa: BLE001 - telemetry is best-effort
            window_text = ""
            print(f"  [Blue] could not fetch telemetry window: {exc}")
        print("  [Blue] correlating this battle's full log window...")
        blue_assessment = BlueTeamAgent().defend_live_window(window_text)
        print(f"  [Blue] chained={blue_assessment.get('chained')} "
              f"threat_detected={blue_assessment.get('threat_detected')} "
              f"category={blue_assessment.get('threat_category')!r} "
              f"severity={blue_assessment.get('severity')!r}")
        for i, step in enumerate(blue_assessment.get("attack_chain", []), 1):
            print(f"         chain step {i}: {step}")

    return {
        "target_url": target_url,
        "decisions": [dataclasses.asdict(d) for d in decisions],
        "recon_findings": [dataclasses.asdict(f) for f in state.recon_findings],
        "techniques_tried": state.techniques_tried,
        "chain_notes": state.chain_notes,
        "final_state_prompt_block": to_prompt_block(state),
        "blue_assessment": blue_assessment,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run router-driven battles with no technique hint (Step 8.1/8.2)")
    parser.add_argument("--target-url", type=str, default=None,
                        help="Live lab target, e.g. http://localhost:5001. If omitted, a target is picked "
                             "at random from every defined lab target (training/targets.py) for each battle.")
    parser.add_argument("--rounds", type=int, default=1,
                        help="Number of rounds to run (default 1). Total battles = rounds x battles.")
    parser.add_argument("--battles", type=int, default=1,
                        help="Battles per round (default 1). Total battles = rounds x battles.")
    parser.add_argument("--max-decision-points", type=int, default=6)
    parser.add_argument("--max-turns-per-technique", type=int, default=None)
    parser.add_argument("--blue-analysis", action="store_true",
                        help="Step 8.4: after each battle, have blue correlate the whole log window and "
                             "report whether it was a multi-step/chained attack (loads the blue model).")
    args = parser.parse_args()

    import os
    os.environ.setdefault("LLM_PROVIDER", "local")

    import random
    from training.targets import TARGETS

    def _pick_target() -> tuple[str, str]:
        """(url, label) for one battle: the fixed --target-url if given, else
        a random lab target (reported with its id/role so the stream says what
        it landed on)."""
        if args.target_url is not None:
            return args.target_url, args.target_url
        picked = random.choice(TARGETS)
        return picked.url, f"{picked.id} ({picked.role})"

    single = args.rounds == 1 and args.battles == 1
    total = args.rounds * args.battles
    wins = done = 0

    try:
        for round_num in range(1, args.rounds + 1):
            if not single:
                print(f"\n{'=' * 60}\n  ROUND {round_num}/{args.rounds}\n{'=' * 60}")
            for battle_num in range(1, args.battles + 1):
                target_url, label = _pick_target()
                done += 1
                if not single:
                    print(f"\n----- battle {battle_num}/{args.battles} (#{done}/{total}) -> {label} -----")
                elif args.target_url is None:
                    print(f"[battle_runner] No --target-url given; randomly selected {label} ({target_url})\n")

                result = run_router_battle(
                    target_url,
                    max_decision_points=args.max_decision_points,
                    max_turns_per_technique=args.max_turns_per_technique,
                    blue_analysis=args.blue_analysis,
                )

                won = any(t.get("outcome", {}).get("success") for t in result["techniques_tried"])
                wins += won
                if single:
                    print("\n" + "=" * 60)
                    print(json.dumps(result, indent=2, default=str))
                else:
                    print(f"  -> decisions={len(result['decisions'])} "
                          f"techniques_tried={len(result['techniques_tried'])} won={won}")

        if not single:
            print(f"\n{'=' * 60}\n  COMPLETE: {wins}/{total} battle(s) won\n{'=' * 60}")
    finally:
        unload_router_model()
