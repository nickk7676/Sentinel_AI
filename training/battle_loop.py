"""
Self-play training loop — the engine that makes Red and Blue improve over time.

What happens each round:
  1. Both agents fight N real battles, for one registered technique
     (agents/techniques/), against the live lab target
  2. Ground truth scores every fight (real attack success, real detection correctness)
  3. Winning examples are saved as individual JSON files, scoped to that technique
  4. After all battles:
       - Red is fine-tuned on this run's technique's own winning examples
         only, saved back to that technique's own adapter directory
         (training/adapters/red_team/<technique_id>/) - separate adapters
         per technique mean training one can never disturb another's. Red
         specializes by technique, so this fits how it actually works.
       - Blue is fine-tuned on a joint batch pulled from EVERY technique's
         saved winning examples (not just this run's), saved to the one
         shared adapter (training/adapters/blue_team/). Blue's actual skill
         is discriminating between categories from raw log evidence, so it
         needs to see a mix of techniques together, not one at a time -
         a per-technique split would be circular (requiring the technique
         to already be known before detection) and would remove the very
         signal blue needs to tell techniques apart from each other.
  5. The updated adapters are loaded for the next round
  6. Repeat

Requires the lab target running (see lab/target/docker-compose.yml).

Usage:
  python -m training.battle_loop                        # 10 rounds of 50 battles each
  python -m training.battle_loop --rounds 5 --battles 20
  python -m training.battle_loop --target-url http://localhost:5001
  python -m training.battle_loop --technique sql_injection
  python -m training.battle_loop --technique all         # every technique, one after another
  python -m training.battle_loop --technique all --no-eval  # skip the automatic before/after eval snapshot
"""

import argparse
import collections
import json
import os
import subprocess
import sys
import time
import traceback
import webbrowser
from pathlib import Path

# Make sure project root is on the path when running directly
_PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

os.environ["LLM_PROVIDER"] = "local"   # use local GPU model, not Ollama

import requests

from agents.blue_team.agent import SYSTEM_PROMPT as BLUE_SYSTEM
from agents.blue_team.agent import LIVE_USER_PROMPT_TEMPLATE as BLUE_LIVE_USER_PROMPT_TEMPLATE
from agents.techniques import DEFAULT_TECHNIQUE_ID, get_technique, list_techniques
from backend.services.simulation_service import run_simulation
from training import cost_tracker, curriculum, league
from training.adapter_version import get_version
from training.battle_log import log_battle
from training.dataset import (
    DATA_DIR,
    count_examples,
    count_examples_all,
    get_data_path,
    get_data_path_all,
    save_blue_win,
    save_red_win,
)
from training.eval_harness import run_eval as run_eval_harness
from training.overnight_report import write_summary
from training.process_lock import technique_lock
from training.progress_state import load_progress, save_progress
from training.session_id import next_session_id
from training.targets import pick_training_target, training_targets_for
from training.train_agent import _mem_checkpoint, adapter_path

STATS_FILE = DATA_DIR / "training_stats.jsonl"
TENSORBOARD_TRAIN_DIR = DATA_DIR / "tensorboard" / "rounds"
TENSORBOARD_LIVE_DIR = DATA_DIR / "tensorboard" / "live"


def _run_stamp() -> str:
    """A per-run id (local date-time) used as the leaf TensorBoard directory
    for a run, e.g. live/idor/20261028_173005. Each training session gets its
    own leaf, so TensorBoard lists every session as a separate, toggleable run
    instead of merging every session's event file in one directory into a
    single overlapping line. Shared across a technique's live + round writers
    (and across all techniques in one --technique all session) so one session
    groups together."""
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _open_writer(log_dir):
    """A persistent writer, opened once per run_loop() call and closed once
    at the end (not once per round/battle). log_dir ends in a per-run stamp
    (see _run_stamp), so a run writes exactly one event file into its own
    directory - TensorBoard then shows each run as its own line rather than
    stacking every past session's file on top of each other. Step numbers
    still come from training/progress_state.py's persisted, ever-increasing
    counters, so the x-axis stays continuous within a run."""
    try:
        from torch.utils.tensorboard import SummaryWriter
    except ImportError:
        print("  (tensorboard not installed - scalar logging disabled; `pip install tensorboard`)")
        return None
    return SummaryWriter(log_dir=str(log_dir))


def _train_in_subprocess(
    agent: str,
    max_examples: int,
    technique: str | None = None,
    force_include_paths: list[str] | None = None,
) -> None:
    """Runs train_agent.py's CLI as a child process instead of calling
    train() in-process. Measured: train() leaves ~1.0-1.2GB of real,
    *allocated* VRAM behind every single call, past its own
    accelerator.free_memory() + del + gc.collect() + empty_cache() cleanup -
    reproduced consistently across rounds regardless of dataset size, which
    points to PEFT/bitsandbytes' C-extension state holding a reference across
    repeated from_pretrained() calls within one process (not a mistake in
    this codebase). A subprocess sidesteps it entirely: when the child exits,
    the CUDA driver reclaims 100% of its VRAM unconditionally, leak or not.

    force_include_paths (blue only): written to a temp JSON file and passed
    via --force-include-file, since a list can't cross the subprocess
    boundary directly - lets this round's own fresh blue_wins survive
    get_data_path_all's per-technique cap (training/dataset.py)."""
    cmd = [sys.executable, "-m", "training.train_agent", "--agent", agent, "--max-examples", str(max_examples)]
    if technique is not None:
        cmd += ["--technique", technique]

    force_include_file = None
    if force_include_paths:
        force_include_file = DATA_DIR / "tmp" / "force_include_blue.json"
        force_include_file.parent.mkdir(parents=True, exist_ok=True)
        force_include_file.write_text(json.dumps(force_include_paths), encoding="utf-8")
        cmd += ["--force-include-file", str(force_include_file)]

    try:
        subprocess.run(cmd, check=True, cwd=str(_PROJECT_ROOT))
    finally:
        if force_include_file is not None:
            force_include_file.unlink(missing_ok=True)


# A training subprocess crashing with STATUS_ACCESS_VIOLATION (3221225477 /
# 0xC0000005) has been observed on Windows specifically when this parent
# process already loaded+used its own quantized model for live battles just
# before spawning the training subprocess - reproduced in isolation with a
# minimal script containing none of this codebase's logic, so it's a
# Windows/driver/CUDA-multi-process issue, not something fixable here. A
# short delay + retry costs nothing (training crashes already skip cleanly -
# see the docstring below) and gives the driver more time to fully release
# the parent's GPU state between attempts.
_TRAIN_CRASH_RETRIES = 2
_TRAIN_CRASH_RETRY_DELAY_SECONDS = 8


def _train_safely(agent: str, max_examples: int, technique: str | None = None, force_include_paths: list[str] | None = None) -> bool:
    """Wraps _train_in_subprocess so a training crash (GPU contention with
    another process, a driver-level crash, OOM, etc.) costs this round's
    training and nothing else - without this, an unhandled
    CalledProcessError propagates out of run_loop() and kills the entire
    multi-round run, including every round after the one that happened to
    crash. Retries a fixed number of times with a short delay first, since
    this kind of crash has been observed to be a transient parent/child GPU
    handoff issue rather than a deterministic one. Returns whether training
    actually completed."""
    attempt = 0
    while True:
        try:
            _train_in_subprocess(agent, max_examples, technique=technique, force_include_paths=force_include_paths)
            return True
        except subprocess.CalledProcessError as exc:
            attempt += 1
            if attempt > _TRAIN_CRASH_RETRIES:
                print(f"\n  !! {agent.upper()} team training crashed (exit code {exc.returncode}) after "
                      f"{attempt} attempt(s) - skipping this round's training and continuing. If this keeps "
                      f"happening, check whether another GPU-heavy process is running at the same time, or "
                      f"whether a recent NVIDIA driver update introduced a regression - exit code 3221225477 "
                      f"is STATUS_ACCESS_VIOLATION, a native CUDA crash below the level Python can catch.")
                return False
            print(f"\n  !! {agent.upper()} team training crashed (exit code {exc.returncode}) - retrying in "
                  f"{_TRAIN_CRASH_RETRY_DELAY_SECONDS}s (attempt {attempt}/{_TRAIN_CRASH_RETRIES})...")
            time.sleep(_TRAIN_CRASH_RETRY_DELAY_SECONDS)


def run_loop(
    rounds: int = 10,
    battles_per_round: int = 50,
    min_examples_to_train: int = 10,
    max_examples_to_train: int = 200,
    target_url: str | None = None,
    technique: str = DEFAULT_TECHNIQUE_ID,
    use_curriculum: bool = True,
    use_league: bool = False,
    run_id: str | None = None,
) -> None:
    """target_url: leave as None (default) for Step 5 target diversity - a
    fresh target is picked from training.targets.pick_training_target()
    every battle, randomized across that technique's training-pool targets
    plus an occasional distractor. Pass an explicit URL (--target-url) to
    pin every battle to one fixed target instead, e.g. for debugging a
    single lab app.

    use_curriculum (Step 9.1): when True and no target is pinned, pick targets
    by curriculum (easy tiers first, harder ones unlock as the win rate
    stabilizes) instead of uniform random. use_league (Step 9.3): when True,
    some rounds pit the current side against an archived past opponent to
    resist self-play collapse."""
    tech = get_technique(technique)  # fail fast on a typo'd --technique
    run_id = run_id or _run_stamp()

    # Refuses to start if another process is already battling this
    # technique, instead of silently corrupting shared round-numbering and
    # target state (see training/process_lock.py for why this happened).
    with technique_lock(technique):
        _run_loop_locked(tech, rounds, battles_per_round, min_examples_to_train, max_examples_to_train,
                         target_url, technique, use_curriculum, use_league, run_id)


def _reachable_targets(technique_id: str, target_url: str | None) -> tuple[bool, list[str]]:
    """Pings /healthz for every target this technique's rounds could actually
    hit, before committing potentially hours of an unattended overnight run
    to a technique whose Docker container was never started. Returns
    (at_least_one_reachable, [ids that failed the check])."""
    if target_url is not None:
        # A pinned --target-url - there's only one URL to check.
        try:
            ok = requests.get(f"{target_url}/healthz", timeout=3).ok
        except requests.RequestException:
            ok = False
        return ok, ([] if ok else [target_url])

    unreachable = []
    any_ok = False
    for target in training_targets_for(technique_id):
        try:
            ok = requests.get(f"{target.url}/healthz", timeout=3).ok
        except requests.RequestException:
            ok = False
        if ok:
            any_ok = True
        else:
            unreachable.append(target.id)
    return any_ok, unreachable


def _unload_between_techniques(label: str) -> None:
    """Belt-and-suspenders cleanup at a technique boundary. Every round
    already unloads inference models + the Ollama model before training
    (see _run_loop_locked below), so by the time run_loop() returns for a
    technique this should be close to a no-op - but for an unattended
    overnight --technique all run it's worth paying the near-zero cost to
    confirm it here (and print a VRAM checkpoint in the log) rather than
    assume it and find out at 4am that something crept up."""
    _unload_inference_models()
    _unload_ollama_judge()
    _mem_checkpoint(f"battle_loop: after {label}")


def _zero_session_stat(tech, status: str) -> dict:
    """A technique that never ran a single battle (skipped up front) - all
    counts zero, rates None (None renders as an empty bar in the summary
    report, not a misleading 0%)."""
    return {
        "id": tech.id, "display_name": tech.display_name, "status": status, "elapsed_seconds": 0.0,
        "attack_battles": 0, "attack_successes": 0, "detections": 0, "normal_battles": 0, "false_positives": 0,
        "fix_proposed": 0, "fix_verified": 0,
        "real_attack_battles": 0, "real_attack_successes": 0,
        "red_attack_success_rate": None, "blue_detection_rate": None, "blue_false_positive_rate": None,
        "blue_fix_verified_rate": None,
    }


def _session_stat_from_progress(tech, status: str, elapsed_seconds: float, baseline: dict, after: dict) -> dict:
    """training/progress_state.py's counters are cumulative across this
    technique's ENTIRE history, not just this run - so this run's own
    contribution is the delta between a snapshot taken right before
    run_loop() and one taken right after (progress is saved after every
    battle, so even a technique that crashed mid-run still has its partial
    progress correctly captured here, not just fully-completed ones)."""
    attack_battles = after["total_attack_battles"] - baseline["total_attack_battles"]
    attack_successes = after["total_attack_successes"] - baseline["total_attack_successes"]
    detections = after["total_detections"] - baseline["total_detections"]
    normal_battles = after["total_normal_battles"] - baseline["total_normal_battles"]
    false_positives = after["total_false_positives"] - baseline["total_false_positives"]
    fix_proposed = after["total_fix_proposed"] - baseline["total_fix_proposed"]
    fix_verified = after["total_fix_verified"] - baseline["total_fix_verified"]
    real_attack_battles = after["total_real_attack_battles"] - baseline["total_real_attack_battles"]
    real_attack_successes = after["total_real_attack_successes"] - baseline["total_real_attack_successes"]
    return {
        "id": tech.id,
        "display_name": tech.display_name,
        "status": status,
        "elapsed_seconds": elapsed_seconds,
        "attack_battles": attack_battles,
        "attack_successes": attack_successes,
        "detections": detections,
        "normal_battles": normal_battles,
        "false_positives": false_positives,
        "fix_proposed": fix_proposed,
        "fix_verified": fix_verified,
        "real_attack_battles": real_attack_battles,
        "real_attack_successes": real_attack_successes,
        # Step 5.3 - computed from real_* (excludes distractor-target
        # battles, which are deliberately unexploitable) so this doesn't
        # structurally cap out below 100% regardless of red's actual skill.
        "red_attack_success_rate": real_attack_successes / real_attack_battles if real_attack_battles else None,
        "blue_detection_rate": detections / attack_battles if attack_battles else None,
        "blue_false_positive_rate": false_positives / normal_battles if normal_battles else None,
        "blue_fix_verified_rate": fix_verified / fix_proposed if fix_proposed else None,
    }


def _run_eval_snapshot(label: str, round_num: int, attacks_per_technique: int, normal_per_technique: int) -> dict | None:
    """Wraps eval_harness.run_eval() so a crash there (e.g. a target
    container down) costs only the snapshot, not the whole overnight run.
    Returns None if the snapshot failed - callers must handle that."""
    print(f"\n{'#'*60}")
    print(f"  {label} EVAL SNAPSHOT (round={round_num}, {attacks_per_technique} attacks + "
          f"{normal_per_technique} normal per target)")
    print(f"{'#'*60}")
    try:
        result = run_eval_harness(
            round_num=round_num,
            attacks_per_technique=attacks_per_technique,
            normal_per_technique=normal_per_technique,
        )
    except Exception:
        print(f"  !! {label} eval snapshot crashed - continuing without it. Traceback:")
        traceback.print_exc()
        result = None
    finally:
        _unload_between_techniques(f"{label.lower()} eval snapshot")
    return result


def run_loop_all(
    rounds: int = 10,
    battles_per_round: int = 50,
    min_examples_to_train: int = 10,
    max_examples_to_train: int = 200,
    target_url: str | None = None,
    run_eval_snapshots: bool = True,
    eval_attacks_per_technique: int = 2,
    eval_normal_per_technique: int = 1,
    use_curriculum: bool = True,
    use_league: bool = False,
) -> None:
    """--technique all: runs every registered technique's full rounds x
    battles back-to-back in one process, instead of one `python -m
    training.battle_loop --technique X` invocation per technique. Meant for
    unattended overnight runs, so a single technique's target being down or
    its lock already held by another process is logged and skipped rather
    than aborting every technique queued up behind it. Ends by writing a
    single HTML summary report (training/overnight_report.py) so the whole
    session's results can be read at a glance instead of scrolled for in
    this console log.

    run_eval_snapshots: if True (default), runs a small eval_harness.py pass
    (all techniques x all 4 targets each) both before and after training -
    a real before/after comparison on frozen, held-out battles, not just
    this run's own live in-training numbers (which reflect a constantly
    shifting adapter, not a clean snapshot). Both snapshots share a small
    persisted session id (training/session_id.py) so their round numbers
    stay meaningful next to any manual eval_harness runs in the same
    eval_summary.jsonl / TensorBoard history, instead of colliding with
    round 0 or injecting a raw timestamp into that series."""
    # Chain steps (token_leak, account_takeover) can't win standalone - they
    # need an artifact the previous step hands them via the router chain - so
    # the self-play sweep skips them (they'd only log 0% noise and no training
    # wins). They're still exercised in sequence by the router battle-runner.
    skipped_chain = [t.id for t in list_techniques() if getattr(t, "chain_step", False)]
    techniques = [t for t in list_techniques() if not getattr(t, "chain_step", False)]
    total = len(techniques)
    overall_start = time.time()
    if skipped_chain:
        print(f"  (skipping chain-step techniques {skipped_chain} - trained via the router chain path, "
              f"not the standalone sweep)")
    # One shared stamp for the whole session, so every technique's live/round
    # writers land under the same run leaf (e.g. live/idor/<stamp>,
    # live/ssrf/<stamp>) and TensorBoard groups the session as one selectable
    # run across techniques instead of scattering it.
    run_id = _run_stamp()

    print("#" * 60)
    print(f"  SENTINEL AI — ALL-TECHNIQUES OVERNIGHT RUN ({total} techniques)")
    print(f"  Rounds/technique: {rounds}   Battles/round: {battles_per_round}")
    print("#" * 60)

    baseline_eval = None
    after_eval = None
    session_id = None
    if run_eval_snapshots:
        session_id = next_session_id()
        baseline_eval = _run_eval_snapshot(
            "BASELINE (before)", session_id * 2, eval_attacks_per_technique, eval_normal_per_technique,
        )

    results = {}
    session_stats = []
    for i, tech in enumerate(techniques, 1):
        print(f"\n{'#'*60}")
        print(f"  TECHNIQUE {i}/{total}: {tech.display_name} ({tech.id})")
        print(f"{'#'*60}")

        reachable, unreachable_ids = _reachable_targets(tech.id, target_url)
        if not reachable:
            print(f"  !! Skipping {tech.id}: no reachable target (/healthz failed for {unreachable_ids}) - "
                  f"is its Docker container running? See lab/{tech.id}*/docker-compose.yml.")
            status = "skipped (no reachable target)"
            results[tech.id] = status
            session_stats.append(_zero_session_stat(tech, status))
            continue
        if unreachable_ids:
            print(f"  !! Warning: {unreachable_ids} unreachable for {tech.id} - battles that randomly pick "
                  f"one of those targets will just fail, the rest of this technique's pool still works.")

        baseline_progress = load_progress(tech.id)
        technique_start = time.time()
        status = "complete"
        try:
            run_loop(
                rounds=rounds,
                battles_per_round=battles_per_round,
                min_examples_to_train=min_examples_to_train,
                max_examples_to_train=max_examples_to_train,
                target_url=target_url,
                technique=tech.id,
                use_curriculum=use_curriculum,
                use_league=use_league,
                run_id=run_id,
            )
        except RuntimeError as exc:
            # technique_lock: another process already holds this technique.
            print(f"  !! Skipping {tech.id}: {exc}")
            status = "skipped (locked by another process)"
        except Exception:
            print(f"  !! {tech.id} crashed unexpectedly - skipping to the next technique instead of "
                  f"aborting the whole overnight run. Traceback:")
            traceback.print_exc()
            status = "crashed"
        finally:
            _unload_between_techniques(f"technique {tech.id}")

        elapsed_s = time.time() - technique_start
        after_progress = load_progress(tech.id)
        session_stats.append(_session_stat_from_progress(tech, status, elapsed_s, baseline_progress, after_progress))
        results[tech.id] = status
        if status == "complete":
            print(f"  {tech.id} complete in {round(elapsed_s)}s")

    elapsed = round(time.time() - overall_start)
    print("\n" + "#" * 60)
    print(f"  ALL-TECHNIQUES RUN COMPLETE in {elapsed}s ({elapsed / 3600:.1f}h)")
    for tech_id, status in results.items():
        print(f"    {tech_id}: {status}")
    print("#" * 60)

    if run_eval_snapshots:
        after_eval = _run_eval_snapshot(
            "COMPARISON (after)", session_id * 2 + 1, eval_attacks_per_technique, eval_normal_per_technique,
        )

    try:
        report_path = write_summary(
            session_stats, rounds, battles_per_round, overall_start, time.time() - overall_start,
            baseline_eval=baseline_eval, after_eval=after_eval,
        )
        print(f"\n  Summary report: {report_path}")
        try:
            webbrowser.open(report_path.as_uri())
        except Exception:
            pass  # no display / default browser unavailable - the file is still on disk
    except Exception:
        print("  !! Failed to write the summary report (raw data is still in training_stats.jsonl):")
        traceback.print_exc()


def _run_loop_locked(
    tech,
    rounds: int,
    battles_per_round: int,
    min_examples_to_train: int,
    max_examples_to_train: int,
    target_url: str | None,
    technique: str,
    use_curriculum: bool = True,
    use_league: bool = False,
    run_id: str | None = None,
) -> None:
    run_id = run_id or _run_stamp()
    print("=" * 60)
    print("  SENTINEL AI — SELF-PLAY TRAINING LOOP")
    print("=" * 60)
    print(f"  Rounds:          {rounds}")
    print(f"  Battles/round:   {battles_per_round}")
    print(f"  Min to train:    {min_examples_to_train}")
    print(f"  Max to train:    {max_examples_to_train} (sliding window)")
    if target_url:
        print(f"  Target:          {tech.display_name} vs {target_url} (fixed, --target-url override)")
    elif use_curriculum:
        print(f"  Target:          {tech.display_name} vs curriculum-selected targets (Step 9.1, tier "
              f"{curriculum.unlocked_tier(technique)} unlocked)")
    else:
        print(f"  Target:          {tech.display_name} vs randomized training-pool targets (Step 5)")
    print(f"  Curriculum:      {'on' if (use_curriculum and not target_url) else 'off'}   "
          f"League: {'on' if use_league else 'off (snapshots still archived)'}")
    print("=" * 60)

    live_writer = _open_writer(TENSORBOARD_LIVE_DIR / technique / run_id)
    round_writer = _open_writer(TENSORBOARD_TRAIN_DIR / technique / run_id)

    # Cumulative counts and the round number itself are both persisted to
    # disk (training/progress_state.py) and loaded here rather than starting
    # at zero, so restarting this process continues the same sequence
    # instead of colliding with it. total_* are cumulative across this
    # technique's entire history (used for the live curve); each round's own
    # local attack_battles/attack_successes/etc. (below, inside the loop)
    # still reset every round for that round's own summary.
    progress = load_progress(technique)
    global_round = progress["global_round"]
    total_attack_battles = progress["total_attack_battles"]
    total_attack_successes = progress["total_attack_successes"]
    total_detections = progress["total_detections"]
    total_normal_battles = progress["total_normal_battles"]
    total_false_positives = progress["total_false_positives"]
    total_fix_proposed = progress["total_fix_proposed"]
    total_fix_verified = progress["total_fix_verified"]
    total_real_attack_battles = progress["total_real_attack_battles"]
    total_real_attack_successes = progress["total_real_attack_successes"]
    total_red_reward = progress["total_red_reward"]
    total_blue_reward = progress["total_blue_reward"]

    try:
        for round_num in range(1, rounds + 1):
            global_round += 1
            print(f"\n{'='*60}")
            print(f"  ROUND {round_num} / {rounds}  (global round {global_round})")
            print(f"{'='*60}")

            # Red's success and blue's detection are tracked independently
            # (not as a single win/loss/draw) so red succeeding-but-detected
            # and red failing-but-undetected don't get collapsed into the
            # same "draw" bucket - see agents/judge/ground_truth.py's
            # winner field for why that collapse happens there. attack_*
            # counters are scoped to real attack attempts (was_attack=True);
            # false_positives is scoped to normal-traffic rounds (Step 2.5),
            # since "detection_correct" means something different there
            # (correctly staying quiet, not correctly flagging an attack).
            attack_battles = 0
            attack_successes = 0
            detections = 0
            normal_battles = 0
            false_positives = 0
            fix_proposed = 0
            fix_verified = 0
            # real_* excludes distractor-target attack battles (Step 5.3) -
            # those are deliberately unexploitable, so counting them toward
            # red's success rate structurally caps it below 100% regardless
            # of red's actual skill. This is what red_attack_success_rate is
            # computed from everywhere below; attack_battles/attack_successes
            # above still count every attack round (including distractor),
            # since that's the correct denominator for blue's detection rate.
            real_attack_battles = 0
            real_attack_successes = 0
            round_start = time.time()

            # Paths of blue_wins saved THIS round - passed to
            # get_data_path_all's always_include so this round's fresh wins
            # are never excluded by the per-technique cap even if this
            # technique already has a large backlog (see training/dataset.py).
            this_round_blue_win_paths: list[str] = []

            # Adapter versions in effect for every battle this round - read once
            # up front since training (and therefore any version bump) only
            # happens after all of this round's battles are played.
            red_version = get_version(adapter_path("red", technique))
            blue_version = get_version(adapter_path("blue"))

            # Step 9.2 - per-round partial-reward sums (graded 0.0-1.0).
            round_red_reward = 0.0
            round_blue_reward = 0.0

            # Step 9.3 - league matchmaking for this round. Clear any prior
            # override first, then maybe replace ONE side with an archived past
            # opponent so the current side trains against an old adversary, not
            # only itself. Safe on VRAM: inference models are unloaded at every
            # round boundary (before training), so only one adapter per side is
            # ever resident within a round.
            os.environ.pop("RED_ADAPTER_PATH_OVERRIDE", None)
            os.environ.pop("BLUE_ADAPTER_PATH", None)
            league_desc = "current vs current"
            if use_league and not target_url:
                import random as _rng
                if _rng.random() < 0.5:
                    past_red = league.pick_opponent_version(red_version, league.available_versions("red", technique), p_past=1.0)
                    if past_red is not None:
                        os.environ["RED_ADAPTER_PATH_OVERRIDE"] = str(league.opponent_adapter_path("red", technique, past_red))
                        league_desc = f"blue v{blue_version} (current) vs red v{past_red} (past)"
                else:
                    past_blue = league.pick_opponent_version(blue_version, league.available_versions("blue", None), p_past=1.0)
                    if past_blue is not None:
                        os.environ["BLUE_ADAPTER_PATH"] = str(league.opponent_adapter_path("blue", None, past_blue))
                        league_desc = f"red v{red_version} (current) vs blue v{past_blue} (past)"
                print(f"  League matchup: {league_desc}")

            for battle_num in range(1, battles_per_round + 1):
                # Step 5.2: a fresh target is picked every battle (not once
                # per round) so red/blue never settle into memorizing one
                # app's quirks - unless target_url was explicitly pinned via
                # --target-url, in which case every battle uses that one URL.
                if target_url:
                    battle_target_url = target_url
                    picked_target = None
                elif use_curriculum:
                    # Step 9.1 - draw from the tiers unlocked so far, easiest first.
                    picked_target = curriculum.pick_curriculum_target(technique)
                    battle_target_url = picked_target.url
                else:
                    picked_target = pick_training_target(technique)
                    battle_target_url = picked_target.url

                print(f"  [{battle_num:02d}/{battles_per_round}] target={picked_target.id if picked_target else battle_target_url} ", end="", flush=True)

                result = run_simulation(target_url=battle_target_url, technique=technique)

                attack      = result["attack"]
                defense     = result["defense"]
                verdict     = result["evaluation"]
                remediation = result.get("remediation", {})
                was_attack  = attack.get("was_attack", True)

                is_distractor = picked_target is not None and picked_target.role == "distractor"

                if was_attack:
                    attack_battles += 1
                    total_attack_battles += 1
                    if verdict.get("attack_success"):
                        attack_successes += 1
                        total_attack_successes += 1
                    if verdict.get("detection_correct"):
                        detections += 1
                        total_detections += 1
                    if not is_distractor:
                        real_attack_battles += 1
                        total_real_attack_battles += 1
                        if verdict.get("attack_success"):
                            real_attack_successes += 1
                            total_real_attack_successes += 1
                else:
                    normal_battles += 1
                    total_normal_battles += 1
                    if verdict.get("false_positives"):
                        false_positives += 1
                        total_false_positives += 1

                # Step 9.2 - accumulate graded partial-credit rewards alongside
                # the binary counters above.
                round_red_reward += verdict.get("red_reward", 0.0)
                total_red_reward += verdict.get("red_reward", 0.0)
                round_blue_reward += verdict.get("blue_reward", 0.0)
                total_blue_reward += verdict.get("blue_reward", 0.0)

                # Step 9.1 - feed real attack outcomes to the curriculum, which
                # unlocks harder target tiers once this one is reliably beaten.
                # Distractor rounds aren't real attacks; normal-traffic rounds
                # aren't attacks at all - neither counts toward promotion.
                if use_curriculum and not target_url and was_attack and not is_distractor:
                    curriculum.record_outcome(technique, bool(verdict.get("attack_success")))

                # Step 7.3: fix verification is a second, independent signal
                # from detection accuracy - it only ever fires on a battle
                # where verify_fix() actually attempted a replay (see
                # agents/judge/verification.py), which requires a real
                # successful attack and a non-empty recommended_fix.
                if remediation.get("attempted"):
                    fix_proposed += 1
                    total_fix_proposed += 1
                    if remediation.get("fix_verified"):
                        fix_verified += 1
                        total_fix_verified += 1

                # Step 4.2: log every battle (not just wins) with its full
                # transcript, reward, and the adapter version each side played
                # with - separate from training/dataset.py's win-only examples.
                # round_num here is the persisted global_round, not the
                # local 1..rounds counter, so battle_log.jsonl's round
                # numbers stay meaningful (and non-colliding) across restarts.
                log_battle(
                    source="train",
                    technique=technique,
                    round_num=global_round,
                    battle_num=battle_num,
                    target_url=battle_target_url,
                    attack=attack,
                    defense=defense,
                    verdict=verdict,
                    red_adapter_version=red_version,
                    blue_adapter_version=blue_version,
                    target_id=picked_target.id if picked_target else None,
                    target_role=picked_target.role if picked_target else None,
                    target_framework=picked_target.framework if picked_target else None,
                    remediation=remediation,
                )

                # Persist the running totals after every battle (not just
                # every round) so even a mid-round restart resumes from the
                # last completed battle instead of losing progress back to
                # the start of the round.
                save_progress(technique, {
                    "global_round": global_round,
                    "total_attack_battles": total_attack_battles,
                    "total_attack_successes": total_attack_successes,
                    "total_detections": total_detections,
                    "total_normal_battles": total_normal_battles,
                    "total_false_positives": total_false_positives,
                    "total_fix_proposed": total_fix_proposed,
                    "total_fix_verified": total_fix_verified,
                    "total_real_attack_battles": total_real_attack_battles,
                    "total_real_attack_successes": total_real_attack_successes,
                    "total_red_reward": total_red_reward,
                    "total_blue_reward": total_blue_reward,
                })

                # Step 4.3 (live): one point per battle, on a running
                # cumulative rate that never resets across rounds, so the
                # curve is visible while a round is still in progress
                # instead of only appearing once the round completes.
                if live_writer is not None:
                    # Per-technique live (intra-run) curves. The technique is
                    # kept in the tag ("live/<technique>/...") so each
                    # technique gets its OWN chart in TensorBoard instead of
                    # every technique's line piling onto one shared chart. Red
                    # attack success and blue detection both appear here (the
                    # live view); their round-summary counterparts are in the
                    # rounds writer (the rounds view).
                    if total_real_attack_battles:
                        live_writer.add_scalar(
                            f"live/{technique}/cumulative_red_attack_success_rate",
                            total_real_attack_successes / total_real_attack_battles, total_real_attack_battles,
                        )
                    if total_attack_battles:
                        live_writer.add_scalar(
                            f"live/{technique}/cumulative_blue_detection_rate",
                            total_detections / total_attack_battles, total_attack_battles,
                        )
                    if total_normal_battles:
                        live_writer.add_scalar(
                            f"live/{technique}/cumulative_false_positive_rate",
                            total_false_positives / total_normal_battles, total_normal_battles,
                        )
                    if total_fix_proposed:
                        live_writer.add_scalar(
                            f"live/{technique}/cumulative_fix_verified_rate",
                            total_fix_verified / total_fix_proposed, total_fix_proposed,
                        )
                    live_writer.add_scalar(
                        f"live/{technique}/battle_quality",
                        verdict.get("defense_quality", 0), total_attack_battles + total_normal_battles,
                    )
                    live_writer.flush()

                # Red and blue are scored independently here: red's training
                # signal is "did the attack actually work", blue's is "was it
                # correctly detected" - neither depends on the other, so a
                # single battle can produce a red example, a blue example,
                # both, or neither.
                # was_attack is False on randomized normal-traffic rounds (Step
                # 2.5) - red never attempted anything, so there's no win or loss
                # to train on.
                # Examples are tagged with the technique that actually produced
                # them (attack["attack_type"]) so training stays scoped per
                # technique and never mixes in another technique's examples.
                example_technique = attack.get("attack_type") or technique

                if was_attack and verdict.get("attack_success"):
                    save_red_win(attack.get("_live_messages", []), example_technique)

                if verdict.get("detection_correct"):
                    log_excerpt = defense.pop("_log_excerpt", "")
                    blue_user_prompt = BLUE_LIVE_USER_PROMPT_TEMPLATE.format(log_text=log_excerpt or "(no new log lines)")

                    # Detection and remediation are separate skills, so they
                    # get separate gates. Detection correctness (the outer if)
                    # is what makes this a blue win and is ALWAYS trained on.
                    # The recommended_fix rides along in the same defense
                    # payload, but blue should never learn to reproduce an
                    # unverified or wrong fix just because the detection was
                    # right (that's how blacklist-style SQLi fixes leaked into
                    # the pool). So the fix fields are kept only when the fix
                    # actually verified - replayed against the patched target
                    # and confirmed to close the hole - and stripped
                    # otherwise, leaving a detection-only training example.
                    # Step 7.3: a verified fix is additionally saved a SECOND
                    # time (oversampling via training/dataset.py's
                    # always_include), so good fixes are over-represented in
                    # blue's batch rather than merely allowed in.
                    fix_verified = bool(remediation.get("fix_verified"))
                    defense_for_training = dict(defense)
                    if not fix_verified:
                        for _k in ("recommended_fix", "mitigation", "recommendations"):
                            defense_for_training.pop(_k, None)

                    saved_path = save_blue_win(attack, defense_for_training, BLUE_SYSTEM, blue_user_prompt, example_technique)
                    this_round_blue_win_paths.append(saved_path)
                    if fix_verified:
                        extra_path = save_blue_win(attack, defense_for_training, BLUE_SYSTEM, blue_user_prompt, example_technique)
                        this_round_blue_win_paths.append(extra_path)

                quality = verdict.get("defense_quality", 0)
                mode = "attack" if was_attack else "normal"
                print(f"mode={mode:<6}  attack_success={str(verdict.get('attack_success')):<5}  "
                      f"detected={str(verdict.get('detection_correct')):<5}  quality={quality:.1f}  "
                      f"fix_verified={remediation.get('fix_verified')}  "
                      f"(AS:{real_attack_successes}/{real_attack_battles} DET:{detections}/{attack_battles} "
                      f"FP:{false_positives}/{normal_battles} FIXV:{fix_verified}/{fix_proposed})")

            round_time = round(time.time() - round_start, 1)
            print(f"\n  Round {round_num} complete in {round_time}s")
            print(f"  Red attack success {real_attack_successes}/{real_attack_battles} "
                  f"(excl. {attack_battles - real_attack_battles} distractor rounds)  |  "
                  f"Blue detection {detections}/{attack_battles}  |  "
                  f"False positives {false_positives}/{normal_battles}  |  "
                  f"Fix verified {fix_verified}/{fix_proposed}")

            # Step 9.2 - graded reward means this round (a "how close" signal
            # the binary rates above can't show). Step 9.4 - record the cost of
            # this round's battles.
            battles_done = attack_battles + normal_battles
            mean_red_reward = round_red_reward / attack_battles if attack_battles else 0.0
            mean_blue_reward = round_blue_reward / battles_done if battles_done else 0.0
            tier_note = f"  |  curriculum tier {curriculum.unlocked_tier(technique)}" if (use_curriculum and not target_url) else ""
            print(f"  Partial reward: red {mean_red_reward:.2f}/attack  |  blue {mean_blue_reward:.2f}/battle{tier_note}")
            cost_tracker.record("round_battles", technique, round_time, battles=battles_done,
                                red_reward=round(round_red_reward, 3), blue_reward=round(round_blue_reward, 3))
            if round_writer is not None:
                round_writer.add_scalar(f"round/{technique}/mean_red_reward", mean_red_reward, global_round)
                round_writer.add_scalar(f"round/{technique}/mean_blue_reward", mean_blue_reward, global_round)
                round_writer.flush()

            # Log stats for tracking improvement over time. Keyed on
            # global_round (persisted, never resets) rather than the local
            # round_num, so entries from different process runs never share
            # a round number - that collision used to make this file (and
            # the matching TensorBoard chart) look like nonsense once you'd
            # restarted training more than once.
            _log_stats(global_round, technique, attack_battles, attack_successes, detections, normal_battles, false_positives, fix_proposed, fix_verified, round_time, real_attack_battles, real_attack_successes)
            if round_writer is not None:
                _log_tensorboard_round(round_writer, technique, global_round, attack_battles, attack_successes, detections, normal_battles, false_positives, fix_proposed, fix_verified, real_attack_battles, real_attack_successes)

            # Unload inference models and Ollama judge before training to free VRAM
            _unload_inference_models()
            _unload_ollama_judge()

            # Red: train if it has enough winning examples for THIS technique -
            # scoped to this run's technique only, so training never mixes in
            # another technique's examples and is saved to that technique's own
            # adapter directory (separate adapters per technique, so training
            # this technique can never disturb another technique's adapter).
            n_red = count_examples("red", technique)
            if n_red >= min_examples_to_train:
                red_paths = get_data_path("red", technique, max_examples=max_examples_to_train)
                print(f"\n  Training RED team on {len(red_paths)} most recent "
                      f"{tech.display_name} wins (of {n_red} total)...")
                with cost_tracker.track("red_train", technique, examples=len(red_paths)):
                    red_trained = _train_safely("red", max_examples_to_train, technique=technique)
                # Step 9.3 - archive the just-trained checkpoint into the league.
                if red_trained:
                    new_red_v = get_version(adapter_path("red", technique))
                    if league.snapshot("red", technique, new_red_v):
                        print(f"  League: archived red {technique} v{new_red_v}")
            else:
                print(f"\n  RED team: only {n_red} {tech.display_name} wins so far "
                      f"(need {min_examples_to_train} to train, skipping)")

            # Blue: train if it has enough winning examples COMBINED ACROSS
            # EVERY technique - blue is a single shared adapter, and its actual
            # skill (discriminating between categories) only develops by
            # training on a mix of techniques together, not this run's alone.
            n_blue = count_examples_all("blue")
            if n_blue >= min_examples_to_train:
                blue_paths = get_data_path_all(
                    "blue", max_examples=max_examples_to_train, always_include=this_round_blue_win_paths,
                )
                breakdown = collections.Counter(Path(p).parent.name for p in blue_paths)
                breakdown_str = ", ".join(f"{t}={c}" for t, c in breakdown.items())
                print(f"\n  Training BLUE team (shared) on {len(blue_paths)} most recent wins "
                      f"across all techniques (of {n_blue} total, capped per technique): {breakdown_str}")
                with cost_tracker.track("blue_train", technique, examples=len(blue_paths)):
                    blue_trained = _train_safely("blue", max_examples_to_train, force_include_paths=this_round_blue_win_paths)
                # Step 9.3 - archive the just-trained shared blue checkpoint.
                if blue_trained:
                    new_blue_v = get_version(adapter_path("blue"))
                    if league.snapshot("blue", None, new_blue_v):
                        print(f"  League: archived blue v{new_blue_v}")
            else:
                print(f"\n  BLUE team: only {n_blue} wins across all techniques so far "
                      f"(need {min_examples_to_train} to train, skipping)")
    finally:
        # Step 9.3 - never leave a league adapter override set past the loop.
        os.environ.pop("RED_ADAPTER_PATH_OVERRIDE", None)
        os.environ.pop("BLUE_ADAPTER_PATH", None)
        if live_writer is not None:
            live_writer.close()
        if round_writer is not None:
            round_writer.close()

    print("\n" + "=" * 60)
    print("  Training loop complete.")
    print(f"  Stats saved to: {STATS_FILE}")
    print("=" * 60)


def _unload_ollama_judge() -> None:
    """Tell Ollama to evict the judge model from VRAM before training starts."""
    import requests

    model = os.getenv("JUDGE_MODEL", "llama3.2")
    try:
        requests.post(
            "http://localhost:11434/api/chat",
            json={"model": model, "messages": [], "keep_alive": 0},
            timeout=10,
        )
        print(f"  Ollama judge model ({model}) unloaded from VRAM.")
    except Exception:
        pass  # Ollama not running or not in use — safe to ignore


def _unload_inference_models() -> None:
    """Clear model caches so VRAM is available for training."""
    import gc
    import torch

    _mem_checkpoint("battle_loop: before unloading inference models")

    popped_keys = []
    for module_name in ("agents.red_team.agent", "agents.blue_team.agent"):
        if module_name in sys.modules:
            mod = sys.modules[module_name]
            if hasattr(mod, "_model_cache"):
                # Pop each entry and explicitly delete the model/tokenizer objects
                # before clearing so GC can free CUDA tensors immediately
                for key in list(mod._model_cache.keys()):
                    model, tokenizer = mod._model_cache.pop(key)
                    del model, tokenizer
                    popped_keys.append(f"{module_name}:{key}")

    gc.collect()
    gc.collect()  # second pass catches circular refs in quantized models
    if torch.cuda.is_available():
        torch.cuda.synchronize()  # wait for all CUDA ops to finish
        torch.cuda.empty_cache()

    print(f"  Model cache cleared. Evicted keys: {popped_keys or '(none - cache was already empty)'}")
    _mem_checkpoint("battle_loop: after unloading inference models")


def _log_stats(round_num, technique, attack_battles, attack_successes, detections, normal_battles, false_positives, fix_proposed, fix_verified, elapsed, real_attack_battles, real_attack_successes):
    STATS_FILE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "round": round_num,
        "technique": technique,
        "attack_battles": attack_battles,
        "attack_successes": attack_successes,
        # Step 5.3 - excludes distractor-target rounds, which are
        # deliberately unexploitable; see agents/safety plan notes /
        # training/progress_state.py for why this differs from
        # attack_battles/attack_successes above (still the right
        # denominator for blue_detection_rate).
        "real_attack_battles": real_attack_battles,
        "real_attack_successes": real_attack_successes,
        "detections": detections,
        "normal_battles": normal_battles,
        "false_positives": false_positives,
        "fix_proposed": fix_proposed,
        "fix_verified": fix_verified,
        "red_attack_success_rate": round(real_attack_successes / real_attack_battles, 3) if real_attack_battles else 0,
        "blue_detection_rate": round(detections / attack_battles, 3) if attack_battles else 0,
        "blue_false_positive_rate": round(false_positives / normal_battles, 3) if normal_battles else 0,
        "blue_fix_verified_rate": round(fix_verified / fix_proposed, 3) if fix_proposed else 0,
        "elapsed_seconds": elapsed,
    }
    with open(STATS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def _log_tensorboard_round(writer, technique, global_round, attack_battles, attack_successes, detections, normal_battles, false_positives, fix_proposed, fix_verified, real_attack_battles, real_attack_successes) -> None:
    """Step 4.3: round-level scalars - red's attack success rate and blue's
    detection rate tracked independently (not collapsed into a win/loss/
    draw), plus blue's false-positive rate on normal-traffic rounds - so
    training-time progress is plottable next to eval_harness.py's held-out
    numbers (which use this same framing) in the same TensorBoard instance.
    Step 7.3 adds fix_verified_rate alongside them - blue's remediation
    signal, tracked independently from detection the same way false positives
    already are.

    Takes an already-open writer (opened once per run_loop() call, into this
    run's own dated directory so sessions don't overlap). The technique is
    kept in each tag ("rounds/<technique>/...") so every technique gets its
    OWN chart - red's attack success rate and blue's detection rate both in
    the rounds view, mirroring the live writer's per-technique live view."""
    if real_attack_battles:
        writer.add_scalar(f"rounds/{technique}/red_attack_success_rate", real_attack_successes / real_attack_battles, global_round)
    if attack_battles:
        writer.add_scalar(f"rounds/{technique}/blue_detection_rate", detections / attack_battles, global_round)
    if normal_battles:
        writer.add_scalar(f"rounds/{technique}/false_positive_rate", false_positives / normal_battles, global_round)
    if fix_proposed:
        writer.add_scalar(f"rounds/{technique}/fix_verified_rate", fix_verified / fix_proposed, global_round)
    writer.flush()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Self-play training loop for SentinelAI")
    parser.add_argument("--rounds",       type=int,  default=10,  help="Number of training rounds")
    parser.add_argument("--battles",      type=int,  default=50,  help="Battles per round")
    parser.add_argument("--min-examples", type=int,  default=10,  help="Min wins before training fires")
    parser.add_argument("--max-examples", type=int,  default=200, help="Sliding window: max recent wins used per training run")
    parser.add_argument("--target-url", type=str, default=None,
                        help="Pin every battle to one fixed lab target URL, e.g. http://localhost:5001. "
                             "Default: unset, which randomizes the target every battle across the "
                             "technique's training pool + occasional distractor (Step 5, training/targets.py).")
    parser.add_argument("--technique", type=str, default=DEFAULT_TECHNIQUE_ID,
                        help=f"Registered technique id (see agents/techniques/), or 'all' to run every "
                             f"technique's full rounds x battles back-to-back in one process (unattended "
                             f"overnight runs). Default: {DEFAULT_TECHNIQUE_ID}")
    parser.add_argument("--no-eval", action="store_true",
                        help="--technique all only: skip the automatic before/after eval_harness snapshot "
                             "(on by default) and just do training, like before this flag existed.")
    parser.add_argument("--eval-attacks-per-technique", type=int, default=2,
                        help="--technique all only: attack battles per target in each before/after eval "
                             "snapshot (x4 targets x6 techniques x2 snapshots). Default: 2.")
    parser.add_argument("--eval-normal-per-technique", type=int, default=1,
                        help="--technique all only: normal-traffic battles per target in each before/after "
                             "eval snapshot. Default: 1.")
    parser.add_argument("--no-curriculum", action="store_true",
                        help="Step 9.1: disable curriculum target selection (easy tiers first, harder ones "
                             "unlock as the win rate stabilizes) and go back to uniform random target picks. "
                             "Ignored when --target-url pins a single target.")
    parser.add_argument("--league", action="store_true",
                        help="Step 9.3: enable the checkpoint league - some rounds pit the current side "
                             "against an archived past opponent to resist self-play collapse. Off by default "
                             "(it loads an extra adapter). Checkpoint snapshotting happens regardless.")
    args = parser.parse_args()

    if args.technique == "all":
        if args.target_url is not None:
            parser.error("--target-url can't be combined with --technique all - each technique needs its "
                         "own target(s). Omit --target-url to use the randomized per-technique pool.")
        run_loop_all(
            rounds=args.rounds,
            battles_per_round=args.battles,
            min_examples_to_train=args.min_examples,
            max_examples_to_train=args.max_examples,
            target_url=args.target_url,
            run_eval_snapshots=not args.no_eval,
            eval_attacks_per_technique=args.eval_attacks_per_technique,
            eval_normal_per_technique=args.eval_normal_per_technique,
            use_curriculum=not args.no_curriculum,
            use_league=args.league,
        )
    else:
        run_loop(
            rounds=args.rounds,
            battles_per_round=args.battles,
            min_examples_to_train=args.min_examples,
            max_examples_to_train=args.max_examples,
            target_url=args.target_url,
            technique=args.technique,
            use_curriculum=not args.no_curriculum,
            use_league=args.league,
        )
