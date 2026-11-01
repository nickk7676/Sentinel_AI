"""
The router's decision point (Step 8.1/8.2): given what's known about a
target so far, decide whether to gather more recon, invoke a specific
technique, or stop.

Model loading mirrors agents/blue_team/agent.py's _call_local /
agents/red_team/agent.py's _get_local_model: base Qwen2.5 in 4-bit, plus an
optional LoRA adapter loaded only if one already exists on disk at
training/adapters/router_team/ (training.train_agent.adapter_path("router")
- that helper already supports an arbitrary agent_name, so no change to
train_agent.py was needed). No adapter exists yet, so decide() runs on the
plain base model today - this is deliberate (see the project plan: measure
baseline accuracy before building a training pipeline) and needs no code
change later if agents/red_team/router/train_router.py is ever written -
it'll just start getting picked up here automatically.

decide() is only ever called at a decision point (battle start, after a
technique adapter finishes its turns, after new recon findings arrive) -
never once per turn - so its own inference cost is small relative to a
technique's multi-turn tool-calling loop.
"""

from __future__ import annotations

import json
import os

from agents.red_team.router.schema import ROUTER_ACTIONS, BattleState, RouterDecision
from agents.red_team.router.state import to_prompt_block
from agents.techniques import get_technique, list_techniques
from training.train_agent import adapter_path as _adapter_path

MAX_NEW_TOKENS = 256

_model_cache: dict = {}

SYSTEM_PROMPT = """You are the decision-making component of a cybersecurity red team AI conducting an authorized, sandboxed penetration test.

You never attack anything directly. You are given a summary of what's been learned about a target so far (recon findings, techniques already tried and their outcomes, and any reusable artifacts discovered) plus a list of available attack techniques with short descriptions. Your only job is to decide what to do next.

Respond with valid JSON only - no extra text before or after - in this exact format:
{
  "action": "<one of: invoke_technique, recon_more, stop>",
  "technique_id": "<the technique id to invoke, or null if action is not invoke_technique>",
  "reasoning": "<one or two sentences explaining the choice, for audit/debugging - not shown to any tool>"
}

Choose "invoke_technique" when the recon findings or a chain note point clearly at one technique (e.g. a sequential/numeric id in a path suggests IDOR; a form with free-text fields feeding into a lookup suggests SQL injection). Choose "recon_more" only if there's a clear, specific next thing worth learning - not just because you're unsure. Choose "stop" once every available technique has already been tried, or nothing further seems learnable."""


def describe_techniques(available_technique_ids: list[str]) -> str:
    lines = []
    for tech in list_techniques():
        if tech.id not in available_technique_ids:
            continue
        keywords = ", ".join(tech.category_keywords[:4]) or "(no keywords)"
        lines.append(f"  - {tech.id}: {tech.display_name} (signals: {keywords})")
    return "\n".join(lines)


def build_prompt(state_prompt_block: str, available_techniques: list[str], recon_exhausted: bool = False) -> str:
    """The exact user-turn text decide() sends the model - takes the already-
    rendered to_prompt_block() string (not a live BattleState) specifically
    so agents/red_team/router/build_router_dataset.py can reconstruct byte-
    identical prompts straight from a logged session's decision_log entries
    (training/router_session_log.py), with no BattleState object needed.
    Training on a prompt shape that drifts from what's actually used at
    inference time would teach a disconnected habit instead of reinforcing
    real behavior (same rationale as training/train_agent.py's tool-schema-
    consistency comment)."""
    exhausted_note = (
        '\n\nNo further recon is possible for this decision - "recon_more" is not a valid '
        'choice here. The "action" field must be either "invoke_technique" (your best guess '
        'of which technique fits, given what\'s known) or "stop".'
        if recon_exhausted else ""
    )
    return (
        f"{state_prompt_block}\n\n"
        f"Available techniques:\n{describe_techniques(available_techniques)}"
        f"{exhausted_note}\n\n"
        "What should happen next?"
    )


def _adapter_exists() -> bool:
    path = str(_adapter_path("router"))
    return os.path.isdir(path) and os.path.exists(os.path.join(path, "adapter_config.json"))


def _get_router_model():
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    path = str(_adapter_path("router"))
    adapter_exists = _adapter_exists()
    cache_key = path if adapter_exists else "base"

    if cache_key not in _model_cache:
        base_model = os.getenv("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct")
        print(f"[Router] Loading model: {base_model}" + (" + router adapter" if adapter_exists else " (no router adapter yet - base model only)"))

        bnb = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )
        model = AutoModelForCausalLM.from_pretrained(
            base_model,
            quantization_config=bnb,
            device_map="auto",
        )
        tokenizer = AutoTokenizer.from_pretrained(base_model)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token

        if adapter_exists:
            from peft import PeftModel
            model = PeftModel.from_pretrained(model, path)

        model.eval()
        _model_cache[cache_key] = (model, tokenizer)

    return _model_cache[cache_key]


def _call_router_model(user_prompt: str) -> str:
    import torch

    model, tokenizer = _get_router_model()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]
    encoded = tokenizer.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True, return_tensors="pt",
    )
    input_ids = encoded["input_ids"].to(model.device) if hasattr(encoded, "input_ids") else encoded.to(model.device)

    with torch.inference_mode():
        output = model.generate(
            input_ids,
            max_new_tokens=MAX_NEW_TOKENS,
            # Greedy, not sampled. Picking which technique fits the recon is a
            # confidence-ranked decision, not a creative one - sampling at
            # temperature 0.7 was injecting randomness into the choice, so a
            # correctly-learned target would still be mis-picked a fraction of
            # the time purely from the dice roll. Greedy decoding takes the
            # model's top-judged technique every time, which is what a router
            # should do (the per-technique attack agents still sample their own
            # payloads; this only makes the routing decision deterministic).
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
            repetition_penalty=1.1,
        )

    new_tokens = output[0][input_ids.shape[1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True)


def _parse_decision(raw: str) -> dict | None:
    """Same JSON-parse-with-fallback shape as agents/blue_team/agent.py's
    _parse_json: try strict parse, then try substring-between-braces, then
    give up (caller treats None as "couldn't parse")."""
    try:
        return json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    start, end = raw.find("{"), raw.rfind("}") + 1
    if start != -1 and end > start:
        try:
            return json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def unload_router_model() -> None:
    """Frees the router's own cached model - separate from
    agents.red_team.agent._model_cache / agents.blue_team.agent._model_cache
    (each of red/blue/router already loads its own independent copy of the
    base model today, so this follows the same precedent rather than
    introducing shared-weight adapter-swapping)."""
    import gc

    for key in list(_model_cache.keys()):
        model, tokenizer = _model_cache.pop(key)
        del model, tokenizer
    gc.collect()
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.synchronize()
            torch.cuda.empty_cache()
    except ImportError:
        pass


def decide(state: BattleState, available_techniques: list[str], recon_exhausted: bool = False) -> RouterDecision:
    """recon_exhausted: set True when no further recon is actually possible
    (used by training/router_baseline_eval.py, which reconstructs state from
    historical battles that have no recon findings at all). When True,
    "recon_more" is removed from the offered action set entirely (not just
    discouraged in prose) - a plain 3B base model reliably ignores a soft
    "don't pick this" instruction but still respects a schema that never
    mentions the option, and every fallback path below degrades to "stop"
    instead of "recon_more" so a malformed/hallucinated response can't
    resurrect an action that was never actually on the table. battle_runner.py
    leaves this False and lets its own consecutive-empty-recon guard force a
    stop instead, since recon_more there is a legitimate option, not a dead
    end."""
    fallback_action = "stop" if recon_exhausted else "recon_more"
    actions_offered = ("invoke_technique", "stop") if recon_exhausted else ROUTER_ACTIONS

    prompt = build_prompt(to_prompt_block(state), available_techniques, recon_exhausted=recon_exhausted)
    raw = _call_router_model(prompt)
    parsed = _parse_decision(raw)

    if parsed is None:
        return RouterDecision(action=fallback_action, technique_id=None, reasoning=f"unparseable router output: {raw[:200]!r}")

    action = str(parsed.get("action") or "").strip()
    technique_id = parsed.get("technique_id")
    reasoning = str(parsed.get("reasoning") or "").strip()

    if action not in actions_offered:
        return RouterDecision(action=fallback_action, technique_id=None, reasoning=f"action {action!r} not valid here, reasoning was: {reasoning!r}")

    if action == "invoke_technique":
        if not technique_id:
            return RouterDecision(action=fallback_action, technique_id=None, reasoning="invoke_technique chosen with no technique_id")
        try:
            get_technique(technique_id)
        except KeyError:
            return RouterDecision(action=fallback_action, technique_id=None, reasoning=f"hallucinated unknown technique_id {technique_id!r}")

    return RouterDecision(action=action, technique_id=technique_id if action == "invoke_technique" else None, reasoning=reasoning)
