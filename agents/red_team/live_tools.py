"""
Real tool-calling attack loop for SentinelAI (Step 2: generalized framework).

Unlike agent.py's attack(), which only ever generates a JSON *description* of
a hypothetical payload, run_live_attack() drives a real tool-calling
conversation on the user's own trained local model (Qwen2.5 + LoRA adapter),
using Qwen's native <tool_call> chat-template support - the model chooses to
call a real HTTP tool against a real target and sees the real result, then
can react to it. Because it's the same model (and adapter) trained by
train_agent.py, fine-tuning on successful live attacks actually reinforces
this exact behavior.

This module is technique-agnostic: it drives the generic model/tool-calling
loop for whichever Technique (agents/techniques/) it's given. All
technique-specific detail (tool schema, prompts, execution, payload
description) lives on the Technique itself.
"""

import json
import random
import re
import time

MAX_NEW_TOKENS = 512

# Fraction of live rounds where red performs a real, harmless action instead
# of attacking, so blue gets real negative (no-attack) examples to train on.
NORMAL_TRAFFIC_PROBABILITY = 0.175

_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def _run_normal_action(technique, target_url: str) -> dict:
    """A single real, harmless request against the live target - no model
    inference, no multi-turn loop, since there's no attack to iterate on."""
    start = time.time()
    result = technique.perform_normal_action(target_url)
    payload = technique.describe_attempt(result) if result else "no action attempted"

    return {
        "attack_type": technique.id,
        "payload": payload,
        "technique": technique.display_name,
        "target": f"{target_url}{technique.endpoint_path}",
        "severity": "none",
        "mitre_technique": technique.mitre_technique,
        "success": False,
        "tool_calls": [result] if result else [],
        "artifacts": {},
        "reasoning": "Normal traffic round: a benign action was performed instead of an attack attempt.",
        "latency": round(time.time() - start, 3),
        "_live_messages": [],
        "was_attack": False,
    }


def _parse_tool_calls(text: str) -> list[dict]:
    """Extract <tool_call>{...}</tool_call> blocks. Malformed JSON is skipped."""
    calls = []
    for raw in _TOOL_CALL_RE.findall(text):
        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(parsed, dict) and "name" in parsed:
            calls.append(parsed)
    return calls


def run_live_attack(
    technique_id: str,
    target_url: str,
    max_turns: int | None = None,
    normal_traffic_probability: float = NORMAL_TRAFFIC_PROBABILITY,
    chain_context: dict | None = None,
) -> dict:
    """Drive a real tool-calling loop, on the user's local trained model,
    against the live lab target for the given technique.

    max_turns: defaults to the technique's own Technique.max_turns (see
    agents/techniques/base.py) when left as None - pass an explicit value
    only to override that per-technique default for this one call.

    chain_context (Step 8.3 router-orchestrated chaining): reusable artifacts
    an EARLIER technique in this battle already discovered (e.g.
    {"reset_token": "RST-..."}), handed down by the router via
    battle_runner.py. When non-empty it's appended to the attack's opening
    user message so this step can actually USE what a previous step stole -
    that's the whole mechanism that turns two single-step techniques into a
    chain. The returned dict's "artifacts" key carries anything THIS step
    discovered, to be folded into the battle state for the next decision.

    On a small fraction of calls (`normal_traffic_probability`), performs a
    real, harmless action instead of attacking, so blue gets genuine
    negative examples - the returned dict is tagged `was_attack: False` and
    the model is never invoked for that round.

    Returns an attack dict shaped like RedTeamAgent.attack()'s output, plus
    `success` (real ground truth from the HTTP response), `tool_calls` (the
    real transcript of every attempt made), and `_live_messages` (the full
    conversation, for saving as a training example that matches this exact
    inference-time format).
    """
    from agents.techniques import get_technique

    technique = get_technique(technique_id)
    turns = max_turns if max_turns is not None else technique.max_turns

    if random.random() < normal_traffic_probability:
        return _run_normal_action(technique, target_url)

    from agents.red_team.agent import _get_local_model

    import torch

    model, tokenizer = _get_local_model(technique.id)

    user_content = technique.user_prompt_template.format(target_url=target_url)
    if chain_context:
        # Hand this step whatever earlier steps already stole, so the router
        # can chain techniques (Step 8.3): a later technique reuses an earlier
        # one's loot instead of each technique running blind.
        artifact_lines = "\n".join(f"  - {k} = {v}" for k, v in chain_context.items())
        user_content += (
            "\n\nReusable information already discovered in earlier steps of this engagement "
            "(use it directly - do not re-discover it):\n" + artifact_lines
        )
    messages = [
        {"role": "system", "content": technique.system_prompt},
        {"role": "user", "content": user_content},
    ]

    start = time.time()
    tool_calls_made: list[dict] = []
    winning_call = None
    final_text = ""

    for _ in range(turns):
        encoded = tokenizer.apply_chat_template(
            messages,
            tools=technique.tool_schemas,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
        )
        if hasattr(encoded, "input_ids"):
            input_ids = encoded["input_ids"].to(model.device)
        else:
            input_ids = encoded.to(model.device)

        with torch.inference_mode():
            output = model.generate(
                input_ids,
                max_new_tokens=MAX_NEW_TOKENS,
                temperature=0.7,
                do_sample=True,
                pad_token_id=tokenizer.eos_token_id,
                repetition_penalty=1.1,
            )

        new_tokens = output[0][input_ids.shape[1]:]
        generated_text = tokenizer.decode(new_tokens, skip_special_tokens=True)

        parsed_calls = _parse_tool_calls(generated_text)
        if not parsed_calls:
            final_text = generated_text
            messages.append({"role": "assistant", "content": generated_text})
            break

        prose = _TOOL_CALL_RE.sub("", generated_text).strip()
        messages.append({
            "role": "assistant",
            "content": prose,
            "tool_calls": [{"name": c["name"], "arguments": c.get("arguments", {})} for c in parsed_calls],
        })

        for call in parsed_calls:
            args = call.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except (json.JSONDecodeError, ValueError):
                    args = {}

            result = technique.execute_tool_call(target_url, call.get("name", ""), args)
            tool_calls_made.append(result)
            if result.get("success") and winning_call is None:
                winning_call = result

            messages.append({"role": "tool", "content": json.dumps(result)})

        if winning_call is not None:
            break

    # Fold together any reusable artifacts this step's tool calls surfaced
    # (Step 8.3) - e.g. a leaked reset_token - so the router can hand them to
    # the next technique in the chain. Each technique's execute_tool_call
    # opts in by putting an "artifacts" dict on its result.
    artifacts: dict = {}
    for call in tool_calls_made:
        found = call.get("artifacts")
        if isinstance(found, dict):
            artifacts.update(found)

    success = winning_call is not None
    last_call = winning_call or (tool_calls_made[-1] if tool_calls_made else None)
    if last_call is None:
        payload = "no payload attempted"
    else:
        try:
            payload = technique.describe_attempt(last_call)
        except KeyError:
            # last_call can be the generic {"error": ..., "success": False}
            # shape every technique's execute_tool_call returns for an
            # unrecognized tool name (a hallucinated/malformed call) - every
            # technique's own describe_attempt() indexes a specific key
            # (filename, username, url, ...) with no fallback for that
            # shape, so this is the framework-level backstop rather than
            # fixing it six times identically.
            payload = f"tool call failed: {last_call.get('error', 'malformed tool call')}"

    return {
        "attack_type": technique.id,
        "payload": payload,
        "technique": technique.display_name,
        "target": f"{target_url}{technique.endpoint_path}",
        "severity": technique.severity_success if success else technique.severity_failure,
        "mitre_technique": technique.mitre_technique,
        "success": success,
        "tool_calls": tool_calls_made,
        "artifacts": artifacts,
        "reasoning": final_text,
        "latency": round(time.time() - start, 3),
        "_live_messages": messages,
        "was_attack": True,
    }
