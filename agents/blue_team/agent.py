import json
import os
import time
from pathlib import Path

import requests

from agents.safety.redact import redact_text

# Providers whose API calls leave the machine - Step 6.3 requires redaction
# before anything is sent to one of these. "local" (in-process) and
# "ollama" (default http://localhost:11434) never leave the box.
_REMOTE_PROVIDERS = {"openai", "huggingface"}

# TEMPORARY bootstrap nudge (added 2026-07-17, diagnosing near-zero IDOR
# detection): real battle logs showed blue calling "no threat" on every
# single IDOR attempt, including ones that succeeded, even when the log line
# itself plainly showed a requester accessing a resource it didn't own -
# blue had never had a positive example of this pattern to learn from, and
# nothing in its prompt hinted to look for it. This is a general procedural
# reminder (not naming this lab's specific field names) - remove once blue
# reliably catches this on its own from training examples.
_BOOTSTRAP_NUDGE = " A request can look completely successful and unremarkable - correct status, well-formed response - and still be an attack: check whether the identity making the request is actually consistent with the account, session, or resource it is accessing, not just whether the request succeeded. A mismatch between who is asking and who/what is being accessed is itself a signal, even with nothing else suspicious in the log."

# TEMPORARY bootstrap nudge (added 2026-07-25, diagnosing generic
# recommended_fix text): real battle logs showed blue reliably detecting
# attacks but never producing a recommended_fix more specific than security-
# advice boilerplate ("sanitize input", "implement proper access control",
# "follow security best practices") - true across every category, not just
# one - so it never named the actual mechanism that closes the hole and
# never passed Step 7.2's fix verification (agents/judge/verification.py's
# per-technique fix_keywords, deliberately tightened to reject exactly this
# kind of generic answer - see agents/techniques/*.py). This is a general
# procedural reminder (not naming any lab's specific fix) - remove once
# blue reliably produces mechanism-specific fixes from training examples of
# its own verified wins.
_FIX_SPECIFICITY_NUDGE = (
    " Your recommended_fix must name the exact technical mechanism that closes this specific hole, not a general security "
    "principle - a reviewer should be able to tell which line of code or logic check is missing just from reading your answer. "
    "Never answer with generic phrases like \"sanitize input\", \"validate input\", \"implement proper access control/"
    "authentication\", or \"follow security best practices\" - those are true of almost every vulnerability and fix nothing on "
    "their own. Instead state precisely what check, comparison, or code change is missing and where it belongs - for example: "
    "which two values should have been compared but weren't, which dangerous operation should never have received unescaped "
    "input, which value should have been generated unpredictably instead of predictably, or which destination should have been "
    "rejected before a request was made to it. If you can't identify that specific mechanism from the evidence in front of you, "
    "say what additional evidence you'd need - do not fall back to a generic platitude."
)

# TEMPORARY bootstrap nudge (added 2026-07-26, diagnosing recommended_fix
# containing the attack payload itself): real battle logs showed blue's
# recommended_fix was, in the large majority of fix-verification attempts
# (78/105 for sql_injection so far), the literal attack payload verbatim
# (e.g. "' OR '1'='1' --") rather than any description of a fix - and this
# same pattern is baked into ~25% of blue's own saved sql_injection training
# examples, so it's being actively reinforced round over round, not just a
# prompting gap. Blue appears to be conflating "what the attacker sent" with
# "what should change in the code". This is a general procedural reminder
# (not naming any lab's specific fix) - remove once blue reliably stops
# doing this from training examples of its own verified wins.
_FIX_PAYLOAD_CONFUSION_NUDGE = (
    " recommended_fix must NEVER contain the attacker's actual input, payload, or exploit string itself - copying what the "
    "attacker sent is not a fix, it is just repeating the attack back. If the specific value the attacker sent is worth "
    "mentioning, that belongs in explanation, not recommended_fix. recommended_fix must instead describe, in your own words "
    "and phrased as an instruction to a developer, the code-level change that would stop this entire class of input from "
    "working - never a quoted string, command, URL, or value copied from the attack itself."
)

# TEMPORARY bootstrap nudge (added 2026-07-26, same diagnosis as
# _FIX_PAYLOAD_CONFUSION_NUDGE above): a worked example, not just an
# abstract rule - this codebase has already learned once, the hard way, with
# path_traversal.py's own bootstrap nudge, that this 3B base model follows a
# single concrete shown example far more reliably than stacked prose rules.
# Deliberately a fictional, made-up vulnerability class (not one of this
# lab's real 6 techniques) so it teaches the general shape of a correct
# answer without ever hinting at a real technique's actual fix or category
# keywords. Remove once blue reliably gets this right from its own training
# examples instead of needing it spelled out here.
_FIX_WORKED_EXAMPLE = """

Worked example (fictional, illustrative only - not one of the real categories you'll actually see):
Log line: 'REQUEST path=/api/export?fmt=../../../etc/passwd result=SUCCESS'
WRONG recommended_fix: "../../../etc/passwd" (this is just the attacker's payload copied back - not a fix, and worthless as an answer)
RIGHT recommended_fix: "Reject any fmt value containing path separators or '..' segments before it is joined onto the export directory, and confirm the resolved path stays inside that directory."
The WRONG answer restates evidence already visible in the log. The RIGHT answer is a code-level instruction that would still make sense even if you deleted the log line above it."""

_VALID_SEVERITIES = ("low", "medium", "high", "critical")

SYSTEM_PROMPT = """You are a cybersecurity blue team AI agent responsible for detecting and neutralizing attacks.
Analyze the provided attack details and produce a structured defense assessment.""" + _BOOTSTRAP_NUDGE + _FIX_SPECIFICITY_NUDGE + _FIX_PAYLOAD_CONFUSION_NUDGE + _FIX_WORKED_EXAMPLE + """

Always respond with valid JSON only — no extra text before or after — in this exact format:
{
  "threat_detected": true,
  "threat_category": "<category of threat, e.g. prompt injection / phishing / code injection>",
  "risk_score": <number 0-10, where 10 is critical>,
  "severity": "<one of: low, medium, high, critical>",
  "confidence": <number 0.0-1.0, how confident you are in this assessment>,
  "explanation": "<plain-language explanation a non-expert could follow: what happened and why it's a threat>",
  "recommended_fix": "<concrete, specific remediation a developer could actually implement to close this hole - not a generic platitude>",
  "mitigation": "<specific mitigation action you are applying>",
  "recommendations": [
    "<security recommendation 1>",
    "<security recommendation 2>",
    "<security recommendation 3>"
  ]
}"""

# Path to this agent's LoRA adapter (populated after training rounds) - a
# single adapter shared across every technique, trained jointly on a mix of
# all of them (see training/battle_loop.py / training/train_agent.py).
# Unlike red, blue's actual skill is discriminating between categories from
# raw log evidence, not acting out one specific technique - a per-technique
# split would be circular (it'd require already knowing the technique
# before running detection, which is what blue is supposed to figure out)
# and would remove the very signal blue needs to learn to tell techniques
# apart from each other.
_PROJECT_ROOT = Path(__file__).parent.parent.parent
ADAPTER_PATH = str(os.getenv("BLUE_ADAPTER_PATH", _PROJECT_ROOT / "training" / "adapters" / "blue_team"))

# Module-level model cache so we load once per process
_model_cache: dict = {}


def _llm_chat(system: str, user: str) -> tuple[str, float]:
    provider = os.getenv("LLM_PROVIDER", "ollama")
    start = time.time()

    if provider == "local":
        content = _call_local(system, user)
    elif provider == "openai":
        content = _call_openai(system, user)
    elif provider == "huggingface":
        content = _call_huggingface(system, user)
    else:
        content = _call_ollama(system, user)

    return content, round(time.time() - start, 3)


def _call_local(system: str, user: str) -> str:
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    adapter_exists = os.path.isdir(ADAPTER_PATH) and os.path.exists(
        os.path.join(ADAPTER_PATH, "adapter_config.json")
    )
    cache_key = ADAPTER_PATH if adapter_exists else "base"

    if cache_key not in _model_cache:
        base_model = os.getenv("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct")
        print(f"[BlueTeam] Loading model: {base_model}" + (f" + adapter" if adapter_exists else ""))

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
            model = PeftModel.from_pretrained(model, ADAPTER_PATH)

        model.eval()
        _model_cache[cache_key] = (model, tokenizer)

    model, tokenizer = _model_cache[cache_key]

    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    encoded = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt",
    )
    # transformers 5.x returns BatchEncoding; older versions return a plain tensor
    if hasattr(encoded, "input_ids"):
        input_ids = encoded["input_ids"].to(model.device)
    else:
        input_ids = encoded.to(model.device)

    import torch
    with torch.inference_mode():
        output = model.generate(
            input_ids,
            max_new_tokens=512,
            temperature=0.7,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id,
            repetition_penalty=1.1,
        )

    new_tokens = output[0][input_ids.shape[1]:]
    return tokenizer.decode(new_tokens, skip_special_tokens=True)


def _call_ollama(system: str, user: str) -> str:
    model = os.getenv("LLM_MODEL", "llama3.2")
    resp = requests.post(
        "http://localhost:11434/api/chat",
        json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "format": "json",
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["message"]["content"]


def _call_openai(system: str, user: str) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    response = client.chat.completions.create(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        response_format={"type": "json_object"},
    )
    return response.choices[0].message.content


def _call_huggingface(system: str, user: str) -> str:
    from huggingface_hub import InferenceClient

    client = InferenceClient(
        model=os.getenv("LLM_MODEL", "mistralai/Mixtral-8x7B-Instruct-v0.1"),
        token=os.getenv("HF_TOKEN"),
    )
    response = client.chat_completion(
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
    )
    return response.choices[0].message.content


def _normalize(data: dict) -> dict:
    if isinstance(data.get("threat_detected"), str):
        data["threat_detected"] = data["threat_detected"].strip().lower() == "true"
    data["risk_score"] = float(data.get("risk_score") or 0)
    recs = data.get("recommendations", [])
    if isinstance(recs, str):
        data["recommendations"] = [r.strip() for r in recs.split(",") if r.strip()]

    # Step 7.1 - severity/confidence/explanation/recommended_fix, with
    # tolerant fallbacks for a model that omits them or returns them
    # malformed, same as risk_score/recommendations above.
    severity = str(data.get("severity") or "").strip().lower()
    data["severity"] = severity if severity in _VALID_SEVERITIES else "medium"
    try:
        confidence = float(data.get("confidence"))
    except (TypeError, ValueError):
        confidence = 0.5
    data["confidence"] = max(0.0, min(1.0, confidence))
    data["explanation"] = str(data.get("explanation") or "").strip()
    data["recommended_fix"] = str(data.get("recommended_fix") or "").strip()
    return data


def _parse_json(raw: str, fallback_category: str) -> dict:
    parsed = None
    try:
        parsed = json.loads(raw.strip())
    except (json.JSONDecodeError, ValueError):
        pass
    if parsed is None:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start != -1 and end > start:
                parsed = json.loads(raw[start:end])
        except (json.JSONDecodeError, ValueError):
            pass
    if parsed is None:
        parsed = {
            "threat_detected": True,
            "threat_category": fallback_category,
            "risk_score": 5.0,
            "severity": "medium",
            "confidence": 0.5,
            "explanation": raw,
            "recommended_fix": "",
            "mitigation": raw,
            "recommendations": [],
        }
    return _normalize(parsed)


LIVE_USER_PROMPT_TEMPLATE = (
    "Analyze this real web server access log excerpt and determine whether it "
    "shows an attack:\n\n{log_text}"
)


class BlueTeamAgent:
    def defend_live(self, log_text: str) -> dict:
        provider = os.getenv("LLM_PROVIDER", "ollama")
        if provider in _REMOTE_PROVIDERS:
            log_text = redact_text(log_text)
        raw, latency = _llm_chat(
            SYSTEM_PROMPT,
            LIVE_USER_PROMPT_TEMPLATE.format(log_text=log_text or "(no new log lines)"),
        )
        result = _parse_json(raw, "unknown")
        result["latency"] = latency
        return result
