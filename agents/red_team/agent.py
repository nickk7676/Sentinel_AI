import os
from pathlib import Path

# Root directory holding every technique's own adapter subdirectory:
# training/adapters/red_team/<technique_id>/. Separate adapters per
# technique share no weights, so training one technique can never disturb
# another's - forgetting is impossible by construction, not managed via
# rehearsal. The base model underneath is shared and unchanged.
_PROJECT_ROOT = Path(__file__).parent.parent.parent
ADAPTERS_ROOT = Path(os.getenv("RED_ADAPTERS_ROOT", _PROJECT_ROOT / "training" / "adapters" / "red_team"))

# Module-level model cache so we load once per process (keyed by adapter
# path, or "base" when no adapter exists yet for a given technique - shared
# across techniques that haven't been trained yet, so we don't load
# redundant copies of the same untrained base model).
_model_cache: dict = {}


def adapter_path(technique_id: str) -> Path:
    return ADAPTERS_ROOT / technique_id


def _get_local_model(technique_id: str):
    """Load (or return the cached) local base model + this technique's own
    LoRA adapter + tokenizer.

    Used by the live tool-calling loop in live_tools.run_live_attack.
    """
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    # Step 9.3 - the checkpoint league points red at a past snapshot for a
    # battle by setting RED_ADAPTER_PATH_OVERRIDE (mirrors blue's
    # BLUE_ADAPTER_PATH). Unset in normal self-play -> this technique's own
    # live adapter.
    override = os.getenv("RED_ADAPTER_PATH_OVERRIDE")
    path = override or str(adapter_path(technique_id))
    adapter_exists = os.path.isdir(path) and os.path.exists(
        os.path.join(path, "adapter_config.json")
    )
    cache_key = path if adapter_exists else "base"

    if cache_key not in _model_cache:
        base_model = os.getenv("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct")
        print(f"[RedTeam] Loading model: {base_model}" + (f" + {technique_id} adapter" if adapter_exists else ""))

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


class RedTeamAgent:
    def attack_live(
        self,
        target_url: str,
        technique: str = None,
        normal_traffic_probability: float | None = None,
    ) -> dict:
        """normal_traffic_probability overrides live_tools' default random mix
        (Step 2.5) - leave as None during normal training, or pass 0.0/1.0 to
        force an attack-only or normal-only battle (used by the Step 4 eval
        harness to measure detection rate and false-positive rate separately
        from a fixed, deterministic split)."""
        from agents.red_team.live_tools import run_live_attack
        from agents.techniques import DEFAULT_TECHNIQUE_ID

        kwargs = {}
        if normal_traffic_probability is not None:
            kwargs["normal_traffic_probability"] = normal_traffic_probability

        return run_live_attack(technique or DEFAULT_TECHNIQUE_ID, target_url, **kwargs)
