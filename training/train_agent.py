"""
Fine-tunes a LoRA adapter for either the red or blue team agent.

Red is scoped to a single technique per training run: each technique gets
its own adapter directory (training/adapters/red_team/<technique_id>/) -
separate adapters share no weights, so training technique B can never
disturb technique A's adapter (forgetting is impossible by construction).
Red specializes by technique, so this fits how it actually works.

Blue is a single shared adapter (training/adapters/blue_team/), trained
jointly on a mix of every technique's saved examples at once. Blue's actual
skill is discriminating between categories from raw log evidence, not
acting out one specific technique - splitting it per technique would be
circular (it would require already knowing the technique before running
detection, which is what blue is supposed to figure out) and would remove
the very signal blue needs to learn to tell techniques apart from each
other.

The base model underneath is shared and unchanged either way.

How it works:
  1. Loads the base model (Qwen2.5-3B-Instruct) in 4-bit to save VRAM
  2. If this adapter already exists (this technique's, for red; the shared
     one, for blue), loads it and continues training (so the model keeps
     improving across rounds, not resetting each time)
  3. If no adapter exists yet, applies a fresh LoRA config to the base model
  4. Trains on the given winning examples
  5. Saves the updated adapter back to disk — inference will pick it up
     next round

Run directly to train a specific agent (and, for red, a specific technique):
  python -m training.train_agent --agent red --technique sql_injection
  python -m training.train_agent --agent blue
"""

import gc
import os
from pathlib import Path

from training.adapter_version import bump_version
from training.dataset import DATA_DIR

BASE_MODEL = os.getenv("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct")
ADAPTERS_DIR = Path(__file__).parent / "adapters"
TENSORBOARD_DIR = DATA_DIR / "tensorboard"


def _mem_checkpoint(label: str) -> None:
    """Diagnostic only - prints allocated vs reserved VRAM at a labeled point
    in train(), so a persistent leak can be localized to the specific step
    that introduces it instead of guessed at. Compare the same label across
    rounds: if `allocated` itself climbs round over round, something is still
    holding a real tensor reference past cleanup. If only `reserved` climbs
    while `allocated` stays flat, that's the caching allocator's high-water
    mark (normal, not a leak) - reserved is what PyTorch has claimed from the
    driver, allocated is what's actually live right now."""
    import torch

    if not torch.cuda.is_available():
        return
    allocated = torch.cuda.memory_allocated() / 1024**3
    reserved = torch.cuda.memory_reserved() / 1024**3
    print(f"    [mem] {label}: allocated={allocated:.2f} GB  reserved={reserved:.2f} GB")


def adapter_path(agent_name: str, technique_id: str | None = None) -> Path:
    """Adapter directory for this agent. Red is scoped per technique - pass
    its technique_id to select that technique's own directory. Blue is a
    single shared adapter trained jointly across every technique - leave
    technique_id as None (or omit it)."""
    if technique_id is None:
        return ADAPTERS_DIR / f"{agent_name}_team"
    return ADAPTERS_DIR / f"{agent_name}_team" / technique_id


def train(agent_name: str, data_path: list[str], technique_id: str | None = None) -> None:
    """
    Fine-tune this agent's LoRA adapter on the given winning examples.

    agent_name:   "red" or "blue"
    data_path:    list of example file paths (as returned by
                  training.dataset.get_data_path for red, or
                  get_data_path_all for blue)
    technique_id: for red, the technique being trained - selects and saves
                  to that technique's own adapter directory. For blue,
                  leave as None - blue always trains on a joint batch and
                  saves to the one shared adapter directory.
    """
    import torch
    from datasets import load_dataset
    from peft import (
        LoraConfig,
        PeftModel,
        get_peft_model,
        prepare_model_for_kbit_training,
    )
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
    )
    from trl import SFTConfig, SFTTrainer

    adapter_save_path = str(adapter_path(agent_name, technique_id))
    label = technique_id if technique_id else "all techniques (joint)"
    tb_run_dir = str(TENSORBOARD_DIR / "train" / f"{agent_name}_{technique_id or 'all'}")

    print(f"\n--- Training {agent_name.upper()} team on {label} ---")
    print(f"Data:    {data_path}")
    print(f"Adapter: {adapter_save_path}")

    # Load base model in 4-bit (uses ~1.5GB VRAM for a 3B model)
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        quantization_config=bnb,
        device_map="auto",
    )
    _mem_checkpoint("after base model load")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    tokenizer.padding_side = "right"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Required before adding LoRA to a quantized model
    model = prepare_model_for_kbit_training(model)

    adapter_config_path = os.path.join(adapter_save_path, "adapter_config.json")
    if os.path.exists(adapter_config_path):
        # Continue training from the existing adapter (keeps learned knowledge)
        print("Loading existing adapter for continued training...")
        model = PeftModel.from_pretrained(model, adapter_save_path, is_trainable=True)
    else:
        # First round for this adapter — apply a fresh LoRA config
        lora_config = LoraConfig(
            r=16,
            lora_alpha=32,
            # Target the attention and feed-forward layers
            target_modules=[
                "q_proj", "k_proj", "v_proj", "o_proj",
                "gate_proj", "up_proj", "down_proj",
            ],
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

    # Load and format the winning examples
    dataset = load_dataset("json", data_files=data_path, split="train", keep_in_memory=True)

    # Tool name -> schema, gathered across every registered technique, so a
    # transcript is rendered with whichever technique's tool(s) it actually
    # used - this file doesn't need to know which technique produced it.
    from agents.techniques import list_techniques

    tool_schema_by_name = {
        schema["function"]["name"]: schema
        for tech in list_techniques()
        for schema in tech.tool_schemas
    }

    def _format(example):
        # Live tool-calling transcripts include a "tool" role message. Those
        # must be rendered with the same tools= schema used at inference time
        # so the <tool_call>/<tool_response> tokens actually appear in the
        # training text - otherwise fine-tuning would teach a disconnected
        # plain-text habit instead of reinforcing the real tool-call behavior.
        tool_names = {
            call["name"]
            for m in example["messages"] if m.get("role") == "assistant"
            for call in m.get("tool_calls", [])
        }
        tools = [tool_schema_by_name[name] for name in tool_names if name in tool_schema_by_name] or None

        return {
            "text": tokenizer.apply_chat_template(
                example["messages"],
                tools=tools,
                tokenize=False,
                add_generation_prompt=False,
            )
        }

    dataset = dataset.map(_format, remove_columns=dataset.column_names)
    print(f"Training on {len(dataset)} winning examples...")

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=dataset,
        args=SFTConfig(
            output_dir=adapter_save_path + "_tmp",
            num_train_epochs=3,
            per_device_train_batch_size=1,
            gradient_accumulation_steps=8,   # effective batch size = 8
            learning_rate=2e-4,
            bf16=True,
            logging_steps=5,
            save_strategy="no",              # we save manually below
            dataset_text_field="text",
            report_to="tensorboard",
            logging_dir=tb_run_dir,
            # Non-paged: "paged" variants allocate optimizer state via bitsandbytes'
            # get_paged(), a raw cudaMallocManaged call outside PyTorch's caching
            # allocator, appended to a bitsandbytes-internal singleton
            # (GlobalPageManager.paged_tensors) that is never cleared - those buffers
            # survive del/gc.collect()/empty_cache() and accumulate permanently, one
            # round's worth at a time. Paging exists to spill state for full
            # fine-tunes of models too big to fit in VRAM; a rank-16 LoRA's optimizer
            # state is tiny, so paging buys nothing here and only costs a leak.
            optim="adamw_8bit",

        ),
    )

    _mem_checkpoint("after PEFT wrap, before trainer.train()")
    trainer.train()
    _mem_checkpoint("after trainer.train(), before save")

    # Save the updated adapter (overwrites previous version at this path only)
    os.makedirs(adapter_save_path, exist_ok=True)
    model.save_pretrained(adapter_save_path)
    tokenizer.save_pretrained(adapter_save_path)
    new_version = bump_version(Path(adapter_save_path))
    print(f"Saved updated adapter -> {adapter_save_path} (version {new_version})")
    _mem_checkpoint("after save_pretrained, before cleanup")

    # Free VRAM before returning — must be thorough or the next load (training or
    # inference) stacks on top and OOMs. Order matters: trainer.accelerator keeps
    # its own _models/_optimizers/_schedulers lists alive independently of the
    # `trainer` variable (accelerate's own docs say to call free_memory() "between
    # two trainings with different models/optimizers") - skipping this is why VRAM
    # climbed round over round even though trainer/model/tokenizer were deleted
    # below. So: free the accelerator's internal refs first, then delete trainer
    # (which holds the model), then tokenizer.
    trainer.accelerator.free_memory()
    del trainer
    del model
    del tokenizer
    gc.collect()
    gc.collect()  # second pass catches circular refs in quantized models
    if torch.cuda.is_available():
        torch.cuda.synchronize()
        torch.cuda.empty_cache()
    _mem_checkpoint("after cleanup (train() returning)")


if __name__ == "__main__":
    import argparse
    import json

    from agents.techniques import DEFAULT_TECHNIQUE_ID
    from training.dataset import get_data_path, get_data_path_all

    parser = argparse.ArgumentParser()
    parser.add_argument("--agent", choices=["red", "blue"], required=True)
    parser.add_argument("--technique", type=str, default=DEFAULT_TECHNIQUE_ID,
                         help=f"Registered technique id (see agents/techniques/) - RED only, selects "
                              f"which technique's adapter to train. Ignored for blue, which always "
                              f"trains jointly across every technique. Default: {DEFAULT_TECHNIQUE_ID}")
    parser.add_argument("--max-examples", type=int, default=200,
                         help="Sliding window: max recent wins used for this training run. For blue "
                              "this is a per-technique cap (max-examples // number of techniques), not "
                              "a flat total, so one heavily-battled technique can't crowd the others "
                              "out of the joint batch. Should match battle_loop.py's --max-examples "
                              "when invoked from there.")
    parser.add_argument("--force-include-file", type=str, default=None,
                         help="BLUE only. Path to a JSON file containing a list of example paths "
                              "(as returned by save_blue_win) to keep in the batch even if they'd "
                              "fall outside their technique's per-technique cap - battle_loop.py uses "
                              "this so the current round's own fresh wins are never silently dropped.")
    args = parser.parse_args()

    if args.agent == "blue":
        force_include = None
        if args.force_include_file:
            force_include = json.loads(Path(args.force_include_file).read_text(encoding="utf-8"))
        data_path = get_data_path_all("blue", max_examples=args.max_examples, always_include=force_include)
        if not data_path:
            print("No training data found for blue (any technique). Run battle_loop.py first.")
        else:
            train("blue", data_path)
    else:
        data_path = get_data_path("red", args.technique, max_examples=args.max_examples)
        if not data_path:
            print(f"No training data found for red/{args.technique}. Run battle_loop.py first.")
        else:
            train("red", data_path, technique_id=args.technique)
