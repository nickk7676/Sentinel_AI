import json
import os
import sys
import time
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_PROJECT_ROOT = Path(__file__).resolve().parents[1]

st.set_page_config(
    page_title="SentinelAI Quantum Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.4rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00d4ff, #7b2fff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        color: #888;
        font-size: 0.95rem;
        margin-bottom: 1.5rem;
    }
    .metric-card {
        background: #1a1a2e;
        border: 1px solid #2d2d5a;
        border-radius: 10px;
        padding: 1rem;
        text-align: center;
    }
    .attack-chain-node {
        background: #0f0f23;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 0.8rem;
        margin: 0.4rem 0;
    }
    .red-badge { color: #ff4444; font-weight: bold; }
    .blue-badge { color: #4488ff; font-weight: bold; }
    .green-badge { color: #44ff88; font-weight: bold; }
    .severity-critical { color: #ff2222; font-weight: bold; }
    .severity-high { color: #ff8800; font-weight: bold; }
    .severity-medium { color: #ffcc00; font-weight: bold; }
    .severity-low { color: #44ff88; font-weight: bold; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ── Session state ──────────────────────────────────────────────────────────────
if "simulation_history" not in st.session_state:
    st.session_state.simulation_history = []
if "uploaded_file_content" not in st.session_state:
    st.session_state.uploaded_file_content = None
if "uploaded_file_name" not in st.session_state:
    st.session_state.uploaded_file_name = None
if "training_battle_log" not in st.session_state:
    st.session_state.training_battle_log = []

# ── Sidebar — LLM Provider selector ───────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ Model Settings")

    provider = st.selectbox(
        "LLM Provider",
        options=["local", "ollama", "openai", "huggingface"],
        index=0,
        help=(
            "local = your own trained GPU model\n"
            "ollama = local Ollama server\n"
            "openai = OpenAI API\n"
            "huggingface = HuggingFace Inference API"
        ),
    )
    os.environ["LLM_PROVIDER"] = provider

    if provider == "local":
        base_model = st.text_input(
            "Base Model",
            value=os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct"),
            help="HuggingFace model ID. Downloaded automatically on first use.",
        )
        os.environ["BASE_MODEL"] = base_model
        st.caption("Adapters loaded from `training/adapters/`")

    elif provider == "openai":
        api_key = st.text_input("OpenAI API Key", type="password",
                                value=os.environ.get("OPENAI_API_KEY", ""))
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
        llm_model = st.text_input("Model", value=os.environ.get("LLM_MODEL", "gpt-4o-mini"))
        os.environ["LLM_MODEL"] = llm_model

    elif provider == "ollama":
        llm_model = st.text_input("Ollama Model", value=os.environ.get("LLM_MODEL", "llama3.2"))
        os.environ["LLM_MODEL"] = llm_model

    elif provider == "huggingface":
        hf_token = st.text_input("HuggingFace Token", type="password",
                                 value=os.environ.get("HF_TOKEN", ""))
        if hf_token:
            os.environ["HF_TOKEN"] = hf_token
        llm_model = st.text_input("Model ID",
                                  value=os.environ.get("LLM_MODEL", "mistralai/Mixtral-8x7B-Instruct-v0.1"))
        os.environ["LLM_MODEL"] = llm_model

    st.markdown("---")
    provider_label = {
        "local":       "🟢 Local GPU Model",
        "ollama":      "🟡 Ollama",
        "openai":      "🔵 OpenAI",
        "huggingface": "🟣 HuggingFace",
    }.get(provider, provider)
    st.markdown(f"**Active:** {provider_label}")


# ── Helper functions ───────────────────────────────────────────────────────────
def severity_color(severity: str) -> str:
    mapping = {
        "critical": "severity-critical",
        "high":     "severity-high",
        "medium":   "severity-medium",
        "low":      "severity-low",
    }
    return mapping.get((severity or "medium").lower(), "severity-medium")


def load_training_stats() -> list:
    path = _PROJECT_ROOT / "training" / "data" / "training_stats.jsonl"
    if not path.exists():
        return []
    stats = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    stats.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return stats


def get_example_counts() -> dict:
    counts = {}
    for agent in ("red", "blue"):
        path = _PROJECT_ROOT / "training" / "data" / f"{agent}_wins.jsonl"
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                counts[agent] = sum(1 for line in f if line.strip())
        else:
            counts[agent] = 0
    return counts


def get_adapter_status() -> dict:
    status = {}
    for agent in ("red", "blue"):
        adapter_path = _PROJECT_ROOT / "training" / "adapters" / f"{agent}_team"
        config_file = adapter_path / "adapter_config.json"
        status[agent] = config_file.exists()
    return status


def render_attack_chain(history: list):
    if not history:
        st.info("No simulations run yet. Use the Agent Interactions tab to run a simulation.")
        return

    for idx, sim in enumerate(reversed(history)):
        sim_num = len(history) - idx
        attack = sim.get("attack", {})
        defense = sim.get("defense", {})
        evaluation = sim.get("evaluation", {})

        with st.expander(
            f"Chain #{sim_num} — {attack.get('attack_type', 'unknown').replace('_', ' ').title()}  |  "
            f"Winner: {evaluation.get('winner', '?').upper()}  |  "
            f"Risk: {defense.get('risk_score', '?')}/10",
            expanded=(idx == 0),
        ):
            col1, col2, col3 = st.columns(3)
            with col1:
                st.markdown("#### 🔴 Red Team — Attack")
                st.markdown(f"**Type:** `{attack.get('attack_type', 'unknown')}`")
                st.markdown(f"**Technique:** {attack.get('technique', 'unknown')}")
                st.markdown(f"**Target:** {attack.get('target', 'unknown')}")
                sev = attack.get("severity", "medium")
                st.markdown(
                    f"**Severity:** <span class='{severity_color(sev)}'>{sev.upper()}</span>",
                    unsafe_allow_html=True,
                )
                mitre = attack.get("mitre_technique", "")
                if mitre and mitre != "unknown":
                    st.markdown(f"**MITRE:** `{mitre}`")
                st.markdown(f"**Latency:** {attack.get('latency', 0):.3f}s")
                st.code(attack.get("payload", ""), language="text")

            with col2:
                st.markdown("#### 🔵 Blue Team — Defense")
                detected = defense.get("threat_detected", False)
                st.markdown(f"**Threat Detected:** {'✅ Yes' if detected else '❌ No'}")
                st.markdown(f"**Category:** {defense.get('threat_category', 'unknown')}")
                risk = float(defense.get("risk_score") or 0)
                st.progress(min(risk / 10.0, 1.0), text=f"Risk Score: {risk}/10")
                blue_sev = defense.get("severity", "medium")
                st.markdown(
                    f"**Severity:** <span class='{severity_color(blue_sev)}'>{blue_sev.upper()}</span>  "
                    f"(confidence: {float(defense.get('confidence') or 0):.0%})",
                    unsafe_allow_html=True,
                )
                if defense.get("explanation"):
                    st.markdown(f"**Explanation:** {defense['explanation']}")
                if defense.get("recommended_fix"):
                    st.markdown(f"**Recommended Fix:** {defense['recommended_fix']}")
                st.markdown(f"**Mitigation:** {defense.get('mitigation', '')}")
                recs = defense.get("recommendations", [])
                if isinstance(recs, str):
                    recs = [r.strip() for r in recs.split(",") if r.strip()]
                if recs:
                    st.markdown("**Recommendations:**")
                    for r in recs:
                        st.markdown(f"- {r}")
                st.markdown(f"**Latency:** {defense.get('latency', 0):.3f}s")

            with col3:
                st.markdown("#### ⚖️ Judge — Evaluation")
                winner = evaluation.get("winner", "draw")
                winner_display = {
                    "red":  "🔴 Red Team Wins",
                    "blue": "🔵 Blue Team Wins",
                    "draw": "🤝 Draw",
                }.get(winner, winner)
                st.markdown(f"**Verdict:** {winner_display}")
                st.metric("Precision",       f"{evaluation.get('precision', 0):.2f}")
                st.metric("Recall",          f"{evaluation.get('recall', 0):.2f}")
                st.metric("Defense Quality", f"{evaluation.get('defense_quality', 0):.1f}/10")
                st.metric("Latency Rating",  f"{evaluation.get('response_latency_rating', 0):.1f}/10")

                remediation = sim.get("remediation", {})
                if remediation.get("attempted"):
                    verified = remediation.get("fix_verified")
                    st.markdown(
                        f"**Fix Verified:** {'✅ Yes' if verified else '❌ No'}  \n"
                        f"<span style='font-size:0.85em;color:var(--text-secondary,#888)'>{remediation.get('reason', '')}</span>",
                        unsafe_allow_html=True,
                    )
                st.markdown(f"**False Positives:** {evaluation.get('false_positives', 0)}")
                st.markdown(f"**Reasoning:** {evaluation.get('reasoning', '')}")

            st.markdown("---")
            st.markdown("**Full Attack Chain Flow:**")
            chain_cols = st.columns(5)
            steps = [
                ("1", "🔴 Attack Generated", attack.get("attack_type", "?"), "#ff4444"),
                ("2", "→", "", "#555"),
                ("3", "🔵 Defense Applied", defense.get("threat_category", "?"), "#4488ff"),
                ("4", "→", "", "#555"),
                ("5", "⚖️ Judged", winner_display, "#aa88ff"),
            ]
            for col, (_, label, detail, _color) in zip(chain_cols, steps):
                with col:
                    st.markdown(f"**{label}**")
                    if detail:
                        st.caption(detail)


# ── Page header ────────────────────────────────────────────────────────────────
st.markdown('<div class="main-header">🛡️ SentinelAI Quantum Dashboard</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-header">Advanced AI-Powered Red Team / Blue Team Security Simulation Platform</div>',
    unsafe_allow_html=True,
)

tab1, tab2, tab3, tab4 = st.tabs([
    "📁 Upload Suspicious Files",
    "🤖 Agent Interactions",
    "⛓️ Attack Chains",
    "🧠 Self-Training",
])

# ── Tab 1 — Upload Suspicious Files ───────────────────────────────────────────
with tab1:
    st.header("Upload Suspicious Files")
    st.markdown(
        "Upload a file to have the Red Team agent analyze its content and generate targeted attacks, "
        "exploits, or malicious payloads based on what it finds."
    )

    uploaded = st.file_uploader(
        "Drop a suspicious file here",
        type=["txt", "py", "js", "ts", "sh", "bat", "ps1", "json", "xml", "yaml",
              "yml", "ini", "cfg", "conf", "log", "csv", "html", "php", "rb", "go",
              "rs", "c", "cpp", "h", "java", "cs", "sql", "env", "dockerfile"],
        help="Supported: scripts, configs, logs, source code, and data files.",
    )

    if uploaded is not None:
        raw_bytes = uploaded.read()
        try:
            file_content = raw_bytes.decode("utf-8", errors="replace")
        except Exception:
            file_content = raw_bytes.decode("latin-1", errors="replace")

        st.session_state.uploaded_file_content = file_content
        st.session_state.uploaded_file_name = uploaded.name

        st.success(f"Loaded: **{uploaded.name}** ({len(raw_bytes):,} bytes)")

        with st.expander("Preview File Content", expanded=True):
            lang_map = {
                "py": "python", "js": "javascript", "ts": "typescript",
                "sh": "bash", "bat": "batch", "ps1": "powershell",
                "json": "json", "xml": "xml", "yaml": "yaml", "yml": "yaml",
                "sql": "sql", "html": "html", "php": "php", "rb": "ruby",
                "go": "go", "rs": "rust", "c": "c", "cpp": "cpp", "java": "java",
                "cs": "csharp",
            }
            ext = uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else "text"
            lang = lang_map.get(ext, "text")
            preview = file_content[:3000] + ("...[truncated]" if len(file_content) > 3000 else "")
            st.code(preview, language=lang)

        st.markdown("---")
        st.info(
            "Synthetic simulation mode has been removed. SentinelAI now runs only "
            "real live SQL-injection battles against the lab target — use "
            "`python -m training.battle_loop` to run them."
        )

    elif st.session_state.uploaded_file_content:
        st.info(
            f"Previously loaded file: **{st.session_state.uploaded_file_name}** is still in memory. "
            "Re-upload to replace it."
        )

# ── Tab 2 — Agent Interactions ─────────────────────────────────────────────────
with tab2:
    st.header("Agent Interactions")
    st.markdown(
        "Run Red Team vs Blue Team simulations and observe how each agent responds. "
        "You can run generic simulations or use an uploaded file as the attack target."
    )

    col_left, col_right = st.columns([1, 2])

    with col_left:
        st.subheader("Simulation Controls")
        st.info(
            "Synthetic simulation mode has been removed. SentinelAI now runs only "
            "real live SQL-injection battles against the lab target — use "
            "`python -m training.battle_loop` to run them."
        )

        st.markdown("---")
        st.subheader("History")
        total = len(st.session_state.simulation_history)
        st.metric("Total Simulations", total)

        if total > 0:
            winners   = [s.get("evaluation", {}).get("winner", "draw") for s in st.session_state.simulation_history]
            red_wins  = winners.count("red")
            blue_wins = winners.count("blue")
            draws     = winners.count("draw")
            st.metric("Red Wins",  red_wins)
            st.metric("Blue Wins", blue_wins)
            st.metric("Draws",     draws)

        if st.button("Clear History", use_container_width=True):
            st.session_state.simulation_history = []
            st.rerun()

    with col_right:
        st.subheader("Live Agent Outputs")

        if not st.session_state.simulation_history:
            st.info("Run a simulation on the left to see live agent outputs here.")
        else:
            latest     = st.session_state.simulation_history[-1]
            attack     = latest.get("attack", {})
            defense    = latest.get("defense", {})
            evaluation = latest.get("evaluation", {})

            st.markdown("##### Latest Simulation")

            with st.expander("🔴 Red Team Agent Output", expanded=True):
                col1, col2 = st.columns(2)
                col1.markdown(f"**Attack Type:** `{attack.get('attack_type', '?')}`")
                col1.markdown(f"**Technique:** {attack.get('technique', '?')}")
                col2.markdown(f"**Target:** {attack.get('target', '?')}")
                sev = attack.get("severity", "medium")
                col2.markdown(
                    f"**Severity:** <span class='{severity_color(sev)}'>{sev.upper()}</span>",
                    unsafe_allow_html=True,
                )
                mitre = attack.get("mitre_technique", "")
                if mitre and mitre != "unknown":
                    st.markdown(f"**MITRE ATT&CK:** `{mitre}`")
                st.markdown("**Payload:**")
                st.code(attack.get("payload", ""), language="text")
                st.caption(f"Latency: {attack.get('latency', 0):.3f}s")

            with st.expander("🔵 Blue Team Agent Output", expanded=True):
                detected = defense.get("threat_detected", False)
                col1, col2 = st.columns(2)
                col1.markdown(f"**Threat Detected:** {'✅ Yes' if detected else '❌ No'}")
                col1.markdown(f"**Category:** {defense.get('threat_category', '?')}")
                risk = float(defense.get("risk_score") or 0)
                col2.progress(min(risk / 10.0, 1.0), text=f"Risk Score: {risk}/10")
                blue_sev = defense.get("severity", "medium")
                col2.markdown(
                    f"**Severity:** <span class='{severity_color(blue_sev)}'>{blue_sev.upper()}</span>  "
                    f"(confidence: {float(defense.get('confidence') or 0):.0%})",
                    unsafe_allow_html=True,
                )
                if defense.get("explanation"):
                    st.markdown(f"**Explanation:** {defense['explanation']}")
                if defense.get("recommended_fix"):
                    st.markdown(f"**Recommended Fix:** {defense['recommended_fix']}")
                st.markdown(f"**Mitigation:** {defense.get('mitigation', '')}")
                recs = defense.get("recommendations", [])
                if recs:
                    for r in recs:
                        st.markdown(f"- {r}")
                st.caption(f"Latency: {defense.get('latency', 0):.3f}s")

            with st.expander("⚖️ Judge Agent Output", expanded=True):
                winner = evaluation.get("winner", "draw")
                badge  = {"red": "🔴 Red Team", "blue": "🔵 Blue Team", "draw": "🤝 Draw"}.get(winner, winner)
                st.markdown(f"**Winner:** {badge}")
                col1, col2, col3 = st.columns(3)
                col1.metric("Precision",        f"{evaluation.get('precision', 0):.2f}")
                col2.metric("Recall",           f"{evaluation.get('recall', 0):.2f}")
                col3.metric("Defense Quality",  f"{evaluation.get('defense_quality', 0):.1f}/10")
                col1.metric("Latency Rating",   f"{evaluation.get('response_latency_rating', 0):.1f}/10")
                col2.metric("False Positives",  evaluation.get("false_positives", 0))
                st.markdown(f"**Reasoning:** {evaluation.get('reasoning', '')}")
                st.caption(f"Judge latency: {evaluation.get('judge_latency', 0):.3f}s")

                remediation = latest.get("remediation", {})
                if remediation.get("attempted"):
                    verified = remediation.get("fix_verified")
                    st.markdown(f"**Fix Verified (Step 7):** {'✅ Yes' if verified else '❌ No'}")
                    st.caption(remediation.get("reason", ""))

            if len(st.session_state.simulation_history) > 1:
                st.markdown("---")
                with st.expander("All Simulation Results (JSON)", expanded=False):
                    st.json(st.session_state.simulation_history)

# ── Tab 3 — Attack Chains ──────────────────────────────────────────────────────
with tab3:
    st.header("Attack Chains")
    st.markdown(
        "Visualize the complete attack chain for every simulation — from red team attack generation "
        "through blue team defense to judge evaluation."
    )

    if st.session_state.simulation_history:
        col1, col2, col3, col4 = st.columns(4)
        total    = len(st.session_state.simulation_history)
        winners  = [s.get("evaluation", {}).get("winner", "draw") for s in st.session_state.simulation_history]
        avg_risk = sum(s.get("defense", {}).get("risk_score", 0) for s in st.session_state.simulation_history) / total
        avg_def  = sum(s.get("evaluation", {}).get("defense_quality", 0) for s in st.session_state.simulation_history) / total

        col1.metric("Simulations Run",  total)
        col2.metric("Avg Risk Score",   f"{avg_risk:.1f}/10")
        col3.metric("Avg Defense Quality", f"{avg_def:.1f}/10")
        col4.metric("Win Rate (Blue)",  f"{winners.count('blue') / total * 100:.0f}%")

        st.markdown("---")

        attack_type_counts: dict = {}
        for s in st.session_state.simulation_history:
            at = s.get("attack", {}).get("attack_type", "unknown")
            attack_type_counts[at] = attack_type_counts.get(at, 0) + 1

        if len(attack_type_counts) > 1:
            import pandas as pd
            df = pd.DataFrame(
                list(attack_type_counts.items()), columns=["Attack Type", "Count"]
            ).sort_values("Count", ascending=False)
            st.subheader("Attack Type Distribution")
            st.bar_chart(df.set_index("Attack Type"))

        st.subheader("Simulation Attack Chains")
        render_attack_chain(st.session_state.simulation_history)

        st.markdown("---")
        if st.button("Export All Chains (JSON)", use_container_width=False):
            export_data = json.dumps(st.session_state.simulation_history, indent=2, default=str)
            st.download_button(
                label="Download chains.json",
                data=export_data,
                file_name="attack_chains.json",
                mime="application/json",
            )
    else:
        st.info(
            "No attack chains yet. Run a simulation in the **Agent Interactions** tab "
            "or upload a file in the **Upload Suspicious Files** tab to get started."
        )

# ── Tab 4 — Self-Training ──────────────────────────────────────────────────────
with tab4:
    st.header("🧠 Self-Training")
    st.markdown(
        "Run battles using your own local GPU model, collect winning examples, "
        "and fine-tune the Red and Blue adapters — all from here."
    )

    if provider != "local":
        st.warning(
            "⚠️ Self-training requires the **local** provider. "
            "Switch to **local** in the sidebar to use your own model."
        )

    # ── Model Status ──────────────────────────────────────────────────────────
    st.subheader("Model Status")

    adapter_status = get_adapter_status()
    example_counts = get_example_counts()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Red Adapter",         "✅ Trained" if adapter_status["red"]  else "⬜ Not trained yet")
    col2.metric("Blue Adapter",        "✅ Trained" if adapter_status["blue"] else "⬜ Not trained yet")
    col3.metric("Red Winning Examples",  example_counts["red"])
    col4.metric("Blue Winning Examples", example_counts["blue"])

    base_model_display = os.environ.get("BASE_MODEL", "Qwen/Qwen2.5-3B-Instruct")
    st.caption(f"Base model: `{base_model_display}`  |  Adapters: `training/adapters/`")

    st.markdown("---")

    # ── Run Battles ───────────────────────────────────────────────────────────
    st.subheader("Run Training Battles")
    st.info(
        "Synthetic simulation mode has been removed. SentinelAI now runs only "
        "real live SQL-injection battles against the lab target — use "
        "`python -m training.battle_loop` to run them. This dashboard doesn't "
        "yet have a live-mode battle runner."
    )

    st.markdown("---")

    # ── Manual Training ───────────────────────────────────────────────────────
    st.subheader("Train Adapters Manually")
    st.markdown("Trigger fine-tuning on demand using all accumulated winning examples.")

    col_a, col_b = st.columns(2)

    with col_a:
        n_red = example_counts["red"]
        st.markdown(f"**🔴 Red Team** — {n_red} winning examples")
        if st.button("Train Red Team Adapter", use_container_width=True,
                     disabled=(n_red == 0 or provider != "local")):
            with st.spinner("Training Red Team... (this may take several minutes)"):
                try:
                    from training.train_agent import train
                    from training.dataset import get_data_path
                    train("red", get_data_path("red"))
                    st.success("✅ Red Team adapter saved.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Training failed: {e}")

    with col_b:
        n_blue = example_counts["blue"]
        st.markdown(f"**🔵 Blue Team** — {n_blue} winning examples")
        if st.button("Train Blue Team Adapter", use_container_width=True,
                     disabled=(n_blue == 0 or provider != "local")):
            with st.spinner("Training Blue Team... (this may take several minutes)"):
                try:
                    from training.train_agent import train
                    from training.dataset import get_data_path
                    train("blue", get_data_path("blue"))
                    st.success("✅ Blue Team adapter saved.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Training failed: {e}")

    st.markdown("---")

    # ── Training Stats Chart ──────────────────────────────────────────────────
    st.subheader("Training Progress Over Rounds")

    stats = load_training_stats()

    if not stats:
        st.info(
            "No training stats yet. Run battles above to start generating data. "
            "After each round completes, win rates will appear here."
        )
    else:
        import pandas as pd

        df = pd.DataFrame(stats)

        col1, col2, col3 = st.columns(3)
        col1.metric("Training Rounds Completed", len(df))
        col2.metric("Latest Red Win Rate",  f"{df['red_win_rate'].iloc[-1] * 100:.1f}%")
        col3.metric("Latest Blue Win Rate", f"{df['blue_win_rate'].iloc[-1] * 100:.1f}%")

        st.markdown("#### Win Rates Per Round")
        chart_df = df[["round", "red_win_rate", "blue_win_rate"]].set_index("round")
        chart_df.columns = ["Red Win Rate", "Blue Win Rate"]
        st.line_chart(chart_df)

        st.markdown("#### Battles Per Round")
        battles_df = df[["round", "red_wins", "blue_wins", "draws"]].set_index("round")
        st.bar_chart(battles_df)

        with st.expander("Raw Stats Table", expanded=False):
            display_df = df[["round", "red_wins", "blue_wins", "draws",
                             "total_battles", "red_win_rate", "blue_win_rate", "elapsed_seconds"]]
            st.dataframe(display_df, use_container_width=True)

        if st.button("Clear Training Stats", use_container_width=False):
            stats_path = _PROJECT_ROOT / "training" / "data" / "training_stats.jsonl"
            if stats_path.exists():
                stats_path.unlink()
            st.rerun()

    st.markdown("---")

    # ── Clear Training Data ───────────────────────────────────────────────────
    with st.expander("⚠️ Danger Zone — Reset Training Data"):
        st.warning(
            "These actions permanently delete training data and/or adapters. "
            "The base model is never affected."
        )
        col1, col2, col3 = st.columns(3)

        with col1:
            if st.button("🗑️ Clear Red Wins", use_container_width=True):
                p = _PROJECT_ROOT / "training" / "data" / "red_wins.jsonl"
                if p.exists():
                    p.unlink()
                st.session_state.training_battle_log = []
                st.rerun()

        with col2:
            if st.button("🗑️ Clear Blue Wins", use_container_width=True):
                p = _PROJECT_ROOT / "training" / "data" / "blue_wins.jsonl"
                if p.exists():
                    p.unlink()
                st.session_state.training_battle_log = []
                st.rerun()

        with col3:
            if st.button("🗑️ Delete All Adapters", use_container_width=True):
                import shutil
                for agent in ("red_team", "blue_team"):
                    p = _PROJECT_ROOT / "training" / "adapters" / agent
                    if p.exists():
                        shutil.rmtree(p)
                st.rerun()
