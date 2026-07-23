from agents.red_team.agent import RedTeamAgent
from agents.blue_team.agent import BlueTeamAgent
from agents.judge.ground_truth import score_live_battle
from agents.techniques import DEFAULT_TECHNIQUE_ID, get_technique
from langgraph.graph import StateGraph, START, END
from typing import TypedDict, Optional


class BattleState(TypedDict):
    attack: dict
    defense: dict
    evaluation: dict
    target_url: Optional[str]
    technique: str
    log_offset: int
    normal_traffic_probability: Optional[float]


def run_simulation(
    target_url: str = None,
    technique: str = DEFAULT_TECHNIQUE_ID,
    normal_traffic_probability: float | None = None,
):
    """normal_traffic_probability: leave as None for the default random mix
    (Step 2.5). Pass 0.0/1.0 to force an attack-only or normal-only battle -
    used by the Step 4 eval harness for a deterministic held-out split."""
    tech = get_technique(technique)

    workflow = StateGraph(BattleState)

    red = RedTeamAgent()
    blue = BlueTeamAgent()

    def red_node(state: BattleState):
        print("  [Red]   Attacking live target...", flush=True)
        result = red.attack_live(
            state["target_url"],
            technique=state["technique"],
            normal_traffic_probability=state["normal_traffic_probability"],
        )
        mode = "attack" if result.get("was_attack", True) else "normal"
        print(f"  [Red]   mode={mode}  success={result.get('success')}  tool_calls={len(result.get('tool_calls', []))}  latency={result.get('latency')}s", flush=True)
        return {"attack": result}

    def blue_node(state: BattleState):
        print("  [Blue]  Reading real telemetry...", flush=True)
        log_text, _ = tech.fetch_telemetry(state["target_url"], state["log_offset"])
        result = blue.defend_live(log_text)
        result["_log_excerpt"] = log_text
        print(f"  [Blue]  detected={result.get('threat_detected')}  category={result.get('threat_category')}  latency={result.get('latency')}s", flush=True)
        return {"defense": result}

    def judge_node(state: BattleState):
        print("  [Judge] Scoring against ground truth...", flush=True)
        result = score_live_battle(state["attack"], state["defense"])
        print(f"  [Judge] attack_success={result.get('attack_success')}  detection_correct={result.get('detection_correct')}", flush=True)
        return {"evaluation": result}

    workflow.add_node("red_agent", red_node)
    workflow.add_node("blue_agent", blue_node)
    workflow.add_node("judge", judge_node)

    workflow.add_edge(START, "red_agent")
    workflow.add_edge("red_agent", "blue_agent")
    workflow.add_edge("blue_agent", "judge")
    workflow.add_edge("judge", END)

    graph = workflow.compile()

    # Record the target's current log position so blue only sees lines
    # produced by this battle's attack, not earlier battles' leftovers.
    _, log_offset = tech.fetch_telemetry(target_url, 0)

    return graph.invoke({
        "attack": {},
        "defense": {},
        "evaluation": {},
        "target_url": target_url,
        "technique": technique,
        "log_offset": log_offset,
        "normal_traffic_probability": normal_traffic_probability,
    })
