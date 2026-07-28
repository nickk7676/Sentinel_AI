from fastapi import APIRouter, HTTPException
from backend.services.simulation_service import run_simulation
from agents.safety.scope import ScopeViolationError
from agents.techniques import DEFAULT_TECHNIQUE_ID

router = APIRouter(prefix="/simulations", tags=["simulations"])

@router.post("/run")
def run(target_url: str = "http://localhost:5001", technique: str = DEFAULT_TECHNIQUE_ID):
    try:
        return run_simulation(target_url=target_url, technique=technique)
    except ScopeViolationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc