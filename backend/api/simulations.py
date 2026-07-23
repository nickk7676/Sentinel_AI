from fastapi import APIRouter
from backend.services.simulation_service import run_simulation
from agents.techniques import DEFAULT_TECHNIQUE_ID

router = APIRouter(prefix="/simulations", tags=["simulations"])

@router.post("/run")
def run(target_url: str = "http://localhost:5001", technique: str = DEFAULT_TECHNIQUE_ID):
    return run_simulation(target_url=target_url, technique=technique)