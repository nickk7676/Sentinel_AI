from fastapi import APIRouter

router = APIRouter(prefix="/agents", tags = ["agents"])
@router.get("/")
def agents():
    return {
        "agents" : [
            {
                "name": "Red Team Agent",
                "role": "Attempt attacks and find weaknesses"
            },
            {
                "name": "Blue Team Agent",
                "role": "Defend against attacks"
            },
            {
                "name": "Judge Agent",
                "role": "Evaluates who performed better"
            },
            {
                "name": "Quantum Threat Agent",
                "role": "Analyzes quantum-based risks"
            },
            {
                "name": "Crypto Research Agent",
                "role": "Studies cryptogrpahy and post-quantum defenses"
            }
        ]
    }