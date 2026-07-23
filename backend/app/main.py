from fastapi import FastAPI
from backend.api import health, simulations, agents, quantum, reports

app = FastAPI(title="Sentinel AI Backend")

app.include_router(health.router)
app.include_router(simulations.router)
app.include_router(agents.router)
#app.include_router(quantum.router)
#app.include_router(reports.router)