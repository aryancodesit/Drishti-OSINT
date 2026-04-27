import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src'))

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from engine.orchestrator import Orchestrator
from plugins.crtsh_plugin import CrtshPlugin
from plugins.shodan_plugin import ShodanPlugin
from plugins.dorking_plugin import DorkingPlugin

app = FastAPI(title="Drishti OSINT API")

# Mount frontend directory for static assets (CSS, JS)
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serves the main index.html file."""
    with open("frontend/index.html", "r", encoding="utf-8") as f:
        return f.read()

class ScanRequest(BaseModel):
    target: str
    target_type: str # "domain" or "ip"
    plugins: list[str] # ["shodan", "crtsh", "dork"]

@app.post("/api/scan")
async def run_scan(request: ScanRequest):
    """Executes the OSINT scan based on the requested target and plugins."""
    plugins_to_run = []
    
    if request.target_type == "domain":
        if "crtsh" in request.plugins:
            plugins_to_run.append("crtsh")
        if "dork" in request.plugins:
            plugins_to_run.append("dork")
        if "shodan" in request.plugins or "censys" in request.plugins or "zoomeye" in request.plugins:
            plugins_to_run.append("infrastructure")
    else: # ip
        if "shodan" in request.plugins or "censys" in request.plugins or "zoomeye" in request.plugins:
            plugins_to_run.append("infrastructure")

    # Remove duplicates
    plugins_to_run = list(set(plugins_to_run))

    if not plugins_to_run:
        raise HTTPException(status_code=400, detail="No valid plugins selected for this target type.")

    orchestrator = Orchestrator(request.target, plugins_to_run)
    try:
        results = await orchestrator.run_all()
        return {"status": "success", "data": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
