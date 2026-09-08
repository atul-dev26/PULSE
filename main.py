from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from common.database import engine, Base
from api.endpoints import router
from api.reports import router as reports_router
from api.exports import router as exports_router
from api.incidents import router as incidents_router
from auth.routes import router as auth_router
from auth.seed import seed_default_user
from correlation.models import IncidentRow  # noqa: F401 — registers table with Base
import os
import asyncio
from contextlib import asynccontextmanager
from ingestion.udp_server import start_udp_server

# Create DB tables
Base.metadata.create_all(bind=engine)
seed_default_user()

@asynccontextmanager
async def lifespan(app: FastAPI):
    port = int(os.environ.get("UDP_PORT", 5514))
    transport = None
    try:
        transport, _ = await start_udp_server("127.0.0.1", port)
    except OSError as e:
        print(f"Warning: UDP server failed to bind to {port}. {e}")
        
    yield
    
    if transport:
        transport.close()

app = FastAPI(title="ULPF - Universal Log Pre-Processing Framework", lifespan=lifespan)

# CORS â€” allow all origins for MVP demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(router)
app.include_router(reports_router)
app.include_router(exports_router)
app.include_router(incidents_router)

# Serve dynamic assets from static folder
app.mount("/assets", StaticFiles(directory="static"), name="assets")

# Serve dashboard static files
app.mount("/static", StaticFiles(directory="dashboard"), name="static")

@app.get("/login")
def serve_login():
    return FileResponse("dashboard/login.html")

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse("dashboard/index.html")

@app.get("/analytics")
def serve_analytics():
    return FileResponse("dashboard/analytics.html")


@app.get("/events")
def serve_events():
    return FileResponse("dashboard/events.html")


@app.get("/playground")
def serve_playground():
    return FileResponse("dashboard/playground.html")

@app.get("/audit-trail")
def serve_audit_trail():
    return FileResponse("dashboard/audit-trail.html")

@app.get("/onboarding")
def serve_onboarding():
    return FileResponse("dashboard/onboarding.html")

@app.get("/observability")
def serve_observability():
    return FileResponse("dashboard/observability.html")

@app.get("/merkle-batches")
def serve_merkle_batches():
    return FileResponse("dashboard/merkle-batches.html")


@app.get("/reports")
def serve_reports():
    return FileResponse("dashboard/reports.html")


@app.get("/settings")
def serve_settings():
    return FileResponse("dashboard/settings.html")

@app.get("/dlq")
def serve_dlq():
    return FileResponse("dashboard/dlq.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
