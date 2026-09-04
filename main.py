from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from common.database import engine, Base
from api.endpoints import router
import os
import asyncio
from contextlib import asynccontextmanager
from ingestion.udp_server import start_udp_server

# Create DB tables
Base.metadata.create_all(bind=engine)

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

# CORS — allow all origins for MVP demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

# Serve dashboard static files
app.mount("/static", StaticFiles(directory="dashboard"), name="static")

@app.get("/dashboard")
def serve_dashboard():
    return FileResponse("dashboard/index.html")

@app.get("/playground")
def serve_playground():
    return FileResponse("dashboard/playground.html")

@app.get("/audit-trail")
def serve_audit_trail():
    return FileResponse("dashboard/audit-trail.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
