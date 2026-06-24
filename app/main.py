"""
SecOps AI Assistant — Main Application

FastAPI application entry point.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import close_db, get_db
from app.routes import alerts, investigations, samples

# Configure logging
logging.basicConfig(
    level=getattr(logging, get_settings().app_log_level),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events (startup/shutdown)."""
    # Startup
    logger.info("Starting SecOps AI Assistant...")
    settings = get_settings()
    
    if settings.is_demo_mode:
        logger.warning(
            "NO LLM API KEYS CONFIGURED. Running in DEMO MODE. "
            "Pre-computed results will be returned."
        )
    else:
        logger.info(
            f"Active LLM Provider: {settings.active_provider.value.upper()} "
            f"({settings.openai_model if settings.active_provider.value == 'openai' else settings.google_model})"
        )
        if settings.fallback_provider:
            logger.info(f"Fallback LLM Provider available: {settings.fallback_provider.value.upper()}")
            
    # Initialize DB
    await get_db()
    
    yield
    
    # Shutdown
    logger.info("Shutting down...")
    await close_db()


# Initialize FastAPI app
app = FastAPI(
    title="SecOps AI Assistant",
    description="AI-powered assistant for Security Operations analysts",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(alerts.router)
app.include_router(investigations.router)
app.include_router(samples.router)

# Mount static files for the dashboard
static_dir = settings.project_root / "app" / "static"
static_dir.mkdir(parents=True, exist_ok=True)
app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")

# Connection manager for WebSocket updates
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass


manager = ConnectionManager()

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time dashboard updates."""
    await manager.connect(websocket)
    try:
        while True:
            # We don't expect messages from the client in this prototype,
            # but we need to keep the connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
