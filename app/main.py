"""
FastAPI Service wrapper for Dunex LLM Guardrails & Data Leakage Prevention.
Layered Clean Architecture with separated Controllers, Services, and Repositories.
"""

from __future__ import annotations

import os
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from dunex.config import GuardrailsConfig
from dunex.middleware import GuardrailsMiddleware
from app.api.controllers.guardrail_controller import (
    router as guardrail_router,
    get_guardrail_service,
)
from app.api.controllers.policy_controller import router as policy_router
from app.api.controllers.audit_controller import router as audit_router
from app.api.controllers.health_controller import router as health_router

# Initialize configuration
config = GuardrailsConfig.load()
guardrail_service = get_guardrail_service()

app = FastAPI(
    title="Dunex — LLM Guardrails & Data Leakage Prevention API",
    description="High-throughput middleware and service for PII masking, prompt-injection defense, and agent boundaries.",
    version=config.version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Transparent ASGI Guardrails middleware on protected routes
app.add_middleware(
    GuardrailsMiddleware,
    pipeline=guardrail_service.pipeline,
    protected_paths=["/v1/guardrails/chat/completions"],
)

# Mount Clean Layered Controllers
app.include_router(health_router)
app.include_router(guardrail_router)
app.include_router(policy_router)
app.include_router(audit_router)

# Static files setup
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    if (STATIC_DIR / "css").exists():
        app.mount("/css", StaticFiles(directory=str(STATIC_DIR / "css")), name="css")
    if (STATIC_DIR / "js").exists():
        app.mount("/js", StaticFiles(directory=str(STATIC_DIR / "js")), name="js")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    """Serve the interactive developer cockpit & documentation frontend."""
    index_path = STATIC_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path))
    return JSONResponse(
        content={
            "service": "Dunex LLM Guardrails",
            "version": config.version,
            "status": "online",
            "docs": "/docs",
        }
    )
