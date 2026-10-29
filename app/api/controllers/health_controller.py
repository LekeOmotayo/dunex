"""
FastAPI Router for Health & Liveness probes.
"""

from fastapi import APIRouter
from dunex.config import GuardrailsConfig

router = APIRouter(tags=["Health"])
config = GuardrailsConfig.load()


@router.get("/health", summary="Liveness probe")
async def health():
    return {"status": "ok", "service": config.service_name, "version": config.version}


@router.get("/ready", summary="Readiness probe")
async def readiness():
    return {"status": "ready"}
