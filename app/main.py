"""
FastAPI Service wrapper for Dunex LLM Guardrails & Data Leakage Prevention.
Serves REST inspection APIs, agent policy configuration, DynamoDB audit queries,
and an embedded interactive developer console.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from dunex import (
    AgentPolicy,
    AgentPolicyRegistry,
    AuditLogger,
    GuardrailPipeline,
    GuardrailsConfig,
    GuardrailsMiddleware,
    GuardrailVerdict,
    InspectionRequest,
    InspectionResult,
    MaskingStrategy,
)

# Initialize application
config = GuardrailsConfig.load()
pipeline = GuardrailPipeline(config=config)

app = FastAPI(
    title="Dunex — LLM Guardrails & Data Leakage Prevention API",
    description="High-throughput middleware and service for PII masking, prompt-injection defense, and agent boundaries.",
    version=config.version,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
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
    pipeline=pipeline,
    protected_paths=["/v1/guardrails/chat/completions"],
)

# Static files setup
STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


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


# ── Health & Telemetry ───────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health():
    """Liveness probe for container orchestrators and Render."""
    return {"status": "ok", "service": config.service_name, "version": config.version}


@app.get("/ready", tags=["Health"])
async def readiness():
    """Readiness probe."""
    return {"status": "ready"}


# ── Guardrail Inspection APIs ────────────────────────────────────────────────

@app.post(
    "/v1/guardrails/inspect-input",
    response_model=InspectionResult,
    tags=["Guardrail Inspection"],
    summary="Inspect and sanitize inbound prompt",
)
async def inspect_input(req: InspectionRequest):
    """
    Inspect inbound prompt text for PII data leakage, prompt injections, toxicity,
    and agent permission boundaries.
    """
    result = pipeline.inspect(
        text=req.text,
        agent_id=req.agent_id,
        tenant_id=req.tenant_id,
        direction="input",
        metadata=req.metadata,
    )
    return result


@app.post(
    "/v1/guardrails/inspect-output",
    response_model=InspectionResult,
    tags=["Guardrail Inspection"],
    summary="Inspect and sanitize outbound LLM generation",
)
async def inspect_output(req: InspectionRequest):
    """
    Inspect outbound LLM response text for PII leakage, confidential API keys,
    credit cards, and harmful output vectors before sending to user.
    """
    result = pipeline.inspect(
        text=req.text,
        agent_id=req.agent_id,
        tenant_id=req.tenant_id,
        direction="output",
        metadata=req.metadata,
    )
    return result


# ── Sample Protected LLM Proxy Endpoint ──────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: List[ChatMessage]
    temperature: float = 0.7


@app.post(
    "/v1/guardrails/chat/completions",
    tags=["LLM Proxy"],
    summary="OpenAI-compatible protected chat completions endpoint",
)
async def protected_chat_completion(req: ChatCompletionRequest):
    """
    Simulated OpenAI-compatible endpoint automatically protected by GuardrailsMiddleware.
    Inbound messages have PII masked and prompt injections blocked.
    """
    last_user_msg = req.messages[-1].content if req.messages else ""
    return {
        "id": "chatcmpl-dunex-sample",
        "object": "chat.completion",
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"[Simulated LLM Response] Safe response to clean prompt: '{last_user_msg[:60]}...'",
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": len(last_user_msg.split()),
            "completion_tokens": 15,
            "total_tokens": len(last_user_msg.split()) + 15,
        },
    }


# ── Agent Policy Configuration APIs ──────────────────────────────────────────

@app.get(
    "/v1/agents",
    response_model=List[AgentPolicy],
    tags=["Agent Permissions"],
    summary="List all registered agent permission policies",
)
async def list_agent_policies():
    """Retrieve all active per-agent security boundary policies."""
    return pipeline.policies.list_policies()


@app.get(
    "/v1/agents/{agent_id}/policy",
    response_model=AgentPolicy,
    tags=["Agent Permissions"],
    summary="Get policy for a specific agent",
)
async def get_agent_policy(agent_id: str):
    """Retrieve security boundaries, topic rules, and PII masking strategy for an agent."""
    return pipeline.policies.get(agent_id)


@app.put(
    "/v1/agents/{agent_id}/policy",
    response_model=AgentPolicy,
    tags=["Agent Permissions"],
    summary="Create or update policy for an agent",
)
async def update_agent_policy(agent_id: str, policy: AgentPolicy):
    """Register or update an agent's permission boundaries and sensitivity levels."""
    policy.agent_id = agent_id
    pipeline.policies.register(policy)
    return policy


# ── Audit Trail & Telemetry APIs ─────────────────────────────────────────────

@app.get(
    "/v1/audit/logs",
    tags=["Audit & Compliance"],
    summary="Query immutable DynamoDB-formatted audit records",
)
async def query_audit_logs(
    limit: int = 50,
    agent_id: Optional[str] = None,
    verdict: Optional[GuardrailVerdict] = None,
):
    """Query recent audit records structured in single-table DynamoDB format."""
    items = pipeline.audit.get_recent(limit=limit, agent_id=agent_id, verdict=verdict)
    return [item.model_dump() for item in items]


@app.get(
    "/v1/audit/summary",
    tags=["Audit & Compliance"],
    summary="Get aggregate telemetry and compliance summary",
)
async def get_audit_summary():
    """Retrieve real-time metrics on total inspections, block rates, and PII incidents."""
    return pipeline.audit.get_summary()
