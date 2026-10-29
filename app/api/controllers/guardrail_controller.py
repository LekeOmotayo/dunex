"""
FastAPI Router for Guardrail Inspection and LLM Proxy endpoints.
"""

from typing import List
from fastapi import APIRouter
from pydantic import BaseModel
from dunex.models import InspectionRequest, InspectionResult
from app.api.services.guardrail_service import GuardrailService

router = APIRouter(prefix="/v1/guardrails", tags=["Guardrail Inspection"])
_service = GuardrailService()


def get_guardrail_service() -> GuardrailService:
    return _service


@router.post(
    "/inspect-input",
    response_model=InspectionResult,
    summary="Inspect and sanitize inbound prompt",
)
async def inspect_input(req: InspectionRequest):
    return _service.inspect_inbound(req)


@router.post(
    "/inspect-output",
    response_model=InspectionResult,
    summary="Inspect and sanitize outbound LLM generation",
)
async def inspect_output(req: InspectionRequest):
    return _service.inspect_outbound(req)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str = "gpt-4o-mini"
    messages: List[ChatMessage]
    temperature: float = 0.7


@router.post(
    "/chat/completions",
    tags=["LLM Proxy"],
    summary="OpenAI-compatible protected chat completions endpoint",
)
async def protected_chat_completion(req: ChatCompletionRequest):
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
