import logging
from uuid import uuid4
from typing import Any, Dict, List, Optional

from app.ai.config import ai_config
from app.ai.guardrails import AIGuardrails
from app.ai.prompt_templates import SOC_ASSISTANT_SYSTEM_PROMPT
from app.ai.provider import get_ai_provider
from app.ai.context_retrieval import ContextRetrievalEngine
from app.ai.schemas import AIChatResponse, SourceReference
from app.services.supabase_service import SupabaseService

logger = logging.getLogger("cybershield.ai.assistant")


class AIAssistant:
    @staticmethod
    async def chat(
        db_service: SupabaseService,
        org_id: str,
        user_id: str,
        message: str,
        conversation_id: Optional[str] = None,
    ) -> AIChatResponse:
        # 1. Guardrail Validation
        sanitized_msg, is_safe, refusal_reason = AIGuardrails.sanitize_user_input(message)
        if not is_safe:
            # Safe refusal response without executing external inference
            msg_id = str(uuid4())
            conv_id = conversation_id or str(uuid4())
            return AIChatResponse(
                conversation_id=conv_id,
                message_id=msg_id,
                response=refusal_reason,
                source_references=[],
                model=ai_config.MODEL,
                provider="guardrail_filter",
                is_mock=True,
                input_tokens=AIGuardrails.estimate_tokens(message),
                output_tokens=AIGuardrails.estimate_tokens(refusal_reason),
                created_at="just now",
            )

        # 2. Context Retrieval (Multi-tenant isolated)
        context_str, source_refs = await ContextRetrievalEngine.retrieve_context_for_query(
            db_service=db_service, org_id=org_id, query=sanitized_msg
        )

        # 3. Construct System Prompt with Grounded Context
        augmented_system_prompt = (
            f"{SOC_ASSISTANT_SYSTEM_PROMPT}\n\n"
            f"=== TENANT SECURITY TELEMETRY (AUTHORIZED READ-ONLY CONTEXT) ===\n"
            f"{context_str}\n"
            f"================================================================="
        )

        # 4. Invoke Provider
        provider = get_ai_provider()
        res = await provider.generate_response(
            system_prompt=augmented_system_prompt,
            user_prompt=sanitized_msg,
        )

        content = AIGuardrails.filter_output_safety(res["content"])
        in_tokens = res.get("input_tokens", 0)
        out_tokens = res.get("output_tokens", 0)

        # 5. Persist Conversation & Messages
        conv_id = conversation_id
        if not conv_id:
            title_candidate = sanitized_msg[:40] + ("..." if len(sanitized_msg) > 40 else "")
            conv_record = await db_service.create_ai_conversation(
                org_id=org_id, user_id=user_id, title=title_candidate
            )
            conv_id = conv_record["id"]

        # Save user message
        await db_service.add_ai_message(
            conversation_id=conv_id,
            role="user",
            content=sanitized_msg,
            source_references=[],
        )

        # Save assistant message
        msg_record = await db_service.add_ai_message(
            conversation_id=conv_id,
            role="assistant",
            content=content,
            source_references=[r.model_dump() for r in source_refs],
        )

        # 6. Usage Audit Logging
        cost_est = (in_tokens / 1000.0) * ai_config.INPUT_COST_PER_1K + (out_tokens / 1000.0) * ai_config.OUTPUT_COST_PER_1K
        await db_service.log_ai_usage(
            org_id=org_id,
            user_id=user_id,
            provider=res.get("provider", "mock"),
            model=res.get("model", ai_config.MODEL),
            endpoint="chat",
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            estimated_cost=round(cost_est, 6),
            request_status="success",
        )

        return AIChatResponse(
            conversation_id=conv_id,
            message_id=msg_record["id"],
            response=content,
            source_references=source_refs,
            model=res.get("model", ai_config.MODEL),
            provider=res.get("provider", "mock"),
            is_mock=res.get("is_mock", True),
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            created_at=msg_record.get("created_at", ""),
        )
