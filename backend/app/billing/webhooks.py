from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict
from app.billing.service import billing_service

if TYPE_CHECKING:
    from app.services.supabase_service import SupabaseService

logger = logging.getLogger("cybershield.billing.webhooks")


class BillingWebhookHandler:
    @staticmethod
    async def process_webhook(
        db_service: "SupabaseService",
        payload_bytes: bytes,
        signature: str,
        secret: str,
        event_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        is_valid = await billing_service.provider.verify_webhook_signature(
            payload_bytes, signature, secret
        )
        if not is_valid:
            raise ValueError("Invalid billing webhook signature")

        event_type = event_data.get("event")
        org_id = event_data.get("organization_id")
        plan_code = event_data.get("plan_code", "PROFESSIONAL")

        if event_type == "subscription.activated" and org_id:
            await billing_service.create_checkout(
                db_service=db_service,
                org_id=org_id,
                user_email="billing@customer.com",
                plan_code=plan_code,
            )
            return {"status": "processed", "event": event_type}

        elif event_type == "subscription.cancelled" and org_id:
            await billing_service.cancel_subscription(db_service, org_id)
            return {"status": "cancelled", "event": event_type}

        return {"status": "ignored", "event": event_type}
