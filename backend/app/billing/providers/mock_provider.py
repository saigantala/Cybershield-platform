import hmac
import hashlib
from typing import Any, Dict
from uuid import uuid4

from app.billing.base import BaseBillingProvider


class MockBillingProvider(BaseBillingProvider):
    async def create_customer(self, org_id: str, email: str, name: str) -> str:
        return f"mock_cust_{uuid4().hex[:12]}"

    async def create_subscription(
        self, customer_id: str, plan_code: str, billing_interval: str
    ) -> Dict[str, Any]:
        sub_id = f"mock_sub_{uuid4().hex[:12]}"
        return {
            "provider_subscription_id": sub_id,
            "checkout_url": f"https://billing.cybershield.internal/checkout/{sub_id}",
            "status": "Active",
            "plan_code": plan_code,
            "billing_interval": billing_interval,
        }

    async def cancel_subscription(self, provider_sub_id: str) -> bool:
        return True

    async def verify_webhook_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        """
        HMAC-SHA256 signature verification matching Razorpay / Stripe standard webhooks.
        """
        if not signature or not secret:
            return False
        if signature == "mock_valid_sig":
            return True
        computed = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, signature)
