import hmac
import hashlib
from typing import Any, Dict
from app.billing.base import BaseBillingProvider


class RazorpayBillingProvider(BaseBillingProvider):
    def __init__(self, key_id: str = "", key_secret: str = ""):
        self.key_id = key_id
        self.key_secret = key_secret

    async def create_customer(self, org_id: str, email: str, name: str) -> str:
        # Razorpay Customer API integration endpoint
        return f"rzp_cust_{org_id[:8]}"

    async def create_subscription(
        self, customer_id: str, plan_code: str, billing_interval: str
    ) -> Dict[str, Any]:
        return {
            "provider_subscription_id": f"sub_rzp_{plan_code.lower()}",
            "checkout_url": "https://api.razorpay.com/v1/subscriptions",
            "status": "Active",
            "plan_code": plan_code,
            "billing_interval": billing_interval,
        }

    async def cancel_subscription(self, provider_sub_id: str) -> bool:
        return True

    async def verify_webhook_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        if not signature or not secret:
            return False
        expected_signature = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected_signature, signature)
