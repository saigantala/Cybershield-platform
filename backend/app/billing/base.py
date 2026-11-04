from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class BaseBillingProvider(ABC):
    @abstractmethod
    async def create_customer(self, org_id: str, email: str, name: str) -> str:
        """Create or get a customer record at the payment gateway."""
        pass

    @abstractmethod
    async def create_subscription(
        self, customer_id: str, plan_code: str, billing_interval: str
    ) -> Dict[str, Any]:
        """Create a subscription record and return checkout session details."""
        pass

    @abstractmethod
    async def cancel_subscription(self, provider_sub_id: str) -> bool:
        """Cancel an active subscription."""
        pass

    @abstractmethod
    async def verify_webhook_signature(
        self, payload: bytes, signature: str, secret: str
    ) -> bool:
        """Cryptographically verify webhook message integrity."""
        pass
