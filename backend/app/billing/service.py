from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import uuid4

from app.billing.base import BaseBillingProvider
from app.billing.plans import DEFAULT_PLANS
from app.billing.providers.mock_provider import MockBillingProvider
from app.billing.usage import QuotaEnforcementService

if TYPE_CHECKING:
    from app.services.supabase_service import SupabaseService


class BillingService:
    def __init__(self, provider: Optional[BaseBillingProvider] = None):
        self.provider = provider or MockBillingProvider()

    def get_plans(self) -> List[Dict[str, Any]]:
        return list(DEFAULT_PLANS.values())

    async def get_current_subscription(
        self, db_service: "SupabaseService", org_id: str
    ) -> Dict[str, Any]:
        sub = await db_service.get_organization_subscription(org_id)
        if not sub:
            # Seed default professional plan for organization
            now = datetime.utcnow()
            plan = DEFAULT_PLANS["PROFESSIONAL"]
            sub = {
                "id": str(uuid4()),
                "organization_id": org_id,
                "plan_id": plan["id"],
                "plan_name": plan["plan_name"],
                "plan_code": plan["plan_code"],
                "status": "Active",
                "billing_provider": "mock",
                "current_period_start": now.isoformat() + "Z",
                "current_period_end": (now + timedelta(days=30)).isoformat() + "Z",
                "cancel_at_period_end": False,
                "price": plan["price"],
            }
            await db_service.set_organization_subscription(org_id, sub)
        return sub

    async def create_checkout(
        self,
        db_service: SupabaseService,
        org_id: str,
        user_email: str,
        plan_code: str,
        billing_interval: str = "monthly",
    ) -> Dict[str, Any]:
        plan = DEFAULT_PLANS.get(plan_code.upper())
        if not plan:
            raise ValueError(f"Invalid plan code: {plan_code}")

        cust_id = await self.provider.create_customer(org_id, user_email, f"Org-{org_id[:6]}")
        sub_data = await self.provider.create_subscription(cust_id, plan_code, billing_interval)

        now = datetime.utcnow()
        new_sub = {
            "id": str(uuid4()),
            "organization_id": org_id,
            "plan_id": plan["id"],
            "plan_name": plan["plan_name"],
            "plan_code": plan["plan_code"],
            "status": "Active",
            "billing_provider": "mock",
            "current_period_start": now.isoformat() + "Z",
            "current_period_end": (now + timedelta(days=30)).isoformat() + "Z",
            "cancel_at_period_end": False,
            "price": plan["price"],
        }
        await db_service.set_organization_subscription(org_id, new_sub)

        return {
            "subscription": new_sub,
            "checkout_url": sub_data.get("checkout_url"),
        }

    async def cancel_subscription(
        self, db_service: SupabaseService, org_id: str
    ) -> Dict[str, Any]:
        sub = await self.get_current_subscription(db_service, org_id)
        sub["cancel_at_period_end"] = True
        await db_service.set_organization_subscription(org_id, sub)
        return sub

    async def get_usage_metrics(
        self, db_service: SupabaseService, org_id: str
    ) -> Dict[str, Any]:
        plan = await QuotaEnforcementService.get_org_plan(db_service, org_id)

        assets_res = await db_service.get_assets(org_id=org_id, page=1, page_size=1000)
        items = assets_res[0] if isinstance(assets_res, tuple) else assets_res.get("items", [])
        assets_used = len(items)

        members = await db_service.get_organization_members(org_id)
        members_used = len(members)

        scans_used = await db_service.get_monthly_scan_usage(org_id)
        usage_ai = await db_service.get_ai_usage_summary(org_id)
        ai_used = usage_ai.get("total_requests", 0)

        now = datetime.utcnow()
        return {
            "organization_id": org_id,
            "plan_code": plan["plan_code"],
            "assets_used": assets_used,
            "assets_limit": plan["max_assets"],
            "members_used": members_used,
            "members_limit": plan["max_members"],
            "monthly_scans_used": scans_used,
            "monthly_scans_limit": plan["monthly_scan_limit"],
            "ai_requests_used": ai_used,
            "ai_requests_limit": plan["ai_usage_limit"],
            "period_start": now.replace(day=1).strftime("%Y-%m-%d"),
            "period_end": (now.replace(day=1) + timedelta(days=30)).strftime("%Y-%m-%d"),
        }


billing_service = BillingService()
