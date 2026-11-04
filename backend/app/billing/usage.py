from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, Tuple
from app.billing.plans import DEFAULT_PLANS

if TYPE_CHECKING:
    from app.services.supabase_service import SupabaseService

logger = logging.getLogger("cybershield.billing.usage")


class QuotaEnforcementService:
    @staticmethod
    async def get_org_plan(db_service: "SupabaseService", org_id: str) -> Dict[str, Any]:
        sub = await db_service.get_organization_subscription(org_id)
        if sub and sub.get("plan_code") in DEFAULT_PLANS:
            return DEFAULT_PLANS[sub["plan_code"]]
        return DEFAULT_PLANS["PROFESSIONAL"]  # default active plan for primary demo org

    @staticmethod
    async def check_quota(
        db_service: SupabaseService, org_id: str, quota_type: str
    ) -> Tuple[bool, int, int, str]:
        """
        Validates if organization is entitled to perform action under active plan.
        Returns: (is_allowed, current_count, limit, explanation_message)
        """
        plan = await QuotaEnforcementService.get_org_plan(db_service, org_id)

        if quota_type == "assets":
            assets_res = await db_service.get_assets(org_id=org_id, page=1, page_size=1000)
            items = assets_res[0] if isinstance(assets_res, tuple) else assets_res.get("items", [])
            current = len(items)
            limit = plan["max_assets"]
            if current >= limit:
                return (
                    False,
                    current,
                    limit,
                    f"Asset limit reached ({current}/{limit}). Upgrade to {plan['plan_name']} or Enterprise to monitor additional devices.",
                )
            return True, current, limit, ""

        elif quota_type == "members":
            members = await db_service.get_organization_members(org_id)
            current = len(members)
            limit = plan["max_members"]
            if current >= limit:
                return (
                    False,
                    current,
                    limit,
                    f"Team member seat limit reached ({current}/{limit}). Upgrade your subscription to invite additional analysts.",
                )
            return True, current, limit, ""

        elif quota_type == "monthly_scans":
            scans_count = await db_service.get_monthly_scan_usage(org_id)
            limit = plan["monthly_scan_limit"]
            if scans_count >= limit:
                return (
                    False,
                    scans_count,
                    limit,
                    f"Monthly scan quota exhausted ({scans_count}/{limit}). Quota resets next billing cycle or upon plan upgrade.",
                )
            return True, scans_count, limit, ""

        elif quota_type == "ai_requests":
            usage_summary = await db_service.get_ai_usage_summary(org_id)
            current = usage_summary.get("total_requests", 0)
            limit = plan["ai_usage_limit"]
            if current >= limit:
                return (
                    False,
                    current,
                    limit,
                    f"AI SOC consultation quota reached ({current}/{limit} requests). Upgrade to unlock additional AI bandwidth.",
                )
            return True, current, limit, ""

        return True, 0, 999999, ""
