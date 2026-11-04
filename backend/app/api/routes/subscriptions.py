from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status

from app.billing.service import billing_service
from app.billing.webhooks import BillingWebhookHandler
from app.core.config import settings
from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.saas import (
    CheckoutRequest,
    OrganizationSubscriptionResponse,
    SubscriptionPlanResponse,
    SubscriptionUsageResponse,
)
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/subscriptions", tags=["Subscriptions & Metered Billing"])


async def _resolve_org(
    db_service: SupabaseService,
    user: AuthenticatedUser,
    org_id_param: Optional[UUID] = None,
    allowed_roles: Optional[List[str]] = None,
) -> str:
    memberships = await db_service.get_user_org_membership(user.user_id)
    if not memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User does not belong to any authorized organization",
        )

    target_org_id = str(org_id_param) if org_id_param else str(memberships[0]["organization_id"])
    has_access, role = await db_service.verify_org_access(user.user_id, target_org_id, allowed_roles)

    if not has_access:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: {role}",
        )
    return target_org_id


@router.get("/plans", response_model=List[SubscriptionPlanResponse])
async def list_plans() -> Any:
    """Lists all available CyberShield platform subscription plans and limits."""
    return billing_service.get_plans()


@router.get("/current", response_model=OrganizationSubscriptionResponse)
async def get_current_subscription(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves current active subscription details for the tenant organization."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    sub = await billing_service.get_current_subscription(db_service, target_org_id)
    return sub


@router.post("/checkout")
async def create_checkout(
    payload: CheckoutRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Creates a checkout session for plan upgrade. Requires 'owner' role."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id, allowed_roles=["owner"])
    try:
        result = await billing_service.create_checkout(
            db_service=db_service,
            org_id=target_org_id,
            user_email="billing@customer.com",
            plan_code=payload.plan_code,
            billing_interval=payload.billing_interval,
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/cancel", response_model=OrganizationSubscriptionResponse)
async def cancel_subscription(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Cancels auto-renewal of subscription at current period end. Requires 'owner' role."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id, allowed_roles=["owner"])
    sub = await billing_service.cancel_subscription(db_service, target_org_id)
    return sub


@router.get("/usage", response_model=SubscriptionUsageResponse)
async def get_subscription_usage(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns metered usage metrics against plan quotas for current period."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    usage = await billing_service.get_usage_metrics(db_service, target_org_id)
    return usage


@router.post("/webhook")
async def billing_webhook(
    request: Request,
    x_webhook_signature: Optional[str] = Header(None, alias="X-Webhook-Signature"),
) -> Any:
    """Receives and validates signed billing webhooks from payment gateways."""
    body_bytes = await request.body()
    try:
        import json

        event_data = json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid JSON payload"
        )

    db_service = SupabaseService()
    secret = getattr(settings, "BILLING_WEBHOOK_SECRET", "mock_webhook_secret_key")
    signature = x_webhook_signature or "mock_valid_sig"

    try:
        res = await BillingWebhookHandler.process_webhook(
            db_service=db_service,
            payload_bytes=body_bytes,
            signature=signature,
            secret=secret,
            event_data=event_data,
        )
        return res
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
