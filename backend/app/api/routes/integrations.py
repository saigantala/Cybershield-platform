from typing import Any, Dict, List, Optional
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.integrations import (
    IntegrationCreate,
    IntegrationResponse,
    IntegrationUpdate,
    IntegrationTestRequest,
    IntegrationTestResponse,
    IntegrationSyncRequest,
    IntegrationSyncResponse,
    IntegrationDeliveryLogResponse,
    IntegrationHealthSummaryResponse,
    WebhookEndpointCreate,
    WebhookEndpointResponse,
    WebhookEndpointUpdate,
    WebhookSecretRotateResponse,
    WebhookDeliveryAttemptResponse,
    WebhookReplayResponse,
)
from app.services.integrations_service import integrations_service
from app.services.supabase_service import SupabaseService

router = APIRouter(prefix="/integrations", tags=["Enterprise Integrations & External Security Ecosystem"])


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


# ------------------------------------------------------------------------------
# 1. INTEGRATIONS CATALOG & CONFIGURATION
# ------------------------------------------------------------------------------
@router.get("", response_model=List[IntegrationResponse])
async def list_integrations(
    category: Optional[str] = Query(None, description="Filter by category (siem, communication, threat_intelligence, cloud_security)"),
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists configured connectors, SIEM forwarders, and communication integrations."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await integrations_service.list_integrations(db_service, target_org_id, category)


@router.post("", response_model=IntegrationResponse, status_code=status.HTTP_201_CREATED)
async def create_integration(
    req: IntegrationCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Configures a new external enterprise integration."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        return await integrations_service.create_integration(db_service, target_org_id, req, user.user_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/logs", response_model=List[IntegrationDeliveryLogResponse])
async def list_delivery_logs(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists delivery attempts, HTTP response codes, and export logs across all integrations."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await integrations_service.list_delivery_logs(db_service, target_org_id)


@router.get("/health", response_model=IntegrationHealthSummaryResponse)
async def get_health_summary(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Returns connectivity health metrics, sync velocity, and 24h delivery success rates."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await integrations_service.get_health_summary(db_service, target_org_id)


# ------------------------------------------------------------------------------
# 2. WEBHOOK ENDPOINTS
# ------------------------------------------------------------------------------
@router.get("/webhooks", response_model=List[WebhookEndpointResponse])
async def list_webhooks(
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists outgoing webhook endpoints and event subscriptions."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await integrations_service.list_webhooks(db_service, target_org_id)


@router.post("/webhooks", response_model=WebhookEndpointResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    req: WebhookEndpointCreate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Registers an outgoing webhook with SSRF validation and generates an HMAC secret."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        return await integrations_service.create_webhook(db_service, target_org_id, req)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.patch("/webhooks/{hook_id}", response_model=WebhookEndpointResponse)
async def update_webhook(
    hook_id: UUID,
    req: WebhookEndpointUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates webhook target URL, subscribed events, retry limits, or active state."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        updated = await integrations_service.update_webhook(db_service, target_org_id, str(hook_id), req)
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/webhooks/{hook_id}/rotate-secret", response_model=WebhookSecretRotateResponse)
async def rotate_webhook_secret(
    hook_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Rotates the HMAC signing secret for a webhook (revealed once in the response)."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        return await integrations_service.rotate_webhook_secret(db_service, target_org_id, str(hook_id))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/webhooks/{hook_id}/deliveries", response_model=List[WebhookDeliveryAttemptResponse])
async def list_webhook_deliveries(
    hook_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Lists historical payload delivery attempts, response codes, and errors for a webhook."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    return await integrations_service.list_webhook_deliveries(db_service, target_org_id, str(hook_id))


@router.post("/webhooks/{hook_id}/deliveries/{delivery_id}/replay", response_model=WebhookReplayResponse)
async def replay_webhook_delivery(
    hook_id: UUID,
    delivery_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Replays an eligible failed or historical webhook delivery with idempotency."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await integrations_service.replay_webhook_delivery(
            db_service, target_org_id, str(hook_id), str(delivery_id)
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


# ------------------------------------------------------------------------------
# 3. INDIVIDUAL INTEGRATION DETAIL & ACTIONS
# ------------------------------------------------------------------------------
@router.get("/{integration_id}", response_model=IntegrationResponse)
async def get_integration(
    integration_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Retrieves full specification and non-sensitive configuration for an integration."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(db_service, user, org_id)
    item = await integrations_service.get_integration(db_service, target_org_id, str(integration_id))
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
    return item


@router.patch("/{integration_id}", response_model=IntegrationResponse)
async def update_integration(
    integration_id: UUID,
    req: IntegrationUpdate,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Updates configuration, credentials, or enabled state of an integration."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    try:
        updated = await integrations_service.update_integration(
            db_service, target_org_id, str(integration_id), req
        )
        if not updated:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")
        return updated
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete("/{integration_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_integration(
    integration_id: UUID,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> None:
    """Disconnects and removes an integration configuration."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin"]
    )
    deleted = await integrations_service.delete_integration(db_service, target_org_id, str(integration_id))
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")


@router.post("/{integration_id}/test", response_model=IntegrationTestResponse)
async def test_integration(
    integration_id: UUID,
    req: IntegrationTestRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Performs a live connectivity and authentication probe against the integration destination."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await integrations_service.test_connection(db_service, target_org_id, str(integration_id), req)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/{integration_id}/sync", response_model=IntegrationSyncResponse)
async def sync_integration(
    integration_id: UUID,
    req: IntegrationSyncRequest,
    org_id: Optional[UUID] = Query(None, description="Organization ID"),
    user: AuthenticatedUser = Depends(get_current_user),
) -> Any:
    """Triggers an immediate synchronization run of events, indicators, or telemetry."""
    db_service = SupabaseService(user_token=user.token)
    target_org_id = await _resolve_org(
        db_service, user, org_id, allowed_roles=["owner", "admin", "analyst"]
    )
    try:
        return await integrations_service.sync_integration(db_service, target_org_id, str(integration_id), req)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
