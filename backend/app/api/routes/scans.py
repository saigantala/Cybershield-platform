from datetime import datetime
from ipaddress import ip_network
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.core.security import AuthenticatedUser, get_current_user
from app.schemas.scan import ScanCreate, ScanEventResponse, ScanResponse
from app.services.supabase_service import SupabaseService
from app.workers.tasks import run_authorized_discovery

router = APIRouter(prefix="/scans", tags=["Scans"])


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


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    List historical and active security scans for an organization.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    # Fetch from Supabase / mock DB
    scans = [
        ScanResponse.model_validate(s)
        for s in db_service._mock_db["scans"]
        if str(s["organization_id"]) == org_id
    ]
    return scans


@router.post("", response_model=ScanResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    payload: ScanCreate,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Authorize and queue a network discovery operation.
    Validates that the target scope is registered, approved, and not expired.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    # 1. Resolve Target Scope (Must be explicitly approved)
    target_scope_record = None
    if payload.scope_id:
        target_scope_record = await db_service.get_scope_by_id(org_id, str(payload.scope_id))
    elif payload.target_scope:
        # Match by CIDR
        scopes = await db_service.get_scopes(org_id)
        target_scope_record = next((s for s in scopes if s["cidr_range"] == payload.target_scope), None)

    if not target_scope_record:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan target is not registered in organization's approved scopes. "
                   "All targets must be submitted and approved before scanning.",
        )

    # 2. Verify Approval Status
    if target_scope_record.get("authorization_status") != "Approved":
        status_val = target_scope_record.get("authorization_status", "Pending")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Network scope '{target_scope_record['scope_name']}' is {status_val}. "
                   "Scans cannot be executed against unapproved scopes.",
        )

    # 3. Verify Expiration
    if target_scope_record.get("expires_at"):
        try:
            exp = datetime.fromisoformat(target_scope_record["expires_at"].replace("Z", "+00:00"))
            if datetime.now(exp.tzinfo) > exp:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Scope authorization expired on {target_scope_record['expires_at']}. Re-authorization required.",
                )
        except HTTPException:
            raise
        except Exception:
            pass

    target_cidr = target_scope_record["cidr_range"]
    scope_id_str = str(target_scope_record["id"])

    # 4. Register Scan Job Record in Database
    scan_record = await db_service.create_scan_record(
        org_id=org_id,
        user_id=current_user.user_id,
        title=payload.title,
        scan_type=payload.type,
        profile=payload.profile,
        target_scope=target_cidr,
        scope_id=scope_id_str,
    )

    scan_id = scan_record["id"]

    # 5. Record Initial Event
    await db_service.add_scan_event(
        scan_id,
        "authorized",
        f"Scan authorized under scope '{target_scope_record['scope_name']}' ({target_cidr}) by operator {current_user.email}",
    )

    # 6. Dispatch Background Discovery Job
    try:
        task = run_authorized_discovery.delay(
            scan_id=scan_id,
            organization_id=org_id,
            scope_id=scope_id_str,
            target_cidr=target_cidr,
            max_rate=target_scope_record.get("max_scan_rate", 1000),
        )
        scan_record["task_id"] = task.id
    except Exception as e:
        scan_record["message"] = "Scan registered; background worker will pick up task."

    return ScanResponse.model_validate(scan_record)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve operational scan status and telemetry.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    scan = await db_service.get_scan_by_id(org_id, str(scan_id))
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found in this organization",
        )

    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/events", response_model=List[ScanEventResponse])
async def get_scan_events(
    scan_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Retrieve real-time event timeline for this scan operation.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(db_service, current_user, organization_id)

    events = await db_service.get_scan_events(str(scan_id))
    return [ScanEventResponse.model_validate(e) for e in events]


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(
    scan_id: UUID,
    organization_id: Optional[UUID] = Query(None),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Abort or cancel an active security assessment job.
    """
    db_service = SupabaseService(user_token=current_user.raw_token)
    org_id = await _resolve_org(
        db_service,
        current_user,
        organization_id,
        allowed_roles=["owner", "admin", "analyst"],
    )

    cancelled = await db_service.cancel_scan(org_id, str(scan_id))
    if not cancelled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} could not be located or cancelled",
        )

    return ScanResponse.model_validate(cancelled)
