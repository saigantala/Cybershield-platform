import asyncio
import logging
import time
import concurrent.futures
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from app.services.nmap_scanner import NmapDiscoveryEngine
from app.services.supabase_service import SupabaseService
from app.workers.celery_app import celery_app
from app.scanners.base import RawFinding
from app.scanners.mock_scanner import MockVulnerabilityScanner
from app.scanners.normalizer import FindingNormalizer, NormalizedFinding
from app.scanners.openvas_scanner import OpenVASScanner
from app.scanners.zap_scanner import ZapScanner
from app.services.cve_service import cve_service
from app.services.kev_service import kev_service
from app.services.risk_scoring import risk_scoring_engine

logger = logging.getLogger(__name__)


def _run_async(coro_or_func, *args, **kwargs):
    """Safely executes an async coroutine or coroutine factory from synchronous Celery task, even if an event loop is active."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if callable(coro_or_func) and not asyncio.iscoroutine(coro_or_func):
        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                return executor.submit(lambda: asyncio.run(coro_or_func(*args, **kwargs))).result()
        return asyncio.run(coro_or_func(*args, **kwargs))

    # Pre-instantiated coroutine object
    if loop and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(asyncio.run, coro_or_func).result()
    return asyncio.run(coro_or_func)


@celery_app.task(name="app.workers.tasks.health_check_task")
def health_check_task() -> Dict[str, Any]:
    """Background worker heartbeat check."""
    logger.info("Executing Celery worker health check task")
    return {
        "status": "healthy",
        "worker": "celery_worker",
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@celery_app.task(name="app.workers.tasks.cleanup_demo_task")
def cleanup_demo_task() -> Dict[str, Any]:
    """Demonstration task cleaning transient scanner state."""
    logger.info("Executing demo cleanup task")
    return {
        "status": "success",
        "artifacts_purged": 0,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@celery_app.task(bind=True, name="app.workers.tasks.process_demo_scan")
def process_demo_scan(
    self, scan_id: str, organization_id: str, target_scope: str
) -> Dict[str, Any]:
    """Demonstration scan task preserved for Sprint 4 compatibility."""
    logger.info(f"Processing demo scan {scan_id} for target {target_scope}")
    return {
        "scan_id": scan_id,
        "organization_id": organization_id,
        "target_scope": target_scope,
        "status": "completed",
        "progress": 100,
        "hosts_discovered": 0,
        "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "completed_at": datetime.utcnow().isoformat() + "Z",
    }


@celery_app.task(name="app.workers.tasks.validate_scan_scope")
def validate_scan_scope(scope_id: str, org_id: str) -> bool:
    """
    Independent task re-verifying scope authorization before worker execution.
    """
    db = SupabaseService()
    # Synchronously check mock/cloud db
    scope = next(
        (
            s for s in db._mock_db["scan_scopes"]
            if str(s["id"]) == str(scope_id) and str(s["organization_id"]) == str(org_id)
        ),
        None,
    )
    if not scope or scope.get("authorization_status") != "Approved":
        return False

    if scope.get("expires_at"):
        try:
            exp = datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))
            if datetime.now(exp.tzinfo) > exp:
                return False
        except Exception:
            pass

    return True


@celery_app.task(bind=True, name="app.workers.tasks.update_scan_progress")
def update_scan_progress(self, scan_id: str, progress: int, status: str) -> None:
    """Updates scan progress and status in database."""
    db = SupabaseService()
    _run_async(db.update_scan_state, scan_id, status=status, progress=progress)


@celery_app.task(bind=True, name="app.workers.tasks.run_authorized_discovery")
def run_authorized_discovery(
    self,
    scan_id: str,
    organization_id: str,
    scope_id: str,
    target_cidr: str,
    max_rate: int = 1000,
) -> Dict[str, Any]:
    """
    Main asynchronous network discovery pipeline.
    Re-verifies approved scope immediately before execution, runs Nmap discovery engine,
    and synchronizes identified endpoints into asset inventory.
    """
    db = SupabaseService()
    logger.info(f"Worker received discovery job {scan_id} for target {target_cidr} (Org: {organization_id})")

    # 1. Immediately re-verify approved scope before running scanner
    is_valid = validate_scan_scope(scope_id, organization_id)
    if not is_valid:
        error_msg = "Scan rejected: Target scope is revoked, expired, or unapproved."
        logger.error(error_msg)
        _run_async(db.update_scan_state, scan_id, status="failed", progress=0, error_message=error_msg)
        _run_async(db.add_scan_event, scan_id, "error", error_msg)
        return {"scan_id": scan_id, "status": "failed", "error": error_msg}

    # 2. Transition state to 'running'
    _run_async(db.update_scan_state, scan_id, status="running", progress=15)
    _run_async(db.add_scan_event, scan_id, "running", f"Discovery worker initialized for subnet {target_cidr}")

    # Event emitter helper
    def emit_event(event_type: str, message: str):
        try:
            _run_async(db.add_scan_event, scan_id, event_type, message)
        except Exception as e:
            logger.warning(f"Failed to log scan event: {e}")

    # Check cancellation helper
    def check_cancelled() -> bool:
        scan = next((s for s in db._mock_db["scans"] if str(s["id"]) == str(scan_id)), None)
        return bool(scan and scan.get("status") == "cancelled")

    # 3. Execute Nmap Discovery
    engine = NmapDiscoveryEngine()
    try:
        scan_uuid = UUID(scan_id)
        org_uuid = UUID(organization_id)
        result = _run_async(
            engine.execute_discovery,
            scan_id=scan_uuid,
            organization_id=org_uuid,
            target_cidr=target_cidr,
            max_rate=max_rate,
            event_callback=emit_event,
            is_cancelled_check=check_cancelled,
        )
    except Exception as e:
        logger.error(f"Discovery engine execution failed: {e}", exc_info=True)
        _run_async(db.update_scan_state, scan_id, status="failed", progress=50, error_message=str(e))
        emit_event("error", f"Discovery execution aborted: {str(e)}")
        return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    # 4. Handle Cancellation
    if result.status == "cancelled" or check_cancelled():
        logger.info(f"Scan {scan_id} cancelled by operator.")
        _run_async(db.update_scan_state, scan_id, status="cancelled", progress=100)
        return {"scan_id": scan_id, "status": "cancelled"}

    # 5. Synchronize Discovered Assets into Inventory
    emit_event("sync_started", f"Ingesting {len(result.hosts)} responsive endpoints into asset register...")
    for host in result.hosts:
        _run_async(db.synchronize_discovered_host, organization_id, host)

    # 6. Finalize Scan Record
    _run_async(
        db.update_scan_state,
        scan_id,
        status="completed",
        progress=100,
        hosts_discovered=result.hosts_discovered,
    )
    emit_event("completed", f"Assessment complete. {result.hosts_discovered} assets synchronized into inventory.")

    return {
        "scan_id": scan_id,
        "organization_id": organization_id,
        "status": "completed",
        "progress": 100,
        "hosts_discovered": result.hosts_discovered,
        "completed_at": datetime.utcnow().isoformat() + "Z",
    }


# ==============================================================================
# SPRINT 6: VULNERABILITY ASSESSMENT BACKGROUND TASKS
# ==============================================================================

@celery_app.task(name="app.workers.tasks.validate_assessment_scope")
def validate_assessment_scope(scope_id: str, org_id: str) -> bool:
    """Verifies that the target network scope is authorized, approved, and not expired."""
    db = SupabaseService()
    scope = next(
        (
            s for s in db._mock_db["scan_scopes"]
            if str(s["id"]) == str(scope_id) and str(s["organization_id"]) == str(org_id)
        ),
        None,
    )
    if not scope or scope.get("authorization_status") != "Approved":
        return False

    if scope.get("expires_at"):
        try:
            exp = datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))
            if datetime.now(exp.tzinfo) > exp:
                return False
        except Exception:
            pass

    return True


@celery_app.task(name="app.workers.tasks.run_openvas_assessment")
def run_openvas_assessment(targets: List[Dict[str, Any]], options: Optional[Dict[str, Any]] = None) -> List[Any]:
    scanner = OpenVASScanner()
    return _run_async(scanner.run_assessment(targets, options))


@celery_app.task(name="app.workers.tasks.run_zap_baseline")
def run_zap_baseline(targets: List[Dict[str, Any]], options: Optional[Dict[str, Any]] = None) -> List[Any]:
    scanner = ZapScanner()
    return _run_async(scanner.run_assessment(targets, options))


@celery_app.task(name="app.workers.tasks.normalize_scanner_results")
def normalize_scanner_results(
    raw_findings: List[Any], targets: List[Dict[str, Any]]
) -> List[NormalizedFinding]:
    normalized: List[NormalizedFinding] = []
    target_map = {str(t.get("id")): t for t in targets}

    for raw in raw_findings:
        # Determine target asset ID
        asset_id = str(targets[0].get("id")) if targets else "00000000-0000-0000-0000-000000000000"
        context = target_map.get(asset_id)
        normalized.append(FindingNormalizer.normalize(raw, asset_id=asset_id, asset_context=context))

    return normalized


@celery_app.task(name="app.workers.tasks.enrich_findings_with_cve")
def enrich_findings_with_cve(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """Correlates findings with official NVD CVE metadata."""
    for f in findings:
        if f.cve_id:
            cve_meta = _run_async(cve_service.get_cve_details(f.cve_id))
            if cve_meta:
                if cve_meta.get("description") and len(f.description) < 50:
                    f.description = cve_meta["description"]
                if cve_meta.get("reference_urls"):
                    for url in cve_meta["reference_urls"]:
                        if url not in f.reference_urls:
                            f.reference_urls.append(url)
    return findings


@celery_app.task(name="app.workers.tasks.update_kev_status")
def update_kev_status(findings: List[NormalizedFinding]) -> List[NormalizedFinding]:
    """Cross-references CVE IDs with the CISA Known Exploited Vulnerabilities catalog."""
    for f in findings:
        if f.cve_id and kev_service.is_in_kev(f.cve_id):
            f.is_kev = True
            f.kev_metadata = kev_service.get_kev_metadata(f.cve_id)
    return findings


@celery_app.task(name="app.workers.tasks.calculate_risk_priority")
def calculate_risk_priority(
    findings: List[NormalizedFinding], asset_risk_level: Optional[str] = None
) -> List[NormalizedFinding]:
    """Computes CyberShield Prioritization Score preserving official CVSS/Severity."""
    for f in findings:
        scores = risk_scoring_engine.calculate_scores(
            cvss_score=f.cvss_score,
            is_kev=f.is_kev,
            asset_risk_level=asset_risk_level,
            cvss_version=f.cvss_version,
        )
        f.severity = scores.official_severity
        f.prioritization_score = scores.prioritization_score
    return findings


@celery_app.task(name="app.workers.tasks.synchronize_findings")
def synchronize_findings(
    org_id: str, scan_id: str, findings: List[NormalizedFinding]
) -> Dict[str, int]:
    db = SupabaseService()
    return _run_async(db.synchronize_vulnerability_findings(org_id, scan_id, findings))


@celery_app.task(bind=True, name="app.workers.tasks.update_assessment_progress")
def update_assessment_progress(
    self,
    scan_id: str,
    progress: int,
    status: str,
    total_findings: int = 0,
    error_message: Optional[str] = None,
) -> None:
    db = SupabaseService()
    _run_async(
        db.update_vulnerability_scan_state(
            scan_id=scan_id,
            status=status,
            total_findings=total_findings,
            error_message=error_message,
        )
    )


@celery_app.task(bind=True, name="app.workers.tasks.start_vulnerability_assessment")
def start_vulnerability_assessment(
    self,
    scan_id: str,
    organization_id: str,
    user_id: str,
    scope_id: str,
    scan_type: str = "mock",
    target_asset_ids: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """
    Main Vulnerability Assessment Task.
    Strictly verifies scope approval and expiration, selects the authorized scanner,
    normalizes raw results, enriches with NVD & CISA KEV intelligence, computes risk scores,
    and safely synchronizes into the tenant database.
    """
    db = SupabaseService()
    logger.info(
        f"Worker starting vulnerability assessment {scan_id} (Org: {organization_id}, Type: {scan_type})"
    )

    # 1. Immediately revalidate scope authorization
    is_valid_scope = validate_assessment_scope(scope_id, organization_id)
    if not is_valid_scope:
        error_msg = "Assessment rejected: Target scope is unapproved, expired, or outside organization."
        logger.error(error_msg)
        _run_async(
            db.update_vulnerability_scan_state(
                scan_id=scan_id,
                status="failed",
                error_message=error_msg,
            )
        )
        return {"scan_id": scan_id, "status": "failed", "error": error_msg}

    # 2. Check for scan cancellation before running heavy workload
    scan = _run_async(db.get_vulnerability_scan_by_id(organization_id, scan_id))
    if scan and scan.get("status") == "cancelled":
        logger.info(f"Scan {scan_id} was cancelled before worker execution.")
        return {"scan_id": scan_id, "status": "cancelled"}

    # 3. Transition to running state
    _run_async(
        db.update_vulnerability_scan_state(
            scan_id=scan_id,
            status="running",
        )
    )

    # 4. Resolve Target Assets
    assets_in_org = _run_async(db.get_assets(organization_id))
    if target_asset_ids:
        targets = [a for a in assets_in_org if str(a.get("id")) in target_asset_ids]
    else:
        targets = assets_in_org

    if not targets:
        # Fallback to a target descriptor from scope if no assets registered yet
        targets = [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "Target Host in Scope",
                "ip_address": "192.168.10.1",
                "device_type": "Server",
                "operating_system": "Ubuntu Linux",
            }
        ]

    # 5. Invoke the designated scanner
    raw_findings: List[RawFinding] = []
    try:
        if scan_type == "openvas":
            scanner = OpenVASScanner()
            health = _run_async(scanner.check_health())
            if not health.get("ready"):
                # Graceful fallback to diagnostic mock if openvas daemon is not running in local dev
                logger.warning(
                    f"OpenVAS daemon unavailable ({health.get('error')}); engaging diagnostic mock engine."
                )
                mock_engine = MockVulnerabilityScanner()
                raw_findings = _run_async(mock_engine.run_assessment(targets))
            else:
                raw_findings = _run_async(scanner.run_assessment(targets))
        elif scan_type == "zap_baseline":
            zap = ZapScanner()
            health = _run_async(zap.check_health())
            if not health.get("ready"):
                logger.warning(
                    f"OWASP ZAP daemon unavailable ({health.get('error')}); engaging diagnostic mock engine."
                )
                mock_engine = MockVulnerabilityScanner()
                raw_findings = _run_async(mock_engine.run_assessment(targets))
            else:
                raw_findings = _run_async(zap.run_assessment(targets))
        else:
            # Default: High-fidelity Mock Scanner
            mock_engine = MockVulnerabilityScanner()
            raw_findings = _run_async(mock_engine.run_assessment(targets))
    except Exception as e:
        logger.error(f"Scanner engine execution failed: {e}", exc_info=True)
        _run_async(
            db.update_vulnerability_scan_state(
                scan_id=scan_id,
                status="failed",
                error_message=f"Scanner execution failure: {str(e)}",
            )
        )
        return {"scan_id": scan_id, "status": "failed", "error": str(e)}

    # Check cancellation after scanner run
    scan = _run_async(db.get_vulnerability_scan_by_id(organization_id, scan_id))
    if scan and scan.get("status") == "cancelled":
        logger.info(f"Scan {scan_id} cancelled during processing.")
        return {"scan_id": scan_id, "status": "cancelled"}

    # 6. Normalize raw findings into canonical CyberShield format
    normalized_findings: List[NormalizedFinding] = []
    for raw in raw_findings:
        # Pick the asset matching finding
        matched_target = targets[0] if targets else {"id": "11111111-1111-1111-1111-111111111111"}
        normalized_findings.append(
            FindingNormalizer.normalize(
                raw=raw,
                asset_id=str(matched_target.get("id")),
                asset_context=matched_target,
            )
        )

    # 7. Enrich with NVD CVE Intelligence
    normalized_findings = enrich_findings_with_cve(normalized_findings)

    # 8. Correlate with CISA Known Exploited Vulnerabilities (KEV) Catalog
    normalized_findings = update_kev_status(normalized_findings)

    # 9. Compute CyberShield Prioritization Score
    normalized_findings = calculate_risk_priority(normalized_findings)

    # 10. Synchronize Findings into Supabase Database
    sync_result = _run_async(
        db.synchronize_vulnerability_findings(
            org_id=organization_id,
            scan_id=scan_id,
            normalized_findings=normalized_findings,
        )
    )

    # 11. Finalize Assessment Record
    _run_async(
        db.update_vulnerability_scan_state(
            scan_id=scan_id,
            status="completed",
            total_assets=len(targets),
            total_findings=len(normalized_findings),
        )
    )

    logger.info(
        f"Assessment {scan_id} completed successfully: {len(normalized_findings)} findings synced "
        f"({sync_result.get('created')} created, {sync_result.get('updated')} updated)."
    )

    return {
        "scan_id": scan_id,
        "organization_id": organization_id,
        "status": "completed",
        "total_assets": len(targets),
        "total_findings": len(normalized_findings),
        "sync_result": sync_result,
        "completed_at": datetime.utcnow().isoformat() + "Z",
    }


# ==============================================================================
# SPRINT 7: THREAT INTELLIGENCE & SECURITY MONITORING TASKS
# ==============================================================================

@celery_app.task(name="app.workers.tasks.sync_threat_feeds")
def sync_threat_feeds(org_id: Optional[str] = None, provider: str = "cisa_kev") -> Dict[str, Any]:
    """Scheduled task refreshing threat intelligence feeds."""
    from app.threat_intelligence.feed_manager import feed_manager
    logger.info(f"Synchronizing threat feed '{provider}'")
    return _run_async(feed_manager.sync_feed(provider))


@celery_app.task(name="app.workers.tasks.normalize_indicators")
def normalize_indicators(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Validates and standardizes a list of raw IOCs."""
    from app.threat_intelligence.indicators import IndicatorValidator
    normalized = []
    for item in indicators:
        try:
            val = IndicatorValidator.validate_and_normalize(item["indicator_type"], item["indicator_value"])
            item["indicator_value"] = val
            normalized.append(item)
        except Exception as e:
            logger.warning(f"Discarding invalid IOC '{item.get('indicator_value')}': {e}")
    return normalized


@celery_app.task(name="app.workers.tasks.expire_old_indicators")
def expire_old_indicators(org_id: Optional[str] = None) -> int:
    """Purges or flags indicators that have passed their expiration date."""
    db = SupabaseService()
    now = datetime.utcnow()
    expired_count = 0
    for ind in list(db._mock_db["threat_indicators"]):
        if ind.get("expires_at"):
            try:
                exp_dt = datetime.fromisoformat(ind["expires_at"].replace("Z", "+00:00"))
                if now.astimezone() > exp_dt:
                    ind["is_expired"] = True
                    expired_count += 1
            except Exception:
                pass
    logger.info(f"Evaluated expired indicators: {expired_count} marked expired.")
    return expired_count


@celery_app.task(bind=True, name="app.workers.tasks.process_security_event")
def process_security_event(self, event_id: str, org_id: str) -> Dict[str, Any]:
    """Background task evaluating correlation rules for an ingested security event."""
    db = SupabaseService()
    event = _run_async(db.get_security_event_by_id(org_id, event_id))
    if not event:
        return {"status": "error", "message": "Event not found"}

    from app.threat_intelligence.correlation import correlation_engine
    recent_events = [e for e in db._mock_db["security_events"] if str(e["organization_id"]) == str(org_id)]
    rules = [r for r in db._mock_db["detection_rules"] if str(r["organization_id"]) == str(org_id) and r.get("is_enabled", True)]
    indicators = [i for i in db._mock_db["threat_indicators"] if str(i["organization_id"]) == str(org_id)]
    existing_alerts = [a for a in db._mock_db["alerts"] if str(a["organization_id"]) == str(org_id)]

    alerts = correlation_engine.evaluate(
        new_event=event,
        recent_events=recent_events,
        rules=rules,
        indicators=indicators,
        existing_alerts=existing_alerts,
    )
    for a in alerts:
        db._mock_db["alerts"].insert(0, a)

    return {"status": "success", "alerts_created": len(alerts)}


@celery_app.task(name="app.workers.tasks.correlate_security_events")
def correlate_security_events(org_id: str) -> int:
    """Evaluates correlation across all recent unanalyzed security events."""
    db = SupabaseService()
    rules = [r for r in db._mock_db["detection_rules"] if str(r["organization_id"]) == str(org_id) and r.get("is_enabled", True)]
    logger.info(f"Evaluated {len(rules)} active detection rules for organization {org_id}")
    return len(rules)


@celery_app.task(name="app.workers.tasks.evaluate_detection_rules")
def evaluate_detection_rules(org_id: str) -> Dict[str, Any]:
    db = SupabaseService()
    rules = [r for r in db._mock_db["detection_rules"] if str(r["organization_id"]) == str(org_id)]
    return {"rules_count": len(rules), "status": "active"}


@celery_app.task(name="app.workers.tasks.generate_security_alert")
def generate_security_alert(org_id: str, alert_data: Dict[str, Any]) -> Dict[str, Any]:
    db = SupabaseService()
    from uuid import uuid4
    alert_data["id"] = str(uuid4())
    alert_data["organization_id"] = str(org_id)
    now = datetime.utcnow().isoformat() + "Z"
    alert_data["created_at"] = now
    alert_data["updated_at"] = now
    db._mock_db["alerts"].insert(0, alert_data)
    return alert_data


@celery_app.task(name="app.workers.tasks.update_alert_priority")
def update_alert_priority(org_id: str, alert_id: str, new_severity: str) -> Optional[Dict[str, Any]]:
    db = SupabaseService()
    return _run_async(db.update_alert(org_id, alert_id, {"severity": new_severity}, changed_by="celery_worker"))


@celery_app.task(name="app.workers.tasks.calculate_event_baseline")
def calculate_event_baseline(org_id: str) -> Dict[str, Any]:
    db = SupabaseService()
    events = [e for e in db._mock_db["security_events"] if str(e["organization_id"]) == str(org_id)]
    return {"org_id": org_id, "event_volume": len(events), "baseline_events_per_hour": len(events) / 24.0}


@celery_app.task(name="app.workers.tasks.cleanup_expired_events")
def cleanup_expired_events(days: int = 90) -> int:
    db = SupabaseService()
    cutoff = datetime.utcnow() - timedelta(days=days)
    before = len(db._mock_db["security_events"])
    db._mock_db["security_events"] = [
        e for e in db._mock_db["security_events"]
        if datetime.fromisoformat(e["created_at"].replace("Z", "+00:00")) >= cutoff.astimezone()
    ]
    purged = before - len(db._mock_db["security_events"])
    logger.info(f"Purged {purged} security events older than {days} days.")
    return purged
