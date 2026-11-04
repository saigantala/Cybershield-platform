from fastapi import APIRouter
from app.api.routes.health import router as health_router
from app.api.routes.auth import router as auth_router
from app.api.routes.assets import router as assets_router
from app.api.routes.scans import router as scans_router
from app.api.routes.scopes import router as scopes_router
from app.api.routes.vulnerabilities import router as vulnerabilities_router
from app.api.routes.threat_intelligence import router as threat_intelligence_router
from app.api.routes.security_events import router as security_events_router
from app.api.routes.alerts import router as alerts_router
from app.api.routes.detection_rules import router as detection_rules_router
from app.api.routes.incidents import router as incidents_router
from app.api.routes.attack import router as attack_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.playbooks import router as playbooks_router
from app.api.routes.response_requests import router as response_requests_router
from app.api.routes.ai import router as ai_router
from app.api.routes.analytics import router as analytics_router
from app.api.routes.organizations import router as organizations_router
from app.api.routes.team import router as team_router
from app.api.routes.subscriptions import router as subscriptions_router
from app.api.routes.api_keys import router as api_keys_router
from app.api.routes.platform_admin import router as platform_admin_router
from app.api.routes.compliance import router as compliance_router
from app.api.routes.reports import router as reports_router
from app.api.routes.monitoring import router as monitoring_router
from app.api.routes.network import router as network_router
from app.api.routes.soar import router as soar_router
from app.api.routes.ai_detection import router as ai_detection_router
from app.api.routes.integrations import router as integrations_router
from app.api.routes.system_health import router as system_health_router
from app.api.routes.threat_hunting import router as threat_hunting_router
from app.api.routes.forensics import router as forensics_router
from app.api.routes.identity import router as identity_router
from app.api.routes.security_assurance import router as security_assurance_router
from app.api.routes.release_readiness import router as release_readiness_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(scopes_router)
api_router.include_router(assets_router)
api_router.include_router(scans_router)
api_router.include_router(vulnerabilities_router)
api_router.include_router(threat_intelligence_router)
api_router.include_router(security_events_router)
api_router.include_router(alerts_router)
api_router.include_router(detection_rules_router)
api_router.include_router(incidents_router)
api_router.include_router(attack_router)
api_router.include_router(evidence_router)
api_router.include_router(playbooks_router)
api_router.include_router(response_requests_router)
api_router.include_router(ai_router)
api_router.include_router(analytics_router)
api_router.include_router(organizations_router)
api_router.include_router(team_router)
api_router.include_router(subscriptions_router)
api_router.include_router(api_keys_router)
api_router.include_router(platform_admin_router)
api_router.include_router(compliance_router)
api_router.include_router(reports_router)
api_router.include_router(monitoring_router)
api_router.include_router(network_router)
api_router.include_router(soar_router)
api_router.include_router(ai_detection_router)
api_router.include_router(integrations_router)
api_router.include_router(system_health_router)
api_router.include_router(threat_hunting_router)
api_router.include_router(forensics_router)
api_router.include_router(identity_router)
api_router.include_router(security_assurance_router)
api_router.include_router(release_readiness_router)
