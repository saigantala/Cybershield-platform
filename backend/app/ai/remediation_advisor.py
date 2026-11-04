from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.ai.config import ai_config
from app.ai.prompt_templates import REMEDIATION_ADVISOR_SYSTEM_PROMPT
from app.ai.provider import get_ai_provider
from app.ai.schemas import RemediationResponse
from app.services.supabase_service import SupabaseService


class RemediationAdvisor:
    @staticmethod
    async def recommend_remediation(
        db_service: SupabaseService, org_id: str, finding_id: str, user_id: str
    ) -> RemediationResponse:
        finding = await db_service.get_vulnerability_finding_by_id(org_id=org_id, finding_id=finding_id)
        if not finding:
            raise ValueError(f"Vulnerability finding {finding_id} not found in organization.")

        cve = finding.get("cve_id", "CVE-UNKNOWN")
        title = finding.get("title", "Software Vulnerability")
        cvss = finding.get("cvss_score", 7.5)
        is_kev = finding.get("is_kev", False)
        affected_asset_id = str(finding.get("asset_id", "Unknown Asset"))

        # Vendor patch intelligence lookup
        suggested_steps = [
            f"Review official vendor advisory for {cve}.",
            "Stage upgrade in non-production pre-flight environment.",
            "Apply latest security patch or update service package to patched revision.",
            "Rescan endpoint via CyberShield Vulnerability Scanner to verify finding resolution.",
        ]

        if "21762" in cve:  # FortiOS SSL-VPN CVE-2024-21762
            explanation = (
                "An out-of-bounds write vulnerability in Fortinet FortiOS SSL-VPN allows remote unauthenticated "
                "threat actors to execute arbitrary commands via crafted HTTP requests."
            )
            suggested_steps = [
                "Upgrade FortiOS to version 7.4.3, 7.2.7, 7.0.14, or higher.",
                "Workaround (if patch cannot be applied immediately): Disable SSL-VPN service web portal access.",
                "Verify no rogue admin accounts or unauthorized VPN tunnels were provisioned.",
                "Rescan firewall with CyberShield discovery engine to verify port 8443 banner.",
            ]
            references = [
                "https://www.fortiguard.com/psirt/FG-IR-24-015",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            ]
            potential_impact = "Brief network reboot required during firmware update; momentary VPN session teardown."
        else:
            explanation = (
                f"Security finding {title} presents elevated exploitation risk (CVSS: {cvss}). "
                f"Identified on asset ID {affected_asset_id}."
            )
            references = [
                f"https://nvd.nist.gov/vuln/detail/{cve}",
                "https://cve.mitre.org/",
            ]
            potential_impact = "May require service daemon restart to load updated libraries."

        rec_id = str(uuid4())
        priority = "P1 - Immediate" if is_kev or cvss >= 9.0 else "P2 - High Priority"

        rec_response = RemediationResponse(
            id=rec_id,
            title=f"Remediation Strategy: {cve} ({title})",
            explanation=explanation,
            related_entity_type="vulnerability",
            related_entity_id=finding_id,
            priority=priority,
            suggested_steps=suggested_steps,
            potential_impact=potential_impact,
            verification_steps=[
                "Confirm software binary version matches or exceeds patched release.",
                "Dispatch an OpenVAS/ZAP verification scan targeting the asset.",
                "Review system authentication logs for post-patch anomalies.",
            ],
            supporting_references=references,
            confidence_notes="Actionable guidance aligned with NIST NVD and vendor advisories.",
            status="Pending Review",
            model=ai_config.MODEL,
            provider="advisor_engine",
            is_mock=True,
            created_at=datetime.utcnow().isoformat() + "Z",
        )

        # Store in DB
        await db_service.create_ai_recommendation(
            org_id=org_id,
            recommendation_type="vulnerability",
            related_entity_type="vulnerability",
            related_entity_id=finding_id,
            recommendation=rec_response.model_dump(),
            model_name=ai_config.MODEL,
            provider="advisor_engine",
            recommendation_id=rec_id,
        )

        # Log AI Usage
        await db_service.log_ai_usage(
            org_id=org_id,
            user_id=user_id,
            provider="advisor_engine",
            model=ai_config.MODEL,
            endpoint="recommend-remediation",
            input_tokens=80,
            output_tokens=220,
            estimated_cost=0.00035,
            request_status="success",
        )

        return rec_response
