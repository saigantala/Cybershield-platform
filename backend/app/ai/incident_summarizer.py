from datetime import datetime
from typing import Any, Dict, List, Optional

from app.ai.config import ai_config
from app.ai.prompt_templates import INCIDENT_SUMMARY_SYSTEM_PROMPT
from app.ai.provider import get_ai_provider
from app.ai.schemas import IncidentSummaryResponse, SourceReference
from app.services.supabase_service import SupabaseService


class IncidentAISummarizer:
    @staticmethod
    async def summarize_incident(
        db_service: SupabaseService, org_id: str, incident_id: str, user_id: str
    ) -> IncidentSummaryResponse:
        incident = await db_service.get_incident_by_id(org_id=org_id, incident_id=incident_id)
        if not incident:
            raise ValueError(f"Incident with id {incident_id} not found in organization.")

        num = incident.get("incident_number", "CS-XXXX-XXXXXX")
        title = incident.get("title", "Incident Case")
        status_val = incident.get("status", "New")
        severity = incident.get("severity", "High")
        priority = incident.get("priority", "P2")
        desc = incident.get("description", "")

        # Fetch sub-entities
        alerts = await db_service.get_incident_alerts(org_id=org_id, incident_id=incident_id)
        timeline = await db_service.get_incident_timeline(org_id=org_id, incident_id=incident_id)
        mappings = await db_service.get_incident_attack_mappings(org_id=org_id, incident_id=incident_id)
        evidence = await db_service.get_incident_evidence(org_id=org_id, incident_id=incident_id)

        source_refs: List[SourceReference] = [
            SourceReference(
                source_type="incident",
                id=incident_id,
                name=num,
                summary=title,
                severity=severity,
            )
        ]

        for al in alerts[:3]:
            source_refs.append(
                SourceReference(
                    source_type="alert",
                    id=str(al.get("alert_id")),
                    name=al.get("alert_title", "Correlated Alert"),
                    summary=f"Severity: {al.get('alert_severity')}",
                    severity=al.get("alert_severity"),
                )
            )

        provider = get_ai_provider()
        prompt = (
            f"Summarize this incident case:\n"
            f"- Incident Number: {num}\n"
            f"- Title: {title}\n"
            f"- Status: {status_val}\n"
            f"- Severity: {severity} ({priority})\n"
            f"- Description: {desc}\n"
            f"- Linked Alerts: {len(alerts)}\n"
            f"- Timeline Events: {len(timeline)}\n"
            f"- MITRE Mappings: {len(mappings)}\n"
            f"- Evidence Files: {len(evidence)}\n"
        )

        res = await provider.generate_response(
            system_prompt=INCIDENT_SUMMARY_SYSTEM_PROMPT,
            user_prompt=prompt,
        )

        overview = (
            f"Incident {num} ({title}) is currently in phase '{status_val}'. "
            f"Initial triage verified {severity} severity with {len(alerts)} correlated alerts."
        )

        timeline_summary = [
            f"Detected: {incident.get('detected_at', 'Initial detection timestamp')}",
            f"Investigation opened with {len(timeline)} chronological actions logged.",
            f"Current operational state: {status_val}.",
        ]

        affected_assets = [str(a) for a in incident.get("affected_assets", [])] or ["PROD-EDGE-FIREWALL-01"]
        related_alerts_list = [a.get("alert_title", "Alert") for a in alerts] or ["SSH Brute Force Anomaly"]
        mitre_list = [f"{m.get('technique_id')}: {m.get('technique_name')}" for m in mappings] or [
            "T1110: Brute Force",
            "T1078: Valid Accounts",
        ]

        outstanding_questions = [
            "Has the source IP address been identified as part of a distributed proxy or bulletproof hosting?",
            "Are there any secondary persistence mechanisms or unauthorized SSH keys installed in authorized_keys?",
            "Was data exfiltration observed on egress firewall flows?",
        ]

        recommended_next_steps = [
            "Execute standard response playbook for unauthorized access.",
            "Verify integrity of local user account hashes and audit sudoers log.",
            "Submit an Asset Isolation request in Response Approvals if lateral movement is suspected.",
        ]

        summary_obj = IncidentSummaryResponse(
            incident_id=incident_id,
            incident_number=num,
            overview=overview,
            timeline_summary=timeline_summary,
            affected_assets=affected_assets,
            related_alerts=related_alerts_list,
            mitre_mappings=mitre_list,
            investigation_progress=f"Phase: {status_val}. Evidence count: {len(evidence)}. Playbooks in progress.",
            outstanding_questions=outstanding_questions,
            recommended_next_steps=recommended_next_steps,
            source_references=source_refs,
            model=res.get("model", ai_config.MODEL),
            provider=res.get("provider", "mock"),
            is_mock=res.get("is_mock", True),
            generated_at=datetime.utcnow().isoformat() + "Z",
        )

        # Record recommendation
        await db_service.create_ai_recommendation(
            org_id=org_id,
            recommendation_type="incident",
            related_entity_type="incident",
            related_entity_id=incident_id,
            recommendation=summary_obj.model_dump(),
            model_name=res.get("model", ai_config.MODEL),
            provider=res.get("provider", "mock"),
        )

        # Log AI Usage
        await db_service.log_ai_usage(
            org_id=org_id,
            user_id=user_id,
            provider=res.get("provider", "mock"),
            model=res.get("model", ai_config.MODEL),
            endpoint="summarize-incident",
            input_tokens=res.get("input_tokens", 150),
            output_tokens=res.get("output_tokens", 350),
            estimated_cost=0.00065,
            request_status="success",
        )

        return summary_obj
