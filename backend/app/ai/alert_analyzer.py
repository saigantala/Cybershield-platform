from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.ai.config import ai_config
from app.ai.prompt_templates import ALERT_ANALYSIS_SYSTEM_PROMPT
from app.ai.provider import get_ai_provider
from app.ai.schemas import AlertAnalysisResponse, SourceReference
from app.services.supabase_service import SupabaseService


class AlertAIAnalyzer:
    @staticmethod
    async def analyze_alert(
        db_service: SupabaseService, org_id: str, alert_id: str, user_id: str
    ) -> AlertAnalysisResponse:
        alert = await db_service.get_alert_by_id(org_id=org_id, alert_id=alert_id)
        if not alert:
            raise ValueError(f"Alert with id {alert_id} not found in organization.")

        title = alert.get("title", "Security Alert")
        description = alert.get("description", "")
        severity = alert.get("severity", "Medium")
        source = alert.get("source", "Telemetry Engine")
        asset_id = alert.get("asset_id")

        source_refs: List[SourceReference] = [
            SourceReference(
                source_type="alert",
                id=alert_id,
                name=title,
                summary=description,
                severity=severity,
            )
        ]

        asset_name = "Edge Perimeter Device"
        if asset_id:
            asset = await db_service.get_asset_by_id(org_id=org_id, asset_id=str(asset_id))
            if asset:
                asset_name = asset.get("name", "Unknown Asset")
                source_refs.append(
                    SourceReference(
                        source_type="asset",
                        id=str(asset_id),
                        name=asset_name,
                        summary=f"IP: {asset.get('ip_address')}",
                        severity=asset.get("risk_level", "Medium"),
                    )
                )

        provider = get_ai_provider()
        prompt = (
            f"Please analyze this alert:\n"
            f"- Title: {title}\n"
            f"- Description: {description}\n"
            f"- Current Severity: {severity}\n"
            f"- Source: {source}\n"
            f"- Targeted Asset: {asset_name} (ID: {asset_id})\n"
        )

        res = await provider.generate_response(
            system_prompt=ALERT_ANALYSIS_SYSTEM_PROMPT,
            user_prompt=prompt,
        )

        # Structured synthesis
        summary = (
            f"Alert triggered by {source} on asset {asset_name}. "
            f"Telemetry indicates abnormal security threshold breach requiring analyst verification."
        )
        trigger_cause = f"Detection rule pattern match on {source} event stream: {title}."
        false_positive_considerations = (
            "Verify whether administrative maintenance, scheduled vulnerability scanning, "
            "or internal load testing coincided with this event timestamp."
        )
        investigation_steps = [
            f"Inspect inbound connection logs and process tree on asset {asset_name}.",
            "Correlate source IP against external threat intelligence reputation feeds.",
            "Verify whether user credentials involved have active MFA challenges.",
            "If hostility is verified, draft an Asset Isolation request via Response Approvals.",
        ]

        analysis_obj = AlertAnalysisResponse(
            alert_id=alert_id,
            alert_title=title,
            summary=summary,
            trigger_cause=trigger_cause,
            related_assets=[asset_name],
            related_indicators=[source],
            severity_assessment=f"{severity} impact based on affected host exposure.",
            false_positive_considerations=false_positive_considerations,
            investigation_steps=investigation_steps,
            suggested_priority="P2" if severity in ("Critical", "High") else "P3",
            supporting_evidence=[description or "Automated event correlation log match."],
            source_references=source_refs,
            model=res.get("model", ai_config.MODEL),
            provider=res.get("provider", "mock"),
            is_mock=res.get("is_mock", True),
            generated_at=datetime.utcnow().isoformat() + "Z",
        )

        # Record recommendation
        await db_service.create_ai_recommendation(
            org_id=org_id,
            recommendation_type="alert",
            related_entity_type="alert",
            related_entity_id=alert_id,
            recommendation=analysis_obj.model_dump(),
            model_name=res.get("model", ai_config.MODEL),
            provider=res.get("provider", "mock"),
        )

        # Log AI Usage
        await db_service.log_ai_usage(
            org_id=org_id,
            user_id=user_id,
            provider=res.get("provider", "mock"),
            model=res.get("model", ai_config.MODEL),
            endpoint="analyze-alert",
            input_tokens=res.get("input_tokens", 100),
            output_tokens=res.get("output_tokens", 250),
            estimated_cost=0.00045,
            request_status="success",
        )

        return analysis_obj
