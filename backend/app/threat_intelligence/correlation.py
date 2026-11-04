import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.threat_intelligence.reputation import reputation_service

logger = logging.getLogger(__name__)


class EventCorrelationEngine:
    """
    Evaluates incoming security events against detection rules and threat intelligence indicators.
    Generates actionable, deduplicated Security Alerts.
    """

    @classmethod
    def evaluate(
        cls,
        new_event: Dict[str, Any],
        recent_events: List[Dict[str, Any]],
        rules: List[Dict[str, Any]],
        indicators: List[Dict[str, Any]],
        existing_alerts: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        generated_alerts: List[Dict[str, Any]] = []
        org_id = str(new_event.get("organization_id", ""))
        event_time_str = new_event.get("event_timestamp") or datetime.utcnow().isoformat()
        try:
            event_dt = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        except Exception:
            event_dt = datetime.now()

        for rule in rules:
            if not rule.get("is_enabled", True):
                continue

            rule_type = rule.get("rule_type")
            threshold = rule.get("threshold", 5)
            window_sec = rule.get("time_window_seconds", 300)
            cutoff = event_dt - timedelta(seconds=window_sec)

            # Filter relevant historical events in the time window
            window_events = []
            for ev in recent_events:
                ts_str = ev.get("event_timestamp")
                if not ts_str:
                    continue
                try:
                    ev_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if ev_dt >= cutoff:
                        window_events.append(ev)
                except Exception:
                    continue

            # ------------------------------------------------------------------
            # Scenario A: Repeated Authentication Failures
            # ------------------------------------------------------------------
            if rule_type == "auth_failure_threshold":
                if new_event.get("event_type") == "auth_failure":
                    src_ip = new_event.get("source_ip")
                    failures = [
                        e for e in window_events
                        if e.get("event_type") == "auth_failure" and e.get("source_ip") == src_ip
                    ]
                    # Count includes the new event
                    count = len(failures) + 1
                    if count >= threshold:
                        title = f"Repeated Authentication Failures ({count} attempts from {src_ip or 'unknown'})"
                        alert = cls._build_alert(
                            org_id=org_id,
                            title=title,
                            description=f"Observed {count} failed login attempts within {window_sec}s exceeding threshold of {threshold}.",
                            alert_type="brute_force_attempt",
                            severity=rule.get("severity", "High"),
                            source="Correlation Engine: Auth Monitor",
                            rule_id=rule.get("id"),
                            asset_id=new_event.get("asset_id"),
                            related_event_ids=[str(e["id"]) for e in failures] + [str(new_event.get("id"))],
                            confidence=85,
                        )
                        if not cls._is_duplicate(alert, existing_alerts):
                            generated_alerts.append(alert)

            # ------------------------------------------------------------------
            # Scenario B: Threat Indicator Match
            # ------------------------------------------------------------------
            elif rule_type == "threat_intel_match":
                fields_to_check = [
                    new_event.get("source_ip"),
                    new_event.get("destination_ip"),
                    new_event.get("hostname"),
                ]
                for val in fields_to_check:
                    if not val:
                        continue
                    rep = reputation_service.lookup(val, indicators)
                    if rep.get("is_malicious"):
                        title = f"Threat Indicator Match: {rep.get('threat_category', 'threat').upper()} ({val})"
                        alert = cls._build_alert(
                            org_id=org_id,
                            title=title,
                            description=(
                                f"Observed communication with known malicious {rep.get('indicator_type')} '{val}' "
                                f"cataloged by {rep.get('source')} ({rep.get('description') or 'Threat activity'})."
                            ),
                            alert_type="threat_intel_match",
                            severity=rep.get("severity", "Critical"),
                            source=f"Threat Intel: {rep.get('source')}",
                            rule_id=rule.get("id"),
                            indicator_id=rep.get("indicator_id"),
                            asset_id=new_event.get("asset_id"),
                            related_event_ids=[str(new_event.get("id"))],
                            confidence=rep.get("confidence", 90),
                        )
                        if not cls._is_duplicate(alert, existing_alerts):
                            generated_alerts.append(alert)
                        break

            # ------------------------------------------------------------------
            # Scenario D: Asset Activity Anomaly
            # ------------------------------------------------------------------
            elif rule_type == "asset_anomaly":
                aid = new_event.get("asset_id")
                if aid:
                    asset_events = [e for e in window_events if e.get("asset_id") == aid]
                    count = len(asset_events) + 1
                    if count >= threshold:
                        title = f"Event Volume Spike Anomaly on Asset ({count} events in {window_sec}s)"
                        alert = cls._build_alert(
                            org_id=org_id,
                            title=title,
                            description=f"Host generated abnormal telemetry volume ({count} events) exceeding baseline threshold of {threshold}.",
                            alert_type="telemetry_anomaly",
                            severity=rule.get("severity", "Medium"),
                            source="Correlation Engine: Anomaly Detector",
                            rule_id=rule.get("id"),
                            asset_id=aid,
                            related_event_ids=[str(e["id"]) for e in asset_events] + [str(new_event.get("id"))],
                            confidence=75,
                        )
                        if not cls._is_duplicate(alert, existing_alerts):
                            generated_alerts.append(alert)

            # ------------------------------------------------------------------
            # Scenario E: Repeated Suspicious Events
            # ------------------------------------------------------------------
            elif rule_type == "repeated_suspicious_events":
                etype = new_event.get("event_type")
                if etype in ("suspicious_traffic", "port_scan", "policy_violation"):
                    same_type = [e for e in window_events if e.get("event_type") == etype]
                    count = len(same_type) + 1
                    if count >= threshold:
                        title = f"Repeated Suspicious Activity ({etype} repeated {count} times)"
                        alert = cls._build_alert(
                            org_id=org_id,
                            title=title,
                            description=f"Suspicious activity {etype} was observed {count} times within {window_sec}s.",
                            alert_type="suspicious_activity_burst",
                            severity=rule.get("severity", "High"),
                            source="Correlation Engine: Pattern Matcher",
                            rule_id=rule.get("id"),
                            asset_id=new_event.get("asset_id"),
                            related_event_ids=[str(e["id"]) for e in same_type] + [str(new_event.get("id"))],
                            confidence=80,
                        )
                        if not cls._is_duplicate(alert, existing_alerts):
                            generated_alerts.append(alert)

        return generated_alerts

    @staticmethod
    def _is_duplicate(new_alert: Dict[str, Any], existing_alerts: List[Dict[str, Any]]) -> bool:
        """Prevent duplicate open alerts for the same underlying pattern."""
        for a in existing_alerts:
            if (
                a.get("title") == new_alert.get("title")
                and a.get("status") in ("New", "Investigating")
                and a.get("asset_id") == new_alert.get("asset_id")
            ):
                return True
        return False

    @staticmethod
    def _build_alert(
        org_id: str,
        title: str,
        description: str,
        alert_type: str,
        severity: str,
        source: str,
        rule_id: Optional[str] = None,
        indicator_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        related_event_ids: Optional[List[str]] = None,
        confidence: int = 80,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        return {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "title": title,
            "description": description,
            "alert_type": alert_type,
            "severity": severity,
            "status": "New",
            "source": source,
            "asset_id": asset_id,
            "indicator_id": indicator_id,
            "rule_id": rule_id,
            "related_event_ids": related_event_ids or [],
            "assigned_to": None,
            "linked_incident_id": None,
            "confidence": confidence,
            "first_detected_at": now,
            "last_detected_at": now,
            "created_at": now,
            "updated_at": now,
        }


correlation_engine = EventCorrelationEngine()
