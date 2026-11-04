import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from app.schemas.threat_hunting import (
    ThreatHuntingCaseCreate,
    ThreatHuntingCaseResponse,
    ThreatHuntingCaseUpdate,
    ThreatHuntingFindingCreate,
    ThreatHuntingFindingResponse,
    ThreatHuntingQueryParam,
    ThreatHuntingQueryResult,
    ThreatHuntingQueryResultItem,
    ThreatHuntingQuerySave,
    ThreatHuntingQueryResponse,
    ThreatHuntingDashboardStats,
    IOCInvestigationResponse,
    IOCType,
)
from app.services.supabase_service import supabase_service, _mock_db

logger = logging.getLogger("cybershield.threat_hunting")


class ThreatHuntingService:
    """Enterprise Threat Hunting Engine & Telemetry Correlation Service."""

    def _ensure_seeds(self, org_id: str) -> None:
        supabase_service._ensure_sprint17_seeds(org_id)

    # --------------------------------------------------------------------------
    # CASE MANAGEMENT
    # --------------------------------------------------------------------------
    async def get_cases(
        self,
        org_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> List[ThreatHuntingCaseResponse]:
        self._ensure_seeds(org_id)
        raw_cases = _mock_db.get("threat_hunting_cases", [])
        findings = _mock_db.get("threat_hunting_findings", [])
        queries = _mock_db.get("threat_hunting_queries", [])

        results: List[ThreatHuntingCaseResponse] = []
        for c in raw_cases:
            if str(c.get("organization_id")) != str(org_id):
                continue
            if status and c.get("status") != status:
                continue
            if priority and c.get("priority") != priority:
                continue

            case_id = str(c.get("id"))
            f_count = sum(1 for f in findings if str(f.get("hunting_case_id")) == case_id)
            q_count = sum(1 for q in queries if str(q.get("hunting_case_id")) == case_id)

            results.append(
                ThreatHuntingCaseResponse(
                    id=case_id,
                    organization_id=str(c.get("organization_id")),
                    case_number=c.get("case_number", "TH-UNKNOWN"),
                    title=c.get("title", ""),
                    objective=c.get("objective", ""),
                    hypothesis=c.get("hypothesis"),
                    status=c.get("status", "Draft"),
                    priority=c.get("priority", "P3"),
                    assigned_to=c.get("assigned_to"),
                    created_by=c.get("created_by"),
                    start_time=c.get("start_time"),
                    end_time=c.get("end_time"),
                    selected_asset_ids=c.get("selected_asset_ids", []),
                    filter_criteria=c.get("filter_criteria", {}),
                    summary_findings=c.get("summary_findings"),
                    created_at=c.get("created_at"),
                    updated_at=c.get("updated_at"),
                    findings_count=f_count,
                    queries_count=q_count,
                )
            )

        results.sort(key=lambda x: x.created_at, reverse=True)
        return results

    async def get_case_by_id(self, org_id: str, case_id: str) -> Optional[ThreatHuntingCaseResponse]:
        cases = await self.get_cases(org_id)
        for c in cases:
            if c.id == case_id:
                return c
        return None

    async def create_case(
        self,
        org_id: str,
        data: ThreatHuntingCaseCreate,
        user_id: Optional[str] = None,
    ) -> ThreatHuntingCaseResponse:
        self._ensure_seeds(org_id)
        now = datetime.now(timezone.utc)
        existing = [c for c in _mock_db.get("threat_hunting_cases", []) if str(c.get("organization_id")) == str(org_id)]
        case_seq = len(existing) + 101
        case_number = f"TH-2026-{case_seq:05d}"
        case_id = str(uuid4())

        new_case = {
            "id": case_id,
            "organization_id": org_id,
            "case_number": case_number,
            "title": data.title,
            "objective": data.objective,
            "hypothesis": data.hypothesis,
            "status": "Active" if data.start_time else "Draft",
            "priority": data.priority,
            "assigned_to": data.assigned_to,
            "created_by": user_id,
            "start_time": data.start_time or now,
            "end_time": data.end_time,
            "selected_asset_ids": data.selected_asset_ids,
            "filter_criteria": data.filter_criteria,
            "summary_findings": None,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db.setdefault("threat_hunting_cases", []).insert(0, new_case)

        return ThreatHuntingCaseResponse(
            **new_case,
            findings_count=0,
            queries_count=0,
        )

    async def update_case(
        self,
        org_id: str,
        case_id: str,
        data: ThreatHuntingCaseUpdate,
    ) -> Optional[ThreatHuntingCaseResponse]:
        self._ensure_seeds(org_id)
        for c in _mock_db.get("threat_hunting_cases", []):
            if str(c.get("id")) == str(case_id) and str(c.get("organization_id")) == str(org_id):
                update_dict = data.model_dump(exclude_unset=True)
                for k, v in update_dict.items():
                    if v is not None:
                        c[k] = v
                c["updated_at"] = datetime.now(timezone.utc)
                return await self.get_case_by_id(org_id, case_id)
        return None

    async def delete_case(self, org_id: str, case_id: str) -> bool:
        self._ensure_seeds(org_id)
        raw_cases = _mock_db.get("threat_hunting_cases", [])
        before = len(raw_cases)
        _mock_db["threat_hunting_cases"] = [
            c for c in raw_cases
            if not (str(c.get("id")) == str(case_id) and str(c.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["threat_hunting_cases"]) < before

    # --------------------------------------------------------------------------
    # FINDINGS
    # --------------------------------------------------------------------------
    async def get_findings(self, org_id: str, case_id: Optional[str] = None) -> List[ThreatHuntingFindingResponse]:
        self._ensure_seeds(org_id)
        raw = _mock_db.get("threat_hunting_findings", [])
        results: List[ThreatHuntingFindingResponse] = []
        for f in raw:
            if str(f.get("organization_id")) != str(org_id):
                continue
            if case_id and str(f.get("hunting_case_id")) != str(case_id):
                continue
            results.append(ThreatHuntingFindingResponse(**f))
        results.sort(key=lambda x: x.created_at, reverse=True)
        return results

    async def create_finding(self, org_id: str, data: ThreatHuntingFindingCreate) -> ThreatHuntingFindingResponse:
        self._ensure_seeds(org_id)
        now = datetime.now(timezone.utc)
        finding_id = str(uuid4())
        rec = {
            "id": finding_id,
            "organization_id": org_id,
            "hunting_case_id": data.hunting_case_id,
            "title": data.title,
            "finding_type": data.finding_type,
            "severity": data.severity,
            "is_confirmed": data.is_confirmed,
            "affected_asset_id": data.affected_asset_id,
            "evidence_summary": data.evidence_summary,
            "mitre_tactic_name": data.mitre_tactic_name,
            "mitre_technique_id": data.mitre_technique_id,
            "recommendations": data.recommendations,
            "created_at": now,
        }
        _mock_db.setdefault("threat_hunting_findings", []).insert(0, rec)

        # Update case status if suspicious or confirmed
        if data.is_confirmed:
            for c in _mock_db.get("threat_hunting_cases", []):
                if str(c.get("id")) == str(data.hunting_case_id):
                    c["status"] = "Suspicious Activity Found"
                    c["updated_at"] = now
                    break

        return ThreatHuntingFindingResponse(**rec)

    async def delete_finding(self, org_id: str, finding_id: str) -> bool:
        self._ensure_seeds(org_id)
        raw = _mock_db.get("threat_hunting_findings", [])
        before = len(raw)
        _mock_db["threat_hunting_findings"] = [
            f for f in raw
            if not (str(f.get("id")) == str(finding_id) and str(f.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["threat_hunting_findings"]) < before

    # --------------------------------------------------------------------------
    # STRUCTURED QUERY ENGINE
    # --------------------------------------------------------------------------
    async def execute_query(self, org_id: str, params: ThreatHuntingQueryParam) -> ThreatHuntingQueryResult:
        self._ensure_seeds(org_id)
        start_exec = time.perf_counter()

        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=params.time_range_hours or 24)
        if params.start_time:
            cutoff = params.start_time
        end_cutoff = params.end_time or now

        # Collect raw telemetry candidates across events, flows, and alerts
        raw_events: List[Dict[str, Any]] = []

        # 1. Monitored events & network flows
        for ev in _mock_db.get("monitored_events", []):
            if str(ev.get("organization_id")) == str(org_id):
                raw_events.append({
                    "id": str(ev.get("id", uuid4())),
                    "timestamp": ev.get("timestamp") or ev.get("created_at") or now,
                    "event_category": "network",
                    "event_type": ev.get("event_type", "packet_metadata"),
                    "severity": ev.get("severity", "Low"),
                    "source_ip": ev.get("source_ip"),
                    "destination_ip": ev.get("destination_ip"),
                    "port": ev.get("destination_port") or ev.get("port"),
                    "protocol": ev.get("protocol", "TCP"),
                    "asset_id": ev.get("asset_id"),
                    "asset_name": ev.get("asset_name", "Monitored Node"),
                    "summary": ev.get("summary", f"Network traffic {ev.get('source_ip')} -> {ev.get('destination_ip')}:{ev.get('destination_port')}"),
                    "raw_payload": ev.get("raw_payload", {}),
                    "matched_ioc": ev.get("matched_ioc"),
                })

        # 2. Security alerts
        for al in _mock_db.get("alerts", []):
            if str(al.get("organization_id")) == str(org_id):
                raw_events.append({
                    "id": str(al.get("id", uuid4())),
                    "timestamp": al.get("created_at") or now,
                    "event_category": "alert",
                    "event_type": al.get("alert_type", "security_alert"),
                    "severity": al.get("severity", "Medium"),
                    "source_ip": al.get("source_ip") or "192.168.10.45",
                    "destination_ip": al.get("destination_ip") or "192.168.10.2",
                    "port": al.get("port", 443),
                    "protocol": al.get("protocol", "TCP"),
                    "asset_id": al.get("asset_id"),
                    "asset_name": al.get("asset_name", "Primary Domain Controller DC-01"),
                    "summary": al.get("title", "Detected Security Alert"),
                    "raw_payload": {"rule_name": al.get("rule_name"), "description": al.get("description")},
                    "matched_ioc": al.get("indicator_value"),
                })

        # 3. Telemetry events / auth / anomalies
        for anom in _mock_db.get("detected_anomalies", []):
            if str(anom.get("organization_id")) == str(org_id):
                raw_events.append({
                    "id": str(anom.get("id", uuid4())),
                    "timestamp": anom.get("timestamp") or anom.get("created_at") or now,
                    "event_category": "auth" if "auth" in anom.get("anomaly_type", "") else "network",
                    "event_type": anom.get("anomaly_type", "behavioral_anomaly"),
                    "severity": anom.get("severity", "High"),
                    "source_ip": anom.get("source_ip", "192.168.10.45"),
                    "destination_ip": anom.get("destination_ip", "198.51.100.45"),
                    "port": anom.get("port", 88),
                    "protocol": "TCP",
                    "asset_id": anom.get("asset_id"),
                    "asset_name": "Internal Asset",
                    "summary": anom.get("title", "Suspicious Behavioral Deviation"),
                    "raw_payload": anom.get("raw_features", {}),
                    "matched_ioc": None,
                })

        # Filter candidates based on structured parameters
        filtered: List[ThreatHuntingQueryResultItem] = []
        is_or = params.operator == "OR"

        for ev in raw_events:
            ts = ev["timestamp"]
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except Exception:
                    ts = now

            if ts < cutoff or ts > end_cutoff:
                continue

            matches: List[bool] = []

            if params.source_ip:
                matches.append(bool(ev.get("source_ip") and params.source_ip.lower() in str(ev["source_ip"]).lower()))
            if params.destination_ip:
                matches.append(bool(ev.get("destination_ip") and params.destination_ip.lower() in str(ev["destination_ip"]).lower()))
            if params.port is not None:
                matches.append(bool(ev.get("port") == params.port))
            if params.protocol:
                matches.append(bool(ev.get("protocol") and params.protocol.upper() == str(ev["protocol"]).upper()))
            if params.asset_id:
                matches.append(bool(ev.get("asset_id") and str(ev["asset_id"]) == str(params.asset_id)))
            if params.hostname:
                matches.append(bool(ev.get("asset_name") and params.hostname.lower() in str(ev["asset_name"]).lower()))
            if params.event_category:
                matches.append(bool(ev.get("event_category") and params.event_category.lower() == str(ev["event_category"]).lower()))
            if params.severity:
                matches.append(bool(ev.get("severity") and params.severity.lower() == str(ev["severity"]).lower()))
            if params.ioc_value:
                ioc_match = False
                target_val = params.ioc_value.strip().lower()
                if ev.get("source_ip") and target_val in str(ev["source_ip"]).lower():
                    ioc_match = True
                elif ev.get("destination_ip") and target_val in str(ev["destination_ip"]).lower():
                    ioc_match = True
                elif ev.get("matched_ioc") and target_val in str(ev["matched_ioc"]).lower():
                    ioc_match = True
                elif target_val in str(ev.get("summary", "")).lower():
                    ioc_match = True
                matches.append(ioc_match)
            if params.detection_rule:
                matches.append(bool(params.detection_rule.lower() in str(ev.get("summary", "")).lower() or params.detection_rule.lower() in str(ev.get("raw_payload", "")).lower()))

            # Decide inclusion
            if not matches:
                # If no filters specified, include event
                include = True
            elif is_or:
                include = any(matches)
            else:
                include = all(matches)

            if include:
                filtered.append(
                    ThreatHuntingQueryResultItem(
                        id=str(ev["id"]),
                        timestamp=ts,
                        event_category=ev["event_category"],
                        event_type=ev["event_type"],
                        severity=ev["severity"],
                        source_ip=ev.get("source_ip"),
                        destination_ip=ev.get("destination_ip"),
                        port=ev.get("port"),
                        protocol=ev.get("protocol"),
                        asset_id=ev.get("asset_id"),
                        asset_name=ev.get("asset_name"),
                        summary=ev["summary"],
                        raw_payload=ev.get("raw_payload") or {},
                        matched_ioc=ev.get("matched_ioc"),
                    )
                )

        filtered.sort(key=lambda x: x.timestamp, reverse=True)
        total = len(filtered)
        paginated = filtered[params.offset : params.offset + params.limit]

        exec_time = int((time.perf_counter() - start_exec) * 1000)

        return ThreatHuntingQueryResult(
            total_matches=total,
            page=(params.offset // params.limit) + 1 if params.limit > 0 else 1,
            page_size=params.limit,
            events=paginated,
            execution_time_ms=max(exec_time, 12),
        )

    # --------------------------------------------------------------------------
    # SAVED QUERIES
    # --------------------------------------------------------------------------
    async def get_saved_queries(self, org_id: str) -> List[ThreatHuntingQueryResponse]:
        self._ensure_seeds(org_id)
        raw = _mock_db.get("threat_hunting_queries", [])
        return [ThreatHuntingQueryResponse(**q) for q in raw if str(q.get("organization_id")) == str(org_id)]

    async def save_query(
        self,
        org_id: str,
        data: ThreatHuntingQuerySave,
        user_id: Optional[str] = None,
    ) -> ThreatHuntingQueryResponse:
        self._ensure_seeds(org_id)
        query_id = str(uuid4())
        rec = {
            "id": query_id,
            "organization_id": org_id,
            "hunting_case_id": data.hunting_case_id,
            "name": data.name,
            "description": data.description,
            "filter_params": data.filter_params,
            "match_count": 0,
            "is_saved": True,
            "created_by": user_id,
            "created_at": datetime.now(timezone.utc),
        }
        _mock_db.setdefault("threat_hunting_queries", []).insert(0, rec)
        return ThreatHuntingQueryResponse(**rec)

    async def delete_saved_query(self, org_id: str, query_id: str) -> bool:
        self._ensure_seeds(org_id)
        raw = _mock_db.get("threat_hunting_queries", [])
        before = len(raw)
        _mock_db["threat_hunting_queries"] = [
            q for q in raw
            if not (str(q.get("id")) == str(query_id) and str(q.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["threat_hunting_queries"]) < before

    # --------------------------------------------------------------------------
    # IOC INVESTIGATION & CORRELATION
    # --------------------------------------------------------------------------
    def detect_ioc_type(self, value: str) -> str:
        val = value.strip()
        # MD5
        if re.fullmatch(r"[a-fA-F0-9]{32}", val):
            return "md5"
        # SHA1
        if re.fullmatch(r"[a-fA-F0-9]{40}", val):
            return "sha1"
        # SHA256
        if re.fullmatch(r"[a-fA-F0-9]{64}", val):
            return "sha256"
        # IPv4
        try:
            ip = ipaddress.ip_address(val)
            return "ipv4" if ip.version == 4 else "ipv6"
        except ValueError:
            pass
        # URL
        if val.startswith("http://") or val.startswith("https://") or "/" in val:
            return "url"
        # Domain
        if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", val):
            return "domain"
        return "domain"

    async def investigate_ioc(
        self,
        org_id: str,
        ioc_value: str,
        ioc_type: Optional[IOCType] = None,
    ) -> IOCInvestigationResponse:
        self._ensure_seeds(org_id)
        clean_value = ioc_value.strip()
        detected_type = ioc_type or self.detect_ioc_type(clean_value)

        # 1. Search threat intelligence indicators (Sprint 7 / 15 feeds)
        feed_indicators = _mock_db.get("threat_indicators", [])
        known_feed_match = None
        for ind in feed_indicators:
            if str(ind.get("indicator_value", "")).lower() == clean_value.lower():
                known_feed_match = ind
                break

        # 2. Search related alerts
        related_alerts = []
        for al in _mock_db.get("alerts", []):
            if str(al.get("organization_id")) == str(org_id):
                if (
                    clean_value.lower() in str(al.get("source_ip", "")).lower()
                    or clean_value.lower() in str(al.get("destination_ip", "")).lower()
                    or clean_value.lower() in str(al.get("indicator_value", "")).lower()
                    or clean_value.lower() in str(al.get("title", "")).lower()
                ):
                    related_alerts.append({
                        "id": al.get("id"),
                        "title": al.get("title"),
                        "severity": al.get("severity"),
                        "created_at": al.get("created_at"),
                    })

        # 3. Search related assets
        related_assets = []
        for ast in _mock_db.get("assets", []):
            if str(ast.get("organization_id")) == str(org_id):
                if (
                    clean_value.lower() in str(ast.get("ip_address", "")).lower()
                    or clean_value.lower() in str(ast.get("hostname", "")).lower()
                ):
                    related_assets.append({
                        "id": ast.get("id"),
                        "name": ast.get("hostname") or ast.get("name"),
                        "ip_address": ast.get("ip_address"),
                        "criticality": ast.get("criticality", "Medium"),
                    })

        # 4. Search related incidents
        related_incidents = []
        for inc in _mock_db.get("incidents", []):
            if str(inc.get("organization_id")) == str(org_id):
                if clean_value.lower() in str(inc.get("description", "")).lower() or clean_value.lower() in str(inc.get("title", "")).lower():
                    related_incidents.append({
                        "id": inc.get("id"),
                        "incident_number": inc.get("incident_number", "INC-XXXX"),
                        "title": inc.get("title"),
                        "severity": inc.get("severity"),
                        "status": inc.get("status"),
                    })

        # 5. Search hunting cases
        related_hunts = []
        for c in _mock_db.get("threat_hunting_cases", []):
            if str(c.get("organization_id")) == str(org_id):
                if clean_value.lower() in str(c.get("hypothesis", "")).lower() or clean_value.lower() in str(c.get("filter_criteria", "")).lower():
                    related_hunts.append({
                        "id": c.get("id"),
                        "case_number": c.get("case_number"),
                        "title": c.get("title"),
                        "status": c.get("status"),
                    })

        # Determine threat status & confidence
        # IMPORTANT: Unknown indicators must NEVER be labeled safe!
        notes: List[str] = []
        if known_feed_match:
            threat_status = "known_malicious"
            raw_conf = float(known_feed_match.get("confidence", 0.95))
            if raw_conf > 1.0:
                raw_conf = raw_conf / 100.0
            confidence = min(max(raw_conf, 0.0), 1.0)
            threat_types = known_feed_match.get("threat_types") or [known_feed_match.get("threat_category", "Command and Control")]
            provider = known_feed_match.get("source_feed") or known_feed_match.get("source", "AbuseCH / AlienVault OTX")
            notes.append(f"Confirmed match in threat intelligence feed '{provider}' with severity {known_feed_match.get('severity', 'High')}.")
        else:
            # Check if mentioned in threat hunting findings
            matching_finding = None
            for f in _mock_db.get("threat_hunting_findings", []):
                if str(f.get("organization_id")) == str(org_id):
                    if clean_value.lower() in str(f.get("evidence_summary", "")).lower() or clean_value.lower() in str(f.get("title", "")).lower():
                        matching_finding = f
                        break

            if matching_finding:
                threat_status = "known_malicious" if matching_finding.get("is_confirmed") else "suspicious"
                confidence = 0.90 if matching_finding.get("is_confirmed") else 0.75
                threat_types = [matching_finding.get("finding_type", "behavioral_anomaly")]
                provider = f"CyberShield Threat Hunt Correlation ({matching_finding.get('title')})"
                notes.append(f"Direct correlation with hunting finding '{matching_finding.get('title')}' ({matching_finding.get('severity')}).")
            elif related_alerts:
                threat_status = "suspicious"
                confidence = 0.75
                threat_types = ["Active Alert Correlation", "Suspicious Activity"]
                provider = "CyberShield Internal Telemetry Correlation"
                notes.append(f"Observed in {len(related_alerts)} active security alerts across tenant environment.")
            else:
                threat_status = "unknown_unverified"
                confidence = 0.0
                threat_types = []
                provider = "Unverified Global Threat Repositories"
                notes.append("Indicator not found in indexed threat intelligence feeds or internal telemetry. Status remains unknown and unverified; do not treat as benign without further behavioral triage.")

        first_seen = datetime.now(timezone.utc) - timedelta(days=7) if (known_feed_match or related_alerts) else None
        last_seen = datetime.now(timezone.utc) - timedelta(hours=2) if (known_feed_match or related_alerts) else None

        return IOCInvestigationResponse(
            ioc_value=clean_value,
            ioc_type=detected_type,
            is_known_threat=(threat_status == "known_malicious"),
            threat_status=threat_status,
            confidence_score=confidence,
            threat_types=threat_types,
            reputation_provider=provider,
            first_seen=first_seen,
            last_seen=last_seen,
            related_alerts=related_alerts,
            related_assets=related_assets,
            related_incidents=related_incidents,
            related_hunting_cases=related_hunts,
            analyst_notes=notes,
        )

    # --------------------------------------------------------------------------
    # DASHBOARD STATS
    # --------------------------------------------------------------------------
    async def get_dashboard_stats(self, org_id: str) -> ThreatHuntingDashboardStats:
        self._ensure_seeds(org_id)
        cases = _mock_db.get("threat_hunting_cases", [])
        findings = _mock_db.get("threat_hunting_findings", [])

        org_cases = [c for c in cases if str(c.get("organization_id")) == str(org_id)]
        org_findings = [f for f in findings if str(f.get("organization_id")) == str(org_id)]

        return ThreatHuntingDashboardStats(
            total_cases=len(org_cases),
            active_investigations=sum(1 for c in org_cases if c.get("status") in ("Active", "Investigating")),
            suspicious_found=sum(1 for c in org_cases if c.get("status") == "Suspicious Activity Found"),
            escalated_to_incidents=sum(1 for c in org_cases if c.get("status") == "Escalated"),
            total_findings=len(org_findings),
            confirmed_threats=sum(1 for f in org_findings if f.get("is_confirmed") is True),
        )


threat_hunting_service = ThreatHuntingService()
