import logging
from typing import Any, Dict, List, Tuple
from app.ai.schemas import SourceReference
from app.services.supabase_service import SupabaseService

logger = logging.getLogger("cybershield.ai.context")


class ContextRetrievalEngine:
    """
    Deterministic, parameterized context retrieval engine that fetches authorized
    organization security records and constructs grounded citations for AI inference.
    """

    @staticmethod
    async def retrieve_context_for_query(
        db_service: SupabaseService, org_id: str, query: str
    ) -> Tuple[str, List[SourceReference]]:
        q = query.lower()
        context_parts: List[str] = []
        source_refs: List[SourceReference] = []

        # 1. Assets Context (if relevant or general query)
        if any(k in q for k in ["asset", "host", "ip", "device", "server", "firewall", "all", "summary"]):
            try:
                assets_res = await db_service.get_assets(org_id=org_id, page=1, page_size=5)
                items = assets_res[0] if isinstance(assets_res, tuple) else assets_res.get("items", [])
                if items:
                    asset_lines = ["### Assets Inventory:"]
                    for a in items:
                        name = a.get("name", "Unknown Asset")
                        ip = a.get("ip_address", "N/A")
                        risk = a.get("risk_level", "Medium")
                        dev_type = a.get("device_type", "Server")
                        asset_lines.append(f"- Asset: {name} (IP: {ip}, Type: {dev_type}, Risk: {risk})")
                        source_refs.append(
                            SourceReference(
                                source_type="asset",
                                id=str(a.get("id")),
                                name=name,
                                summary=f"IP: {ip} | Risk: {risk}",
                                severity=risk,
                            )
                        )
                    context_parts.append("\n".join(asset_lines))
            except Exception as e:
                logger.warning(f"Error retrieving assets context: {e}")

        # 2. Vulnerabilities & CVEs
        if any(k in q for k in ["vuln", "cve", "kev", "patch", "exploit", "critical", "risk", "all", "summary"]):
            try:
                vulns_res = await db_service.get_vulnerability_findings(org_id=org_id, page=1, page_size=5)
                items = vulns_res[0] if isinstance(vulns_res, tuple) else vulns_res.get("items", [])
                if items:
                    vuln_lines = ["### Open Vulnerabilities & CVEs:"]
                    for v in items:
                        cve = v.get("cve_id", "VULN-GENERIC")
                        title = v.get("title", "Vulnerability Finding")
                        cvss = v.get("cvss_score", 0.0)
                        kev = "YES" if v.get("is_kev") else "NO"
                        sev = v.get("severity", "Medium")
                        vuln_lines.append(f"- {cve}: {title} (CVSS: {cvss}, KEV: {kev}, Severity: {sev})")
                        source_refs.append(
                            SourceReference(
                                source_type="vulnerability",
                                id=str(v.get("id")),
                                name=cve,
                                summary=title,
                                severity=sev,
                                details={"cvss": cvss, "is_kev": v.get("is_kev")},
                            )
                        )
                    context_parts.append("\n".join(vuln_lines))
            except Exception as e:
                logger.warning(f"Error retrieving vulnerability context: {e}")

        # 3. Alerts & Security Events
        if any(k in q for k in ["alert", "event", "threat", "alarm", "spike", "all", "summary"]):
            try:
                alerts_res = await db_service.get_alerts(org_id=org_id, page=1, page_size=5)
                items = alerts_res[0] if isinstance(alerts_res, tuple) else alerts_res.get("items", [])
                if items:
                    alert_lines = ["### Active Security Alerts:"]
                    for al in items:
                        title = al.get("title", "Security Alert")
                        sev = al.get("severity", "Medium")
                        status_val = al.get("status", "New")
                        alert_lines.append(f"- Alert: {title} (Severity: {sev}, Status: {status_val})")
                        source_refs.append(
                            SourceReference(
                                source_type="alert",
                                id=str(al.get("id")),
                                name=title,
                                summary=f"Status: {status_val}",
                                severity=sev,
                            )
                        )
                    context_parts.append("\n".join(alert_lines))
            except Exception as e:
                logger.warning(f"Error retrieving alert context: {e}")

        # 4. Incidents & Incident Operations
        if any(k in q for k in ["incident", "case", "investigat", "mitre", "containment", "playbook", "all"]):
            try:
                inc_res = await db_service.get_incidents(org_id=org_id, page=1, page_size=3)
                items = inc_res[0] if isinstance(inc_res, tuple) else inc_res.get("items", [])
                if items:
                    inc_lines = ["### Active Incident Cases:"]
                    for inc in items:
                        num = inc.get("incident_number", "CS-XXXX-XXXXXX")
                        title = inc.get("title", "Incident Case")
                        status_val = inc.get("status", "New")
                        sev = inc.get("severity", "High")
                        inc_lines.append(f"- Incident {num}: {title} (Status: {status_val}, Severity: {sev})")
                        source_refs.append(
                            SourceReference(
                                source_type="incident",
                                id=str(inc.get("id")),
                                name=num,
                                summary=title,
                                severity=sev,
                            )
                        )
                    context_parts.append("\n".join(inc_lines))
            except Exception as e:
                logger.warning(f"Error retrieving incident context: {e}")

        combined_context = "\n\n".join(context_parts)
        if not combined_context:
            combined_context = "No specific database entities directly matched query keywords."

        return combined_context, source_refs
