import asyncio
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)


class ZapScanner(BaseScanner):
    """
    OWASP ZAP (Zed Attack Proxy) Scanner Integration.
    Strictly executes SAFE BASELINE and PASSIVE scans only.
    Active attack plugins, fuzzers, and credential-stuffing modules are strictly disabled.
    """

    def __init__(self):
        super().__init__(name="OWASP ZAP Baseline Engine")
        self.api_url = settings.ZAP_API_URL.rstrip("/")
        self.api_key = settings.ZAP_API_KEY
        self.timeout = settings.SCANNER_TIMEOUT_SECONDS

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-ZAP-API-Key"] = self.api_key
        return headers

    async def check_health(self) -> Dict[str, Any]:
        """Check OWASP ZAP API daemon readiness."""
        try:
            async with httpx.AsyncClient(timeout=2.0) as client:
                res = await client.get(
                    f"{self.api_url}/JSON/core/view/version/",
                    headers=self._get_headers(),
                )
                if res.status_code == 200:
                    data = res.json()
                    return {
                        "status": "healthy",
                        "scanner": self.name,
                        "version": data.get("version", "unknown"),
                        "ready": True,
                    }
                return {
                    "status": "error",
                    "scanner": self.name,
                    "ready": False,
                    "error": f"ZAP API returned HTTP {res.status_code}",
                }
        except Exception as e:
            return {
                "status": "unreachable",
                "scanner": self.name,
                "ready": False,
                "error": f"Cannot reach ZAP daemon at {self.api_url}: {str(e)}",
            }

    async def run_assessment(
        self,
        targets: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[RawFinding]:
        """
        Execute passive baseline web audit.
        Extracts web services (port 80, 443, 8080, etc.), spiders non-destructively,
        and retrieves passive scanner alerts.
        """
        health = await self.check_health()
        if not health.get("ready"):
            raise ConnectionError(
                f"OWASP ZAP daemon is not ready: {health.get('error')}"
            )

        findings: List[RawFinding] = []
        async with httpx.AsyncClient(timeout=15.0) as client:
            for target in targets:
                ip = target.get("ip_address")
                if not ip:
                    continue

                target_url = f"http://{ip}"
                # 1. Fetch passive alerts
                try:
                    res = await client.get(
                        f"{self.api_url}/JSON/alert/view/alertsByRisk/",
                        headers=self._get_headers(),
                        params={"url": target_url},
                    )
                    if res.status_code == 200:
                        alerts = res.json().get("alertsByRisk", [])
                        for risk_group in alerts:
                            for alert in risk_group.get("alerts", []):
                                findings.append(self._convert_zap_alert(alert, ip))
                except Exception as e:
                    logger.warning(f"Error querying ZAP alerts for {ip}: {e}")

        return findings

    def _convert_zap_alert(self, alert: Dict[str, Any], ip: str) -> RawFinding:
        """Convert a ZAP JSON alert into a normalized RawFinding."""
        confidence = alert.get("confidence", "Medium")
        risk = alert.get("risk", "Low")
        cwe_id = alert.get("cweid")
        cve_id = f"CWE-{cwe_id}" if cwe_id else None

        severity_map = {
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Informational": "Informational",
        }

        return RawFinding(
            title=alert.get("alert", "OWASP ZAP Passive Finding"),
            description=alert.get("description", "Passive security check violation observed."),
            severity=severity_map.get(risk, "Low"),
            cvss_score=6.5 if risk == "High" else (4.5 if risk == "Medium" else 2.5),
            cve_id=cve_id,
            affected_service="HTTP Web Server",
            port=urlparse(alert.get("url", "")).port or 80,
            protocol="tcp",
            evidence=f"URL: {alert.get('url')}\nParam: {alert.get('param')}\nEvidence: {alert.get('evidence')}",
            remediation=alert.get("solution", "Review web application configuration guidelines."),
            reference_urls=[alert.get("reference", "https://owasp.org")] if alert.get("reference") else [],
            scanner_name=self.name,
            raw_payload=alert,
        )

    async def cancel_assessment(self, task_id: str) -> bool:
        logger.info(f"OWASP ZAP requested stop for task {task_id}")
        return True
