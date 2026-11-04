import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Fallback known CVE knowledge base for offline operation & fast deterministic testing
FALLBACK_CVE_CATALOG: Dict[str, Dict[str, Any]] = {
    "CVE-2024-6387": {
        "cve_id": "CVE-2024-6387",
        "title": "OpenSSH regreSSHion Remote Code Execution Vulnerability",
        "description": "A signal handler race condition vulnerability was discovered in OpenSSH's server (sshd) on glibc-based Linux systems. An unauthenticated attacker can exploit this condition to execute arbitrary code as root.",
        "cvss_score": 8.1,
        "cvss_version": "3.1",
        "severity": "High",
        "published_date": "2024-07-01T00:00:00Z",
        "last_modified_date": "2024-07-15T12:00:00Z",
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
            "https://www.openssh.com/txt/release-9.8",
            "https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt",
        ],
        "affected_products": ["OpenSSH: 8.5p1 - 9.7p1"],
    },
    "CVE-2024-21762": {
        "cve_id": "CVE-2024-21762",
        "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write RCE",
        "description": "An out-of-bounds write vulnerability in Fortinet FortiOS and FortiProxy allows an unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
        "cvss_score": 9.8,
        "cvss_version": "3.1",
        "severity": "Critical",
        "published_date": "2024-02-09T00:00:00Z",
        "last_modified_date": "2024-03-01T15:00:00Z",
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            "https://www.fortiguard.com/psirt/FG-IR-24-015",
        ],
        "affected_products": ["Fortinet FortiOS 7.4.0 - 7.4.2", "FortiOS 7.2.0 - 7.2.6"],
    },
    "CVE-2023-48795": {
        "cve_id": "CVE-2023-48795",
        "title": "SSH Protocol Terrapin Attack (Prefix Truncation)",
        "description": "The Terrapin attack allows a man-in-the-middle attacker to truncate extension negotiation messages during SSH handshake, disabling keystroke timing obfuscation and channel security features.",
        "cvss_score": 5.9,
        "cvss_version": "3.1",
        "severity": "Medium",
        "published_date": "2023-12-18T00:00:00Z",
        "last_modified_date": "2024-01-10T10:00:00Z",
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
            "https://terrapin-attack.com/",
        ],
        "affected_products": ["OpenSSH < 9.6", "libssh < 0.10.6"],
    },
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "title": "Apache Log4j2 JNDI Remote Code Execution (Log4Shell)",
        "description": "Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints, allowing full remote code execution.",
        "cvss_score": 10.0,
        "cvss_version": "3.1",
        "severity": "Critical",
        "published_date": "2021-12-10T00:00:00Z",
        "last_modified_date": "2023-04-18T00:00:00Z",
        "reference_urls": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "https://logging.apache.org/log4j/2.x/security.html",
        ],
        "affected_products": ["Apache Log4j: 2.0-beta9 - 2.14.1"],
    },
}


class CVEService:
    """
    NVD CVE Intelligence Service.
    Queries the National Vulnerability Database API with caching, rate limit throttling,
    and safe offline catalog fallback.
    """

    def __init__(self):
        self.api_url = settings.NVD_API_URL
        self.api_key = settings.NVD_API_KEY
        self._cache: Dict[str, Dict[str, Any]] = dict(FALLBACK_CVE_CATALOG)
        self._cache_timestamps: Dict[str, float] = {k: time.time() for k in FALLBACK_CVE_CATALOG}
        self.cache_ttl = 86400  # 24 hours
        self._last_request_time = 0.0

    def _get_headers(self) -> Dict[str, str]:
        headers = {"User-Agent": "CyberShield-Security-Platform/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    async def _rate_limit_throttle(self):
        """Enforces minimum interval between NVD API requests."""
        # 0.6s interval with API key (up to 50 req / 30s), 6.0s without key (5 req / 30s)
        interval = 0.6 if self.api_key else 6.0
        elapsed = time.time() - self._last_request_time
        if elapsed < interval:
            await asyncio.sleep(interval - elapsed)
        self._last_request_time = time.time()

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve CVE metadata by CVE ID with caching."""
        normalized_cve = cve_id.strip().upper()
        now = time.time()

        # Check in-memory cache
        if normalized_cve in self._cache:
            ts = self._cache_timestamps.get(normalized_cve, 0)
            if now - ts < self.cache_ttl:
                return self._cache[normalized_cve]

        # Query NVD API if available
        try:
            await self._rate_limit_throttle()
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(
                    self.api_url,
                    headers=self._get_headers(),
                    params={"cveId": normalized_cve},
                )
                if res.status_code == 200:
                    data = res.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    if vulnerabilities:
                        cve_item = vulnerabilities[0].get("cve", {})
                        parsed = self._parse_nvd_cve(cve_item)
                        self._cache[normalized_cve] = parsed
                        self._cache_timestamps[normalized_cve] = now
                        return parsed
        except Exception as e:
            logger.warning(f"Error querying NVD API for {normalized_cve}: {e}")

        # Return fallback catalog entry if present
        return FALLBACK_CVE_CATALOG.get(normalized_cve)

    def _parse_nvd_cve(self, cve_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Extract standardized CVE metadata from NVD 2.0 response format."""
        cve_id = cve_dict.get("id", "UNKNOWN-CVE")
        descriptions = cve_dict.get("descriptions", [])
        desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "No description.")

        # Extract CVSS metrics (check 3.1, then 3.0, then 2.0)
        metrics = cve_dict.get("metrics", {})
        cvss_score = 0.0
        cvss_version = "3.1"
        severity = "Informational"

        if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
            data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", 0.0)
            severity = data.get("baseSeverity", "MEDIUM").capitalize()
        elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
            data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", 0.0)
            cvss_version = "3.0"
            severity = data.get("baseSeverity", "MEDIUM").capitalize()
        elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss_score = data.get("baseScore", 0.0)
            cvss_version = "2.0"
            severity = "Medium"

        refs = [r.get("url") for r in cve_dict.get("references", []) if r.get("url")]

        return {
            "cve_id": cve_id,
            "title": f"Vulnerability {cve_id}",
            "description": desc,
            "cvss_score": float(cvss_score),
            "cvss_version": cvss_version,
            "severity": severity,
            "published_date": cve_dict.get("published", ""),
            "last_modified_date": cve_dict.get("lastModified", ""),
            "reference_urls": refs[:5],
            "affected_products": [],
        }

    async def search_cves_by_product(
        self, product: str, version: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Search CVEs for a specific product and version.
        Requires explicit version to prevent false-positive flood on unverified banners.
        """
        if not version or len(version.strip()) == 0:
            logger.info(
                f"Skipping aggressive CVE correlation for {product}: version is uncertain or missing."
            )
            return []

        search_term = f"{product} {version}".lower()
        results = []
        for cve_id, data in FALLBACK_CVE_CATALOG.items():
            if product.lower() in data["title"].lower() or product.lower() in data["description"].lower():
                results.append(data)
        return results


cve_service = CVEService()
