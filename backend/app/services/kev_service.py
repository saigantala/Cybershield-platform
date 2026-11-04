import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Fallback snapshot of high-profile KEV entries for offline / fast test environments
FALLBACK_KEV_ENTRIES: Dict[str, Dict[str, Any]] = {
    "CVE-2024-21762": {
        "cveID": "CVE-2024-21762",
        "vendorProject": "Fortinet",
        "product": "FortiOS and FortiProxy",
        "vulnerabilityName": "Fortinet FortiOS and FortiProxy Out-of-Bounds Write Vulnerability",
        "dateAdded": "2024-02-09",
        "shortDescription": "Fortinet FortiOS and FortiProxy contain an out-of-bounds write vulnerability that allows an unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
        "requiredAction": "Apply mitigations per vendor instructions or discontinue use of the product if mitigations are unavailable.",
        "dueDate": "2024-02-16",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://www.fortiguard.com/psirt/FG-IR-24-015",
    },
    "CVE-2021-44228": {
        "cveID": "CVE-2021-44228",
        "vendorProject": "Apache",
        "product": "Log4j2",
        "vulnerabilityName": "Apache Log4j2 Deserialization of Untrusted Data Vulnerability",
        "dateAdded": "2021-12-10",
        "shortDescription": "Apache Log4j2 versions 2.0-beta9 through 2.14.1 JNDI features do not protect against attacker-controlled LDAP and other JNDI related endpoints.",
        "requiredAction": "Apply vendor updates immediately.",
        "dueDate": "2021-12-24",
        "knownRansomwareCampaignUse": "Known",
        "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
    },
}


class KEVService:
    """
    CISA Known Exploited Vulnerabilities (KEV) Catalog Service.
    Retrieves and caches the authoritative CISA KEV catalog to flag weaponized
    and actively exploited vulnerabilities in tenant environments.

    NOTE: KEV membership is an indicator of active threat actor exploitation in the wild,
    NOT proof that an individual tenant asset has been compromised.
    """

    def __init__(self):
        self.catalog_url = settings.KEV_CATALOG_URL
        self._catalog: Dict[str, Dict[str, Any]] = dict(FALLBACK_KEV_ENTRIES)
        self._last_refreshed: float = time.time()
        self.refresh_interval = 86400  # 24 hours

    async def refresh_catalog(self, force: bool = False) -> int:
        """Download and refresh the CISA KEV catalog from cisa.gov."""
        now = time.time()
        if not force and (now - self._last_refreshed < self.refresh_interval) and self._catalog:
            return len(self._catalog)

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(self.catalog_url)
                if res.status_code == 200:
                    data = res.json()
                    vulnerabilities = data.get("vulnerabilities", [])
                    new_catalog = {}
                    for item in vulnerabilities:
                        cve = item.get("cveID", "").strip().upper()
                        if cve:
                            new_catalog[cve] = item
                    self._catalog = new_catalog
                    self._last_refreshed = now
                    logger.info(f"Refreshed CISA KEV catalog: {len(new_catalog)} weaponized CVEs loaded.")
                    return len(new_catalog)
        except Exception as e:
            logger.warning(f"Could not refresh CISA KEV catalog from remote URL, using local cache: {e}")

        return len(self._catalog)

    def is_in_kev(self, cve_id: Optional[str]) -> bool:
        """Check if a CVE is listed in the CISA KEV catalog."""
        if not cve_id:
            return False
        return cve_id.strip().upper() in self._catalog

    def get_kev_metadata(self, cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """Retrieve KEV metadata (due date, vendor, required action, ransomware use)."""
        if not cve_id:
            return None
        return self._catalog.get(cve_id.strip().upper())

    def get_all_kev(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Return list of active KEV entries."""
        return list(self._catalog.values())[:limit]


kev_service = KEVService()
