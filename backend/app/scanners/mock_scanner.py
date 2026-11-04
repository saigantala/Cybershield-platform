import asyncio
import logging
from typing import Any, Dict, List, Optional

from app.scanners.base import BaseScanner, RawFinding

logger = logging.getLogger(__name__)


class MockVulnerabilityScanner(BaseScanner):
    """
    High-fidelity deterministic mock scanner for development, offline environments, and CI/CD.
    Simulates OpenVAS and ZAP passive discoveries mapped to real CVEs.
    """

    def __init__(self):
        super().__init__(name="CyberShield Diagnostic Mock Engine")

    async def check_health(self) -> Dict[str, Any]:
        return {
            "status": "healthy",
            "scanner": self.name,
            "version": "1.0.0-mock",
            "ready": True,
            "details": "Deterministic simulation mode active for testing and evaluation.",
        }

    async def run_assessment(
        self,
        targets: List[Dict[str, Any]],
        options: Optional[Dict[str, Any]] = None,
    ) -> List[RawFinding]:
        results: List[RawFinding] = []
        options = options or {}

        # Allow tests to request a cancellation or simulated delay
        simulated_delay = options.get("simulated_delay", 0.05)
        if simulated_delay > 0:
            await asyncio.sleep(simulated_delay)

        if options.get("simulate_timeout"):
            raise asyncio.TimeoutError("Simulated scanner timeout exceeded.")

        if options.get("simulate_failure"):
            raise RuntimeError("Underlying scanner worker process terminated unexpectedly.")

        for target in targets:
            asset_id = str(target.get("id", ""))
            os_name = (target.get("operating_system") or "").lower()
            device_type = (target.get("device_type") or "").lower()
            ip_addr = target.get("ip_address") or "target-host"

            # If firewall or FortiOS detected:
            if "forti" in os_name or "router" in device_type:
                results.append(
                    RawFinding(
                        title="Fortinet FortiOS SSL-VPN Remote Code Execution (regreSSHion / Out-of-bounds Write)",
                        description=(
                            "An out-of-bounds write vulnerability in FortiOS fgfmd daemon allows an unauthenticated "
                            "attacker to execute arbitrary code or commands via specially crafted requests."
                        ),
                        severity="Critical",
                        cvss_score=9.8,
                        cvss_version="3.1",
                        cve_id="CVE-2024-21762",
                        affected_service="SSL-VPN Web Portal",
                        affected_version="FortiOS 7.4.2",
                        port=443,
                        protocol="tcp",
                        evidence=f"GET /remote/login HTTP/1.1 on {ip_addr}:443 responded with vulnerable FortiOS header token.",
                        remediation="Upgrade FortiOS to version 7.4.3 or apply the vendor workaround disabling SSL-VPN web interface.",
                        reference_urls=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
                            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                        ],
                        scanner_name=self.name,
                    )
                )

            # Linux / OpenSSH findings:
            if "ubuntu" in os_name or "server" in device_type or "linux" in os_name:
                results.append(
                    RawFinding(
                        title="OpenSSH Signal Handler Race Condition Remote Code Execution (regreSSHion)",
                        description=(
                            "A signal handler race condition was discovered in OpenSSH server (sshd) in glibc-based "
                            "Linux systems where unauthenticated attackers can gain remote code execution as root."
                        ),
                        severity="High",
                        cvss_score=8.1,
                        cvss_version="3.1",
                        cve_id="CVE-2024-6387",
                        affected_service="OpenSSH",
                        affected_version="OpenSSH_8.9p1",
                        port=22,
                        protocol="tcp",
                        evidence=f"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 banner observed on {ip_addr}:22.",
                        remediation="Update OpenSSH to OpenSSH 9.8p1 or newer, or set LoginGraceTime to 0 in sshd_config.",
                        reference_urls=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                            "https://www.openssh.com/txt/release-9.8",
                        ],
                        scanner_name=self.name,
                    )
                )

                # SSH Terrapin Prefix Truncation Attack
                results.append(
                    RawFinding(
                        title="SSH Terrapin Prefix Truncation Attack (ChaCha20-Poly1305 / CBC-EtM)",
                        description=(
                            "The Terrapin attack exploits vulnerabilities in the SSH transport layer protocol to truncate "
                            "messages during the handshake, compromising channel integrity."
                        ),
                        severity="Medium",
                        cvss_score=5.9,
                        cvss_version="3.1",
                        cve_id="CVE-2023-48795",
                        affected_service="OpenSSH",
                        affected_version="OpenSSH_8.9p1",
                        port=22,
                        protocol="tcp",
                        evidence=f"Target {ip_addr}:22 supports chacha20-poly1305@openssh.com without strict key exchange extension.",
                        remediation="Configure sshd to disable ChaCha20-Poly1305 and CBC-EtM ciphers or apply strict KEX patches.",
                        reference_urls=[
                            "https://nvd.nist.gov/vuln/detail/CVE-2023-48795",
                            "https://terrapin-attack.com/",
                        ],
                        scanner_name=self.name,
                    )
                )

            # Web / HTTP passive finding:
            results.append(
                RawFinding(
                    title="Missing Strict-Transport-Security (HSTS) and Content-Security-Policy HTTP Headers",
                    description=(
                        "The remote web server does not enforce HTTPS communication using the HTTP Strict-Transport-Security "
                        "(HSTS) header or restrict content origins via Content-Security-Policy."
                    ),
                    severity="Low",
                    cvss_score=3.7,
                    cvss_version="3.1",
                    cve_id=None,
                    affected_service="HTTP Web Server",
                    affected_version="nginx 1.18.0",
                    port=80,
                    protocol="tcp",
                    evidence=f"HTTP/1.1 response from {ip_addr}:80 lacks 'Strict-Transport-Security' and 'Content-Security-Policy' headers.",
                    remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to reverse proxy configurations.",
                    reference_urls=[
                        "https://owasp.org/www-project-secure-headers/",
                    ],
                    scanner_name=self.name,
                )
            )

        return results

    async def cancel_assessment(self, task_id: str) -> bool:
        logger.info(f"Mock scanner cancelled assessment job {task_id}")
        return True
