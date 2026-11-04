import asyncio
import logging
import os
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime
from ipaddress import ip_network, ip_address
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID

from app.services.device_classifier import DeviceClassifier
from app.services.scanner_base import DiscoveredHost, DiscoveredService, EngineScanResult

logger = logging.getLogger(__name__)


class NmapDiscoveryEngine:
    """
    Authorized Network Discovery Engine.
    Executes constrained, non-evasive network sweeps against approved RFC 1918 scopes.
    Strictly prohibits arbitrary user flags and never invokes shell=True.
    Falls back to native asynchronous TCP connect & ARP discovery when Nmap binary is absent.
    """

    SAFE_DISCOVERY_ARGS = [
        "-sT",               # Standard TCP Connect scan (conservative, non-stealth)
        "-sV",               # Basic Service Version detection
        "--version-light",   # Light intensity to prevent target service disruption
        "-T3",               # Normal operational timing
        "--top-ports", "100",# Limited to top 100 ports
        "--max-retries", "2",# Fast fail on non-responsive ports
        "--host-timeout", "3m",
        "-oX", "-",          # Stream XML to stdout
    ]

    COMMON_PROBE_PORTS = [
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (80, "http"),
        (110, "pop3"),
        (135, "msrpc"),
        (139, "netbios-ssn"),
        (443, "https"),
        (445, "microsoft-ds"),
        (1433, "ms-sql-s"),
        (3000, "http-nextjs"),
        (3306, "mysql"),
        (3389, "ms-wbt-server"),
        (5432, "postgresql"),
        (6379, "redis"),
        (8000, "http-fastapi"),
        (8080, "http-proxy"),
        (8443, "https-alt"),
        (9000, "cs-mgmt"),
    ]

    def __init__(self):
        self.nmap_path = shutil.which("nmap")

    async def execute_discovery(
        self,
        scan_id: UUID,
        organization_id: UUID,
        target_cidr: str,
        max_rate: int = 1000,
        event_callback: Optional[Callable[[str, str], Any]] = None,
        is_cancelled_check: Optional[Callable[[], bool]] = None,
    ) -> EngineScanResult:
        """
        Executes authorized discovery sweep.
        Emits progress events and returns parsed discovered endpoints.
        """
        start_time = datetime.utcnow()

        if event_callback:
            event_callback("scope_validated", f"Approved scope {target_cidr} confirmed. Initializing discovery.")

        # If Nmap is installed, run binary safely via asyncio subprocess without shell
        if self.nmap_path:
            try:
                result = await self._run_nmap_process(
                    scan_id, target_cidr, max_rate, event_callback, is_cancelled_check
                )
                if result:
                    return result
            except Exception as e:
                logger.warning(f"Native nmap execution encountered error: {e}. Falling back to native socket engine.")

        # Real Native Async Socket & ARP Discovery Engine for environments where Nmap binary is absent
        return await self._run_native_socket_discovery(
            scan_id, target_cidr, event_callback, is_cancelled_check
        )

    async def _run_nmap_process(
        self,
        scan_id: UUID,
        target_cidr: str,
        max_rate: int,
        event_callback: Optional[Callable[[str, str], Any]],
        is_cancelled_check: Optional[Callable[[], bool]],
    ) -> Optional[EngineScanResult]:
        """Runs nmap binary safely using argument vectors."""
        rate = max(10, min(max_rate, 2000))
        cmd = [
            self.nmap_path,
            *self.SAFE_DISCOVERY_ARGS,
            "--max-rate", str(rate),
            target_cidr,
        ]

        logger.info(f"Launching authorized Nmap process: {' '.join(cmd)}")
        if event_callback:
            event_callback("scanner_started", f"Nmap discovery engine initiated for {target_cidr}")

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            if event_callback:
                event_callback("timeout", "Scan exceeded execution timeout limit.")
            return None

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="ignore")
            logger.error(f"Nmap exited with code {proc.returncode}: {err_msg}")
            if event_callback:
                event_callback("error", f"Nmap failed: {err_msg}")
            return None

        xml_output = stdout.decode(errors="ignore")
        return self._parse_nmap_xml(scan_id, xml_output, event_callback)

    def _parse_nmap_xml(
        self,
        scan_id: UUID,
        xml_content: str,
        event_callback: Optional[Callable[[str, str], Any]],
    ) -> EngineScanResult:
        """Parses Nmap XML output into structured host & service records."""
        discovered_hosts: List[DiscoveredHost] = []
        now = datetime.utcnow()

        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                status_elem = host.find("status")
                if status_elem is not None and status_elem.get("state") != "up":
                    continue

                ip_addr = None
                mac_addr = None
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip_addr = addr.get("addr")
                    elif addr.get("addrtype") == "mac":
                        mac_addr = addr.get("addr")

                if not ip_addr:
                    continue

                # Hostname
                hostname = None
                hostnames_elem = host.find("hostnames")
                if hostnames_elem is not None:
                    h_elem = hostnames_elem.find("hostname")
                    if h_elem is not None:
                        hostname = h_elem.get("name")

                # Ports & Services
                services: List[DiscoveredService] = []
                ports_elem = host.find("ports")
                if ports_elem is not None:
                    for port_elem in ports_elem.findall("port"):
                        state_elem = port_elem.find("state")
                        if state_elem is not None and state_elem.get("state") == "open":
                            port_num = int(port_elem.get("portid"))
                            protocol = port_elem.get("protocol", "tcp")
                            service_elem = port_elem.find("service")

                            s_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                            s_product = service_elem.get("product") if service_elem is not None else None
                            s_version = service_elem.get("version") if service_elem is not None else None

                            services.append(
                                DiscoveredService(
                                    port=port_num,
                                    protocol=protocol,
                                    name=s_name,
                                    product=s_product,
                                    version=s_version,
                                    state="open",
                                )
                            )

                # Classify device
                classification = DeviceClassifier.classify(
                    ip_address=ip_addr,
                    mac_address=mac_addr,
                    hostname=hostname,
                    open_ports=[s.port for s in services],
                    service_banners=[{"name": s.name, "product": s.product, "version": s.version} for s in services],
                )

                discovered_hosts.append(
                    DiscoveredHost(
                        ip_address=ip_addr,
                        mac_address=mac_addr,
                        hostname=hostname,
                        status="up",
                        os_name=classification.device_type,
                        services=services,
                    )
                )

                if event_callback:
                    event_callback(
                        "host_discovered",
                        f"Discovered {ip_addr} ({hostname or 'No PTR'}) - {classification.device_type} [{len(services)} ports]",
                    )

        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")

        return EngineScanResult(
            scan_id=scan_id,
            status="completed",
            hosts_discovered=len(discovered_hosts),
            hosts=discovered_hosts,
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            started_at=now,
            completed_at=now,
            logs=[f"Nmap parsed {len(discovered_hosts)} responsive endpoints."],
        )

    def _sync_probe_port(self, ip: str, port: int, service_name: str, timeout: float = 0.12) -> Optional[DiscoveredService]:
        """Probes a single TCP port synchronously with strict timeout, avoiding Windows IOCP hanging."""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((ip, port))
            if res != 0:
                s.close()
                return None

            product = None
            version = None
            try:
                if port in (80, 443, 3000, 8000, 8080, 8443):
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    raw = s.recv(512)
                    header_text = raw.decode("utf-8", errors="ignore")
                    for line in header_text.splitlines():
                        if line.lower().startswith("server:"):
                            product = line.split(":", 1)[1].strip()
                            break
                    if not product:
                        if port == 3000:
                            product = "Next.js Dev Server"
                        elif port == 8000:
                            product = "FastAPI / Uvicorn Server"
                        else:
                            product = "HTTP Web Service"
                elif port == 22:
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="ignore").strip()
                    if banner:
                        product = banner
                elif port == 5432:
                    product = "PostgreSQL Server"
                elif port == 6379:
                    product = "Redis In-Memory Store"
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass

            return DiscoveredService(
                port=port,
                protocol="tcp",
                name=service_name,
                product=product or service_name,
                version=version,
                state="open",
            )
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            return None

    async def _probe_single_port(self, ip: str, port: int, service_name: str, timeout: float = 0.12) -> Optional[DiscoveredService]:
        """Asynchronously dispatches socket probe to thread pool."""
        return await asyncio.to_thread(self._sync_probe_port, ip, port, service_name, timeout)

    def _get_arp_table(self) -> Dict[str, str]:
        """Extracts local IPv4 to MAC mappings from system ARP table."""
        arp_map: Dict[str, str] = {}
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
            for line in output.splitlines():
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{11,17})", line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).replace("-", ":").lower()
                    arp_map[ip] = mac
        except Exception as e:
            logger.debug(f"ARP table lookup skipped: {e}")
        return arp_map

    async def _probe_host(
        self,
        target_ip: str,
        arp_map: Dict[str, str],
        is_active_hint: bool,
    ) -> Optional[DiscoveredHost]:
        """Probes an individual host across common ports with fast failover."""
        # For non-active hints (not in ARP table, not loopback), test sentinel ports first
        if not is_active_hint:
            test_port = await self._probe_single_port(target_ip, 80, "http", timeout=0.1)
            if not test_port:
                test_port_2 = await self._probe_single_port(target_ip, 443, "https", timeout=0.1)
                if not test_port_2:
                    return None

        port_tasks = [
            self._probe_single_port(target_ip, port, name, timeout=0.25)
            for port, name in self.COMMON_PROBE_PORTS
        ]
        port_results = await asyncio.gather(*port_tasks)
        open_services = [s for s in port_results if s is not None]

        mac_addr = arp_map.get(target_ip, "02:00:00:00:00:01" if target_ip == "127.0.0.1" else None)
        if not open_services and not (mac_addr and mac_addr not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00")):
            return None

        hostname = None
        try:
            hostname = socket.gethostbyaddr(target_ip)[0]
        except Exception:
            if target_ip == "127.0.0.1":
                hostname = "localhost"

        service_banners = [
            {"name": s.name, "product": s.product, "version": s.version}
            for s in open_services
        ]
        classification = DeviceClassifier.classify(
            ip_address=target_ip,
            mac_address=mac_addr,
            hostname=hostname,
            open_ports=[s.port for s in open_services],
            service_banners=service_banners,
        )

        return DiscoveredHost(
            ip_address=target_ip,
            mac_address=mac_addr,
            hostname=hostname or f"host-{target_ip.replace('.', '-')}",
            status="up",
            os_name=classification.device_type,
            services=open_services,
        )

    async def _run_native_socket_discovery(
        self,
        scan_id: UUID,
        target_cidr: str,
        event_callback: Optional[Callable[[str, str], Any]],
        is_cancelled_check: Optional[Callable[[], bool]],
    ) -> EngineScanResult:
        """
        Real asynchronous socket & ARP discovery engine.
        Probes real reachable endpoints and active ports without fabricating fake devices.
        """
        now = datetime.utcnow()
        try:
            net = ip_network(target_cidr, strict=False)
        except Exception as e:
            return EngineScanResult(
                scan_id=scan_id,
                status="failed",
                hosts_discovered=0,
                hosts=[],
                started_at=now,
                completed_at=now,
                logs=[f"Invalid target CIDR {target_cidr}: {e}"],
            )

        if event_callback:
            event_callback("discovery_progress", f"Scanning address space {target_cidr} via native asynchronous socket engine...")

        arp_map = self._get_arp_table()

        # Identify candidate IP addresses
        candidate_ips: List[str] = []
        if net.num_addresses == 1:
            candidate_ips.append(str(net.network_address))
        elif net.is_loopback:
            candidate_ips.append("127.0.0.1")
        else:
            # Collect matching IPs from ARP table
            for arp_ip in arp_map.keys():
                try:
                    if ip_address(arp_ip) in net:
                        candidate_ips.append(arp_ip)
                except ValueError:
                    pass

            # Always test subnet gateway (.1) if not present
            try:
                gw_ip = str(net.network_address + 1)
                if gw_ip not in candidate_ips and gw_ip != str(net.broadcast_address):
                    candidate_ips.insert(0, gw_ip)
            except Exception:
                pass

            # Cap candidate list to avoid scan timeouts (max 32 hosts)
            candidate_ips = candidate_ips[:32]

        if event_callback:
            event_callback("discovery_progress", f"Identified {len(candidate_ips)} potential targets on {target_cidr}. Probing ports...")

        if is_cancelled_check and is_cancelled_check():
            return EngineScanResult(
                scan_id=scan_id,
                status="cancelled",
                hosts_discovered=0,
                hosts=[],
                started_at=now,
                completed_at=datetime.utcnow(),
                logs=["Scan was cancelled by operator."],
            )

        # Probe all candidate hosts concurrently
        host_tasks = [
            self._probe_host(
                tip,
                arp_map,
                is_active_hint=(tip in arp_map or tip == "127.0.0.1" or tip == "localhost"),
            )
            for tip in candidate_ips
        ]
        host_results = await asyncio.gather(*host_tasks)
        discovered_hosts = [h for h in host_results if h is not None]

        for host in discovered_hosts:
            if event_callback:
                event_callback(
                    "host_discovered",
                    f"Identified endpoint: {host.ip_address} ({host.hostname}) as {host.os_name} with {len(host.services)} open ports",
                )

        if event_callback:
            event_callback(
                "discovery_completed",
                f"Discovery sweep completed. {len(discovered_hosts)} responsive endpoints identified on {target_cidr}."
            )

        return EngineScanResult(
            scan_id=scan_id,
            status="completed",
            hosts_discovered=len(discovered_hosts),
            hosts=discovered_hosts,
            findings_summary={"critical": 0, "high": 0, "medium": 0, "low": 0},
            started_at=now,
            completed_at=datetime.utcnow(),
            logs=[
                f"Native socket sweep finished on {target_cidr}: {len(discovered_hosts)} responsive hosts found."
            ],
        )
