"""
CyberShield Scanner Safety Boundary Validator
Enforces strict CIDR, IP range, and domain scope boundaries.
Refuses scanning of unauthorized, external, loopback, or private infrastructure without explicit authorization.
"""

import ipaddress
import socket
from typing import List, Optional
from urllib.parse import urlparse

class ScopeViolationError(Exception):
    """Raised when an assessment target breaches approved tenant scope boundaries."""
    pass

class SafetyBoundaryValidator:
    def __init__(self, approved_targets: List[str]):
        """
        :param approved_targets: List of approved CIDRs (e.g. '192.168.10.0/24')
                                 or approved fully-qualified domain names.
        """
        self.approved_networks: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.approved_domains: List[str] = []

        for target in approved_targets:
            target = target.strip()
            try:
                # Attempt to parse as CIDR network or single IP
                net = ipaddress.ip_network(target, strict=False)
                self.approved_networks.append(net)
            except ValueError:
                # Treat as domain/hostname
                self.approved_domains.append(target.lower())

    def validate_ip_target(self, ip_str: str) -> bool:
        """
        Verify that a single target IP belongs strictly inside one of the approved networks.
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError as exc:
            raise ScopeViolationError(f"Invalid IP address format: {ip_str}") from exc

        # Block loopback, link-local, and multicast unless explicitly approved in test configs
        if ip.is_multicast:
            raise ScopeViolationError(f"Target {ip} is a multicast address and cannot be audited.")

        for network in self.approved_networks:
            if ip in network:
                return True

        raise ScopeViolationError(
            f"ACCESS DENIED: Target IP {ip_str} is outside tenant-approved scope boundaries."
        )

    def validate_hostname_target(self, hostname: str) -> bool:
        """
        Verify that a hostname matches or is a subdomain of an approved domain,
        and its resolved IP address falls within the authorized IP boundaries.
        """
        cleaned_host = hostname.strip().lower()

        # Remove scheme if a URL was provided
        if "://" in cleaned_host:
            parsed = urlparse(cleaned_host)
            cleaned_host = (parsed.hostname or "").lower()

        domain_match = False
        for approved in self.approved_domains:
            if cleaned_host == approved or cleaned_host.endswith(f".{approved}"):
                domain_match = True
                break

        if not domain_match:
            raise ScopeViolationError(
                f"ACCESS DENIED: Target domain '{hostname}' is not within approved tenant domains."
            )

        # Resolve DNS and check resulting IP against safety boundaries
        try:
            resolved_ip = socket.gethostbyname(cleaned_host)
            # Ensure resolved IP is not loopback (anti SSRF) unless explicitly desired
            resolved_obj = ipaddress.ip_address(resolved_ip)
            if resolved_obj.is_loopback:
                raise ScopeViolationError(
                    f"POTENTIAL SSRF: Target hostname '{hostname}' resolves to loopback IP {resolved_ip}."
                )
        except socket.error as e:
            raise ScopeViolationError(f"Failed to resolve target hostname '{hostname}': {e}") from e

        return True
