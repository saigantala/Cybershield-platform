import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import httpx
from fastapi import HTTPException, status

from app.core.config import settings
from app.schemas.asset import AssetCreate, AssetUpdate
from app.schemas.scope import ScopeCreate
from app.scanners.normalizer import NormalizedFinding
from app.threat_intelligence.indicators import IndicatorValidator
from app.threat_intelligence.correlation import correlation_engine
from app.threat_intelligence.feed_manager import feed_manager
from app.services.attack_service import attack_service
from app.services.evidence_service import evidence_service
from app.schemas.incident import IncidentCreate, IncidentUpdate, IncidentEvidenceCreate, PlaybookCreate
from app.billing.plans import DEFAULT_PLANS

logger = logging.getLogger(__name__)


# In-memory test store for local testing when Supabase cloud is not configured
_mock_db: Dict[str, Any] = {
    "organizations": [
        {
            "id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "name": "Apex CyberDefense",
            "slug": "apex-cyberdefense",
            "description": "Enterprise SOC & Managed Threat Defense Operations",
            "website": "https://apexcyberdefense.io",
            "industry": "Cybersecurity & Defense",
            "organization_size": "50-250 employees",
            "country": "US",
            "time_zone": "America/New_York",
            "status": "Active",
            "suspension_reason": None,
            "created_at": "2026-01-01T00:00:00Z",
        }
    ],
    "organization_members": [
        {
            "id": "f5b39a43-089c-4f70-a889-cb4c5b36dc33",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "user_id": "00000000-0000-0000-0000-000000000001",
            "role": "owner",
            "email": "chief.architect@apexcyberdefense.io",
            "full_name": "Chief Security Architect",
            "joined_at": "2026-01-01T00:00:00Z",
            "last_active": "2026-10-31T20:00:00Z",
        },
        {
            "id": "a1b2c3d4-089c-4f70-a889-cb4c5b36dc44",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "user_id": "00000000-0000-0000-0000-000000000002",
            "role": "viewer",
            "email": "auditor@apexcyberdefense.io",
            "full_name": "Compliance Auditor",
            "joined_at": "2026-03-15T00:00:00Z",
            "last_active": "2026-10-30T15:00:00Z",
        },
    ],
    "scan_scopes": [
        {
            "id": "33333333-3333-3333-3333-333333333333",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scope_name": "Core Production Subnet",
            "cidr_range": "192.168.10.0/24",
            "authorization_status": "Approved",
            "authorization_basis": "Signed infrastructure assessment mandate #CYBER-2026-001",
            "approved_by": "00000000-0000-0000-0000-000000000001",
            "approved_at": "2026-01-10T10:00:00Z",
            "expires_at": "2027-01-10T10:00:00Z",
            "max_scan_rate": 1000,
            "created_at": "2026-01-10T09:30:00Z",
        },
        {
            "id": "44444444-4444-4444-4444-444444444444",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scope_name": "Expired Test Scope",
            "cidr_range": "10.0.99.0/24",
            "authorization_status": "Approved",
            "authorization_basis": "Temporary maintenance window",
            "approved_by": "00000000-0000-0000-0000-000000000001",
            "approved_at": "2025-01-01T10:00:00Z",
            "expires_at": "2025-02-01T10:00:00Z",  # Expired
            "max_scan_rate": 500,
            "created_at": "2025-01-01T09:00:00Z",
        },
        {
            "id": "55555555-5555-5555-5555-555555555555",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scope_name": "Pending Approval Subnet",
            "cidr_range": "172.16.50.0/24",
            "authorization_status": "Pending",
            "authorization_basis": "Branch office audit pending CISO signoff",
            "approved_by": None,
            "approved_at": None,
            "expires_at": None,
            "max_scan_rate": 1000,
            "created_at": "2026-10-31T09:00:00Z",
        },
    ],
    "assets": [
        {
            "id": "11111111-1111-1111-1111-111111111111",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "name": "PROD-EDGE-FIREWALL-01",
            "ip_address": "192.168.10.1",
            "mac_address": "52:54:00:8F:90:A1",
            "hostname": "fw-01.edge.nexus.internal",
            "device_type": "Router",
            "operating_system": "FortiOS 7.4.2",
            "manufacturer": "Fortinet",
            "risk_level": "Critical",
            "status": "Active",
            "description": "Primary edge perimeter firewall with SSL-VPN service",
            "created_at": "2026-01-15T09:00:00Z",
            "updated_at": "2026-10-31T14:30:00Z",
            "discovery_method": "manual",
            "confidence": 95,
            "evidence": ["Manual asset baseline"],
        },
        {
            "id": "22222222-2222-2222-2222-222222222222",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "name": "DB-POSTGRES-PRIMARY",
            "ip_address": "192.168.10.45",
            "mac_address": "52:54:00:8F:90:B2",
            "hostname": "pg-primary.prod.nexus.internal",
            "device_type": "Server",
            "operating_system": "Ubuntu 22.04 LTS",
            "manufacturer": "Dell Technologies",
            "risk_level": "High",
            "status": "Active",
            "description": "Primary production transactional database cluster",
            "created_at": "2026-01-20T11:15:00Z",
            "updated_at": "2026-10-31T14:28:00Z",
            "discovery_method": "manual",
            "confidence": 90,
            "evidence": ["Manual asset baseline"],
        },
    ],
    "scans": [],
    "scan_events": [],
    "services": [],
    "asset_interfaces": [],
    "vulnerability_scans": [
        {
            "id": "77777777-7777-7777-7777-777777777777",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scan_scope_id": "33333333-3333-3333-3333-333333333333",
            "scan_type": "openvas",
            "scanner_name": "Greenbone OpenVAS Community Engine",
            "status": "completed",
            "started_at": "2026-10-31T10:00:00Z",
            "completed_at": "2026-10-31T10:14:32Z",
            "total_assets": 2,
            "total_findings": 4,
            "error_message": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T09:59:00Z",
        }
    ],
    "vulnerability_findings": [
        {
            "id": "88888888-8888-8888-8888-888888888888",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scan_id": "77777777-7777-7777-7777-777777777777",
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "asset_name": "PROD-EDGE-FIREWALL-01",
            "asset_ip": "192.168.10.1",
            "title": "Fortinet FortiOS SSL-VPN Out-of-Bounds Write RCE",
            "description": "An out-of-bounds write vulnerability in Fortinet FortiOS allows an unauthenticated attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
            "cve_id": "CVE-2024-21762",
            "cvss_score": 9.8,
            "cvss_version": "3.1",
            "severity": "Critical",
            "prioritization_score": 98.6,
            "affected_service": "SSL-VPN Web Portal",
            "affected_version": "FortiOS 7.4.2",
            "evidence": "GET /remote/login HTTP/1.1 on 192.168.10.1:443 returned vulnerable header token.",
            "remediation": "Upgrade FortiOS to version 7.4.3 or disable the web interface.",
            "reference_urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
                "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            ],
            "is_kev": True,
            "kev_metadata": {
                "cveID": "CVE-2024-21762",
                "dueDate": "2024-02-16",
                "knownRansomwareCampaignUse": "Known",
            },
            "status": "Open",
            "first_detected_at": "2026-10-31T10:05:00Z",
            "last_detected_at": "2026-10-31T10:14:00Z",
            "created_at": "2026-10-31T10:05:00Z",
            "updated_at": "2026-10-31T10:14:00Z",
        },
        {
            "id": "99999999-9999-9999-9999-999999999999",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scan_id": "77777777-7777-7777-7777-777777777777",
            "asset_id": "22222222-2222-2222-2222-222222222222",
            "asset_name": "DB-POSTGRES-PRIMARY",
            "asset_ip": "192.168.10.45",
            "title": "OpenSSH Signal Handler Race Condition RCE (regreSSHion)",
            "description": "A signal handler race condition was discovered in OpenSSH server (sshd) in glibc-based Linux systems where unauthenticated attackers can gain remote code execution as root.",
            "cve_id": "CVE-2024-6387",
            "cvss_score": 8.1,
            "cvss_version": "3.1",
            "severity": "High",
            "prioritization_score": 56.7,
            "affected_service": "OpenSSH",
            "affected_version": "OpenSSH_8.9p1",
            "evidence": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7 banner observed on port 22.",
            "remediation": "Update OpenSSH to OpenSSH 9.8p1 or newer, or set LoginGraceTime to 0 in sshd_config.",
            "reference_urls": [
                "https://nvd.nist.gov/vuln/detail/CVE-2024-6387",
                "https://www.openssh.com/txt/release-9.8",
            ],
            "is_kev": False,
            "kev_metadata": None,
            "status": "In Progress",
            "first_detected_at": "2026-10-31T10:06:00Z",
            "last_detected_at": "2026-10-31T10:14:00Z",
            "created_at": "2026-10-31T10:06:00Z",
            "updated_at": "2026-10-31T10:20:00Z",
        },
        {
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scan_id": "77777777-7777-7777-7777-777777777777",
            "asset_id": "22222222-2222-2222-2222-222222222222",
            "asset_name": "DB-POSTGRES-PRIMARY",
            "asset_ip": "192.168.10.45",
            "title": "SSH Protocol Terrapin Attack (Prefix Truncation)",
            "description": "The Terrapin attack exploits vulnerabilities in the SSH transport layer protocol to truncate handshake messages.",
            "cve_id": "CVE-2023-48795",
            "cvss_score": 5.9,
            "cvss_version": "3.1",
            "severity": "Medium",
            "prioritization_score": 41.3,
            "affected_service": "OpenSSH",
            "affected_version": "OpenSSH_8.9p1",
            "evidence": "Target 192.168.10.45:22 supports chacha20-poly1305 without strict key exchange extension.",
            "remediation": "Disable ChaCha20-Poly1305 and CBC-EtM ciphers or apply strict KEX patches.",
            "reference_urls": ["https://terrapin-attack.com/"],
            "is_kev": False,
            "kev_metadata": None,
            "status": "Open",
            "first_detected_at": "2026-10-31T10:06:00Z",
            "last_detected_at": "2026-10-31T10:14:00Z",
            "created_at": "2026-10-31T10:06:00Z",
            "updated_at": "2026-10-31T10:06:00Z",
        },
        {
            "id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "scan_id": "77777777-7777-7777-7777-777777777777",
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "asset_name": "PROD-EDGE-FIREWALL-01",
            "asset_ip": "192.168.10.1",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "description": "The remote HTTP service does not enforce HTTPS communication using the Strict-Transport-Security header.",
            "cve_id": None,
            "cvss_score": 3.7,
            "cvss_version": "3.1",
            "severity": "Low",
            "prioritization_score": 25.9,
            "affected_service": "HTTP Web Server",
            "affected_version": None,
            "evidence": "HTTP response lacks Strict-Transport-Security header.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to response headers.",
            "reference_urls": ["https://owasp.org/www-project-secure-headers/"],
            "is_kev": False,
            "kev_metadata": None,
            "status": "Resolved",
            "first_detected_at": "2026-10-31T10:07:00Z",
            "last_detected_at": "2026-10-31T10:14:00Z",
            "created_at": "2026-10-31T10:07:00Z",
            "updated_at": "2026-10-31T11:00:00Z",
        }
    ],
    "remediation_history": [
        {
            "id": "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "finding_id": "99999999-9999-9999-9999-999999999999",
            "previous_status": "Open",
            "new_status": "In Progress",
            "notes": "Patch scheduled during Saturday maintenance window.",
            "changed_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T10:20:00Z",
        },
        {
            "id": "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "finding_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "previous_status": "Open",
            "new_status": "Resolved",
            "notes": "Added HSTS header directive to reverse proxy configuration.",
            "changed_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T11:00:00Z",
        }
    ],
    "vulnerability_references": [],
    "threat_indicators": [
        {
            "id": "11000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "indicator_type": "ipv4",
            "indicator_value": "198.51.100.42",
            "source": "abuse.ch URLhaus",
            "threat_category": "c2",
            "confidence": 95,
            "severity": "Critical",
            "first_seen": "2026-10-25T12:00:00Z",
            "last_seen": "2026-10-31T08:00:00Z",
            "expires_at": "2027-01-25T12:00:00Z",
            "description": "Active Cobalt Strike command and control listener observed in phishing campaigns.",
            "reference_url": "https://urlhaus.abuse.ch/host/198.51.100.42/",
            "created_at": "2026-10-25T12:00:00Z",
        },
        {
            "id": "11000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "indicator_type": "domain",
            "indicator_value": "malicious-payload-drop.xyz",
            "source": "abuse.ch URLhaus",
            "threat_category": "phishing",
            "confidence": 90,
            "severity": "High",
            "first_seen": "2026-10-28T09:30:00Z",
            "last_seen": "2026-10-31T11:00:00Z",
            "expires_at": "2027-01-28T09:30:00Z",
            "description": "Credential harvesting domain mimicking corporate SSO portals.",
            "reference_url": "https://urlhaus.abuse.ch/host/malicious-payload-drop.xyz/",
            "created_at": "2026-10-28T09:30:00Z",
        },
        {
            "id": "11000000-0000-0000-0000-000000000003",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "indicator_type": "url",
            "indicator_value": "http://198.51.100.42/payload.bin",
            "source": "abuse.ch URLhaus",
            "threat_category": "malware",
            "confidence": 98,
            "severity": "Critical",
            "first_seen": "2026-10-30T14:15:00Z",
            "last_seen": "2026-10-31T12:00:00Z",
            "expires_at": "2027-01-30T14:15:00Z",
            "description": "Hosted loader delivering LockBit 3.0 ransomware stage.",
            "reference_url": "https://urlhaus.abuse.ch/url/1985110042/",
            "created_at": "2026-10-30T14:15:00Z",
        },
        {
            "id": "11000000-0000-0000-0000-000000000004",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "indicator_type": "sha256",
            "indicator_value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "source": "MalwareBazaar",
            "threat_category": "malware",
            "confidence": 85,
            "severity": "High",
            "first_seen": "2026-10-29T10:00:00Z",
            "last_seen": "2026-10-31T10:00:00Z",
            "expires_at": "2027-01-29T10:00:00Z",
            "description": "Known agent dropper executable identified in APT campaigns.",
            "reference_url": "https://bazaar.abuse.ch/",
            "created_at": "2026-10-29T10:00:00Z",
        }
    ],
    "threat_feeds": [
        {
            "id": "12000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "feed_name": "CISA Known Exploited Vulnerabilities Catalog",
            "feed_provider": "cisa_kev",
            "feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            "is_enabled": True,
            "sync_interval_hours": 24,
            "last_sync_at": "2026-10-31T06:00:00Z",
            "last_sync_status": "success",
            "indicators_count": 1284,
            "error_message": None,
            "created_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "12000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "feed_name": "abuse.ch URLhaus Malicious URLs Feed",
            "feed_provider": "urlhaus",
            "feed_url": "https://urlhaus.abuse.ch/downloads/json_recent/",
            "is_enabled": True,
            "sync_interval_hours": 6,
            "last_sync_at": "2026-10-31T11:30:00Z",
            "last_sync_status": "success",
            "indicators_count": 2450,
            "error_message": None,
            "created_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "12000000-0000-0000-0000-000000000003",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "feed_name": "abuse.ch MalwareBazaar Hashes Feed",
            "feed_provider": "malwarebazaar",
            "feed_url": "https://mb-api.abuse.ch/api/v1/",
            "is_enabled": True,
            "sync_interval_hours": 12,
            "last_sync_at": "2026-10-31T08:00:00Z",
            "last_sync_status": "success",
            "indicators_count": 4820,
            "error_message": None,
            "created_at": "2026-10-01T00:00:00Z",
        },
    ],
    "security_events": [
        {
            "id": "13000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "source": "network_discovery",
            "event_type": "port_discovered",
            "severity": "Informational",
            "source_ip": "192.168.10.1",
            "destination_ip": None,
            "hostname": "fw-01.edge.nexus.internal",
            "username": None,
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "event_description": "Network scan discovered open TCP port 443 (HTTPS SSL-VPN).",
            "event_timestamp": "2026-10-31T14:30:00Z",
            "metadata": {"port": 443, "proto": "tcp"},
            "created_at": "2026-10-31T14:30:00Z",
        },
        {
            "id": "13000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "source": "auth",
            "event_type": "auth_failure",
            "severity": "Medium",
            "source_ip": "203.0.113.88",
            "destination_ip": "192.168.10.1",
            "hostname": "vpn-portal",
            "username": "admin",
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "event_description": "Failed authentication attempt for username 'admin' on VPN gateway.",
            "event_timestamp": "2026-10-31T14:32:00Z",
            "metadata": {"attempt": 1},
            "created_at": "2026-10-31T14:32:00Z",
        },
    ],
    "detection_rules": [
        {
            "id": "10000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "rule_name": "Repeated Authentication Failure Anomaly",
            "description": "Detects multiple failed authentication attempts within a short time window.",
            "severity": "High",
            "rule_type": "auth_failure_threshold",
            "is_enabled": True,
            "threshold": 5,
            "time_window_seconds": 300,
            "event_conditions": {"event_type": "auth_failure", "group_by": "source_ip"},
            "last_triggered_at": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "10000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "rule_name": "Known Threat Indicator Correlation Match",
            "description": "Detects network connection matching active Threat Intelligence IOCs.",
            "severity": "Critical",
            "rule_type": "threat_intel_match",
            "is_enabled": True,
            "threshold": 1,
            "time_window_seconds": 60,
            "event_conditions": {"check_fields": ["source_ip", "destination_ip", "hostname"]},
            "last_triggered_at": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "10000000-0000-0000-0000-000000000003",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "rule_name": "Vulnerability Risk & CISA KEV Exposure Correlation",
            "description": "Correlates critical unmitigated vulnerability discoveries listed in CISA KEV on network assets.",
            "severity": "High",
            "rule_type": "vuln_risk_correlation",
            "is_enabled": True,
            "threshold": 1,
            "time_window_seconds": 3600,
            "event_conditions": {"min_cvss": 7.0, "require_kev": True},
            "last_triggered_at": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "10000000-0000-0000-0000-000000000004",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "rule_name": "Asset Telemetry Volume Spike Anomaly",
            "description": "Identifies statistically abnormal bursts of security events from a single host.",
            "severity": "Medium",
            "rule_type": "asset_anomaly",
            "is_enabled": True,
            "threshold": 20,
            "time_window_seconds": 60,
            "event_conditions": {"group_by": "asset_id"},
            "last_triggered_at": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        },
        {
            "id": "10000000-0000-0000-0000-000000000005",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "rule_name": "Repeated Suspicious Network Activity",
            "description": "Triggers when suspicious port sweeps or non-baseline discovery signals recur.",
            "severity": "High",
            "rule_type": "repeated_suspicious_events",
            "is_enabled": True,
            "threshold": 3,
            "time_window_seconds": 600,
            "event_conditions": {"event_type": "suspicious_traffic"},
            "last_triggered_at": None,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-01T00:00:00Z",
            "updated_at": "2026-10-01T00:00:00Z",
        },
    ],
    "alerts": [
        {
            "id": "14000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "title": "Threat Intelligence Match: C2 Cobalt Strike IP Observed",
            "description": "Outbound egress connection to known Cobalt Strike command and control IP 198.51.100.42 detected from perimeter firewall.",
            "alert_type": "threat_intel_match",
            "severity": "Critical",
            "status": "New",
            "source": "Threat Intel: abuse.ch URLhaus",
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "indicator_id": "11000000-0000-0000-0000-000000000001",
            "rule_id": "10000000-0000-0000-0000-000000000002",
            "related_event_ids": [],
            "assigned_to": None,
            "linked_incident_id": None,
            "confidence": 95,
            "first_detected_at": "2026-10-31T14:00:00Z",
            "last_detected_at": "2026-10-31T14:15:00Z",
            "created_at": "2026-10-31T14:00:00Z",
            "updated_at": "2026-10-31T14:15:00Z",
        },
        {
            "id": "14000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "title": "CISA KEV Weaponized Vulnerability Exposure (Fortinet SSL-VPN)",
            "description": "Asset PROD-EDGE-FIREWALL-01 is exposed to active in-the-wild exploitation via CVE-2024-21762.",
            "alert_type": "vuln_risk_correlation",
            "severity": "High",
            "status": "Investigating",
            "source": "Correlation Engine",
            "asset_id": "11111111-1111-1111-1111-111111111111",
            "indicator_id": None,
            "rule_id": "10000000-0000-0000-0000-000000000003",
            "related_event_ids": [],
            "assigned_to": "00000000-0000-0000-0000-000000000001",
            "linked_incident_id": None,
            "confidence": 90,
            "first_detected_at": "2026-10-31T12:00:00Z",
            "last_detected_at": "2026-10-31T12:00:00Z",
            "created_at": "2026-10-31T12:00:00Z",
            "updated_at": "2026-10-31T13:00:00Z",
        },
    ],
    "alert_notes": [
        {
            "id": "15000000-0000-0000-0000-000000000001",
            "alert_id": "14000000-0000-0000-0000-000000000002",
            "author_id": "00000000-0000-0000-0000-000000000001",
            "note": "Assigned to Lead Security Architect for emergency firewall patch validation.",
            "created_at": "2026-10-31T13:00:00Z",
        }
    ],
    "alert_history": [],
    "incidents": [
        {
            "id": "20000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_number": "CS-2026-000001",
            "title": "Fortinet Edge SSL-VPN Exploitation & C2 Infiltration",
            "description": "Critical vulnerability exploitation attempt targeting PROD-EDGE-FIREWALL-01 matching known CISA KEV CVE-2024-21762 with observed outbound C2 communications.",
            "incident_type": "Vulnerability Exploitation",
            "severity": "Critical",
            "status": "Investigating",
            "priority": "P1",
            "source": "Correlation Engine",
            "assigned_to": "00000000-0000-0000-0000-000000000001",
            "created_by": "00000000-0000-0000-0000-000000000001",
            "affected_assets": ["11111111-1111-1111-1111-111111111111"],
            "detected_at": "2026-10-31T14:15:00Z",
            "acknowledged_at": "2026-10-31T14:20:00Z",
            "investigation_started_at": "2026-10-31T14:22:00Z",
            "resolved_at": None,
            "closed_at": None,
            "resolution_summary": None,
            "created_at": "2026-10-31T14:15:00Z",
            "updated_at": "2026-10-31T14:22:00Z",
        },
    ],
    "incident_alerts": [
        {
            "id": "21000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_id": "20000000-0000-0000-0000-000000000001",
            "alert_id": "14000000-0000-0000-0000-000000000002",
            "linked_by": "00000000-0000-0000-0000-000000000001",
            "linked_at": "2026-10-31T14:16:00Z",
        }
    ],
    "incident_notes": [
        {
            "id": "22000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_id": "20000000-0000-0000-0000-000000000001",
            "author_id": "00000000-0000-0000-0000-000000000001",
            "note": "Incident initiated following CISA KEV correlation match. Initiating memory dump and packet trace inspection.",
            "created_at": "2026-10-31T14:22:00Z",
            "updated_at": "2026-10-31T14:22:00Z",
        }
    ],
    "incident_timeline": [
        {
            "id": "23000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_id": "20000000-0000-0000-0000-000000000001",
            "event_type": "incident_created",
            "description": "Incident CS-2026-000001 opened from correlation alert.",
            "actor_id": "00000000-0000-0000-0000-000000000001",
            "metadata": {},
            "created_at": "2026-10-31T14:15:00Z",
        }
    ],
    "incident_evidence": [],
    "incident_attack_mappings": [
        {
            "id": "24000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_id": "20000000-0000-0000-0000-000000000001",
            "tactic_id": "TA0001",
            "tactic_name": "Initial Access",
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "confidence": 95,
            "evidence": "Observed HTTP POST payload matching CVE-2024-21762 exploit signatures on WAN interface port 10443.",
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T14:25:00Z",
        }
    ],
    "playbooks": [
        {
            "id": "30000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "playbook_name": "Suspicious Login Investigation",
            "category": "authentication",
            "description": "Standard operating procedure for investigating abnormal authentication spikes, credential stuffing, and brute force attempts.",
            "is_enabled": True,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T10:00:00Z",
            "updated_at": "2026-10-31T10:00:00Z",
        },
        {
            "id": "30000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "playbook_name": "Malware Alert Investigation",
            "category": "malware",
            "description": "Response procedure for host-based malware discoveries, C2 beaconing, and malicious payload distribution.",
            "is_enabled": True,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T10:00:00Z",
            "updated_at": "2026-10-31T10:00:00Z",
        },
        {
            "id": "30000000-0000-0000-0000-000000000003",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "playbook_name": "Phishing Investigation",
            "category": "phishing",
            "description": "Triage and remediation protocol for reported phishing emails, domain spoofing, and credential harvesting landing pages.",
            "is_enabled": True,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T10:00:00Z",
            "updated_at": "2026-10-31T10:00:00Z",
        },
        {
            "id": "30000000-0000-0000-0000-000000000004",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "playbook_name": "Vulnerability Incident",
            "category": "vulnerability",
            "description": "Incident investigation workflow for weaponized vulnerability discoveries, zero-days, and CISA KEV exposures.",
            "is_enabled": True,
            "created_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T10:00:00Z",
            "updated_at": "2026-10-31T10:00:00Z",
        },
    ],
    "playbook_steps": [
        {"id": "31000000-0000-0000-0000-000000000001", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 1, "step_title": "Review Authentication Logs", "step_description": "Analyze source IP, geo-location, user-agent, and failed vs successful timestamps.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000002", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 2, "step_title": "Identify Affected Account", "step_description": "Verify account owner, role, privileged access rights, and recent credential changes.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000003", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 3, "step_title": "Review Source IP Reputation", "step_description": "Cross-reference IP against Threat Intelligence IOCs and known proxy/VPN ranges.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000004", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 4, "step_title": "Check Related Alerts", "step_description": "Determine if other services or assets were accessed around the same timeframe.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000005", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 5, "step_title": "Assign Analyst & Conduct User Outreach", "step_description": "Contact account owner via out-of-band communication to verify activity.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000006", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 6, "step_title": "Record Investigation Outcome", "step_description": "Document user confirmation or compromise evidence in incident notes.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000007", "playbook_id": "30000000-0000-0000-0000-000000000001", "step_number": 7, "step_title": "Escalate to Containment if Necessary", "step_description": "Submit a Response Request to disable account or revoke active sessions.", "is_required": False},

        {"id": "31000000-0000-0000-0000-000000000011", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 1, "step_title": "Review Alert Telemetry", "step_description": "Inspect detection signature, file path, process lineage, and parent executable.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000012", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 2, "step_title": "Identify Affected Asset", "step_description": "Locate asset hostname, primary IP, and criticality tier in CyberShield Asset Inventory.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000013", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 3, "step_title": "Check Related Threat Indicators", "step_description": "Verify observed hashes or domain queries against MalwareBazaar and URLhaus.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000014", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 4, "step_title": "Examine Forensic Evidence", "step_description": "Collect memory dump, autorun keys, or network packet captures in Evidence Vault.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000015", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 5, "step_title": "Determine Containment Requirements", "step_description": "Assess risk of lateral movement across internal network subnets.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000016", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 6, "step_title": "Document Findings & Next Steps", "step_description": "Record all forensic findings and remediation recommendations.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000017", "playbook_id": "30000000-0000-0000-0000-000000000002", "step_number": 7, "step_title": "Request Approval for Containment", "step_description": "Submit response request for endpoint isolation or firewall blocking.", "is_required": False},

        {"id": "31000000-0000-0000-0000-000000000021", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 1, "step_title": "Record Reported Email Details", "step_description": "Capture message headers, sender address, subject line, and recipient list.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000022", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 2, "step_title": "Review Sender & Domain Indicators", "step_description": "Verify SPF, DKIM, DMARC alignment and lookup sending domain in Threat Intel.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000023", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 3, "step_title": "Check Related Security Events", "step_description": "Query proxy/web gateway logs to determine whether recipients clicked URLs.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000024", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 4, "step_title": "Identify Potentially Affected Accounts", "step_description": "List all internal users who interacted with or received the phishing payload.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000025", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 5, "step_title": "Record Evidence & SHA-256 Hashes", "step_description": "Upload .eml message file and payload screenshot to Evidence Vault.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000026", "playbook_id": "30000000-0000-0000-0000-000000000003", "step_number": 6, "step_title": "Escalate Confirmed Suspicious Activity", "step_description": "Notify SOC team and initiate password resets for affected users.", "is_required": True},

        {"id": "31000000-0000-0000-0000-000000000031", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 1, "step_title": "Review Affected Asset & Service", "step_description": "Identify exposed port, software banner version, and host network placement.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000032", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 2, "step_title": "Review CVE & CVSS Metrics", "step_description": "Examine CVSS base score, attack complexity, and vendor security advisory.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000033", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 3, "step_title": "Check CISA KEV Status", "step_description": "Confirm if CVE is listed in CISA Known Exploited Vulnerabilities Catalog.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000004", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 4, "step_title": "Assess Exposure Evidence", "step_description": "Review Nmap/OpenVAS scan findings and network reachability evidence.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000035", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 5, "step_title": "Document Remediation Recommendations", "step_description": "Provide patch version, workaround configuration, or WAF virtual patch rule.", "is_required": True},
        {"id": "31000000-0000-0000-0000-000000000036", "playbook_id": "30000000-0000-0000-0000-000000000004", "step_number": 6, "step_title": "Track Remediation & Verification Scan", "step_description": "Verify patch application via targeted rescanning in Scan Center.", "is_required": True},
    ],
    "incident_playbooks": [],
    "playbook_step_progress": [],
    "response_requests": [
        {
            "id": "40000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "incident_id": "20000000-0000-0000-0000-000000000001",
            "action_type": "block_firewall_rule",
            "target_resource": "TCP/10443 on WAN Interface (PROD-EDGE-FIREWALL-01)",
            "justification": "Active exploitation of CVE-2024-21762 detected from external IP 198.51.100.99. Requesting immediate ingress ACL blocking.",
            "status": "Pending",
            "requested_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T14:30:00Z",
            "updated_at": "2026-10-31T14:30:00Z",
        }
    ],
    "response_approvals": [],
    "ai_conversations": [
        {
            "id": "50000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "user_id": "00000000-0000-0000-0000-000000000001",
            "title": "Perimeter Vulnerability Review",
            "created_at": "2026-10-31T12:00:00Z",
            "updated_at": "2026-10-31T12:05:00Z",
        }
    ],
    "ai_messages": [
        {
            "id": "51000000-0000-0000-0000-000000000001",
            "conversation_id": "50000000-0000-0000-0000-000000000001",
            "role": "user",
            "content": "What are my critical vulnerabilities?",
            "source_references": [],
            "created_at": "2026-10-31T12:00:00Z",
        },
        {
            "id": "51000000-0000-0000-0000-000000000002",
            "conversation_id": "50000000-0000-0000-0000-000000000001",
            "role": "assistant",
            "content": "You have 2 critical vulnerabilities identified on `PROD-EDGE-FIREWALL-01`: CVE-2024-21762 (CISA KEV listed) and CVE-2023-48788.",
            "source_references": [
                {
                    "source_type": "vulnerability",
                    "id": "55555555-5555-5555-5555-555555555555",
                    "name": "CVE-2024-21762",
                    "summary": "FortiOS SSL-VPN RCE",
                    "severity": "Critical",
                }
            ],
            "created_at": "2026-10-31T12:00:05Z",
        },
    ],
    "ai_recommendations": [],
    "ai_usage_logs": [
        {
            "id": "52000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "user_id": "00000000-0000-0000-0000-000000000001",
            "provider": "mock",
            "model": "cybershield-soc-mock-v1",
            "endpoint": "chat",
            "input_tokens": 120,
            "output_tokens": 280,
            "total_tokens": 400,
            "estimated_cost": 0.00074,
            "request_status": "success",
            "latency_ms": 45,
            "created_at": "2026-10-31T12:00:05Z",
        }
    ],
    "subscription_plans": list(DEFAULT_PLANS.values()),
    "organization_subscriptions": [
        {
            "id": "70000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "plan_id": DEFAULT_PLANS["PROFESSIONAL"]["id"],
            "plan_name": DEFAULT_PLANS["PROFESSIONAL"]["plan_name"],
            "plan_code": DEFAULT_PLANS["PROFESSIONAL"]["plan_code"],
            "status": "Active",
            "billing_provider": "mock",
            "current_period_start": "2026-10-01T00:00:00Z",
            "current_period_end": "2026-11-01T00:00:00Z",
            "cancel_at_period_end": False,
            "price": DEFAULT_PLANS["PROFESSIONAL"]["price"],
        }
    ],
    "organization_invitations": [
        {
            "id": "71000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "email": "sarah.connor@cyberdefense.org",
            "role": "analyst",
            "status": "Pending",
            "invited_by": "00000000-0000-0000-0000-000000000001",
            "token": "mock_invitation_token_001",
            "expires_at": "2026-11-07T00:00:00Z",
            "created_at": "2026-10-31T12:00:00Z",
        }
    ],
    "api_keys": [
        {
            "id": "72000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "key_name": "Production SOC CI/CD",
            "key_prefix": "cs_live_9f8a",
            "key_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "scopes": ["read:assets", "write:scans", "read:vulnerabilities"],
            "created_at": "2026-10-01T10:00:00Z",
            "expires_at": "2026-12-31T23:59:59Z",
            "last_used_at": "2026-10-31T18:30:00Z",
            "is_revoked": False,
            "created_by": "00000000-0000-0000-0000-000000000001",
        }
    ],
    "platform_audit_logs": [
        {
            "id": "73000000-0000-0000-0000-000000000001",
            "action": "SYSTEM_INITIALIZATION",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "admin_id": "system",
            "reason": "Platform tenant initialization",
            "timestamp": "2026-01-01T00:00:00Z",
        }
    ],
    "compliance_frameworks": [
        {
            "id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "name": "NIST Cybersecurity Framework",
            "version": "2.0",
            "description": "National Institute of Standards and Technology Framework for Improving Critical Infrastructure Cybersecurity",
            "category": "Federal & Critical Infrastructure",
            "total_controls": 5,
        },
        {
            "id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "name": "CIS Critical Security Controls",
            "version": "v8",
            "description": "Center for Internet Security Prescriptive Prioritized Safeguards against widespread cyber attacks",
            "category": "Industry Best Practice",
            "total_controls": 4,
        },
        {
            "id": "80000000-0000-0000-0000-000000000003",
            "framework_code": "OWASP_TOP_10_2021",
            "name": "OWASP Top 10 Application Security",
            "version": "2021",
            "description": "Standard awareness document representing broad consensus on the most critical security risks to web applications",
            "category": "Application Security",
            "total_controls": 4,
        },
        {
            "id": "80000000-0000-0000-0000-000000000004",
            "framework_code": "ISO_27001_2022",
            "name": "ISO/IEC 27001 Information Security",
            "version": "2022",
            "description": "International standard for information security management systems (ISMS)",
            "category": "International Standard",
            "total_controls": 4,
        },
    ],
    "compliance_controls": [
        {
            "id": "81000000-0000-0000-0000-000000000001",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_id": "ID.AM-01",
            "title": "Physical Devices and Systems Inventory",
            "description": "Physical devices and systems within the organization are inventoried and correlated with network discovery telemetry.",
            "domain": "Identify (Asset Management)",
            "remediation_guidance": "Deploy automated Nmap discovery scans across authorized subnets and maintain continuous IP/MAC registers.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000002",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_id": "ID.RA-01",
            "title": "Asset Vulnerability Identification",
            "description": "Asset vulnerabilities are identified, validated against authoritative CVE and CISA KEV feeds, and documented.",
            "domain": "Identify (Risk Assessment)",
            "remediation_guidance": "Execute weekly vulnerability scans and correlate findings with the national CISA KEV catalog.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000003",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_id": "PR.AC-01",
            "title": "Identity and Access Management",
            "description": "Identities and credentials are authenticated and managed for authorized devices and SOC analysts.",
            "domain": "Protect (Access Control)",
            "remediation_guidance": "Enforce MFA across all console operators and rotate API keys on a 90-day schedule.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000004",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_id": "DE.CM-01",
            "title": "Continuous Network Security Monitoring",
            "description": "Networks and physical perimeters are continuously monitored to detect potential cybersecurity events and anomalies.",
            "domain": "Detect (Continuous Monitoring)",
            "remediation_guidance": "Ingest network event telemetry into detection rules engine for automated brute force and IOC correlation.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000005",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_id": "RS.MA-01",
            "title": "Incident Response Plan Execution",
            "description": "The incident management plan is executed during or after an incident to contain and eradicate threats.",
            "domain": "Respond (Incident Management)",
            "remediation_guidance": "Link active alerts to CS-YYYY-XXXXXX incidents and execute standardized MITRE ATT&CK playbooks.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000006",
            "framework_id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "control_id": "CIS-1.1",
            "title": "Enterprise Asset Inventory",
            "description": "Establish and maintain a detailed enterprise asset inventory tracking authorized and unauthorized hardware.",
            "domain": "Asset Management",
            "remediation_guidance": "Run automated network discovery on RFC 1918 subnets and classify host roles.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000007",
            "framework_id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "control_id": "CIS-7.1",
            "title": "Vulnerability Management Process",
            "description": "Establish and maintain a vulnerability management process performing regular automated vulnerability assessments.",
            "domain": "Vulnerability Management",
            "remediation_guidance": "Enforce strict 7-day remediation SLAs for Critical CVEs and 30-day SLAs for High CVEs.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000008",
            "framework_id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "control_id": "CIS-8.1",
            "title": "Audit Log Management Process",
            "description": "Establish and maintain an audit log management process collecting, reviewing, and retaining event logs.",
            "domain": "Audit & Accountability",
            "remediation_guidance": "Stream security events to immutable append-only audit trail.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000009",
            "framework_id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "control_id": "CIS-17.1",
            "title": "Incident Response Management",
            "description": "Establish and maintain an incident response management process to quickly discover, contain, and remediate attacks.",
            "domain": "Incident Response",
            "remediation_guidance": "Utilize CyberShield Incident Response Workspace with digital evidence hashing.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000010",
            "framework_id": "80000000-0000-0000-0000-000000000003",
            "framework_code": "OWASP_TOP_10_2021",
            "control_id": "A01:2021",
            "title": "Broken Access Control Defense",
            "description": "Enforce strict server-side authorization boundaries, deny access by default, and restrict CORS.",
            "domain": "Access Control",
            "remediation_guidance": "Enforce PostgreSQL Row Level Security (RLS) across all tenant collections.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000011",
            "framework_id": "80000000-0000-0000-0000-000000000003",
            "framework_code": "OWASP_TOP_10_2021",
            "control_id": "A03:2021",
            "title": "Injection Vulnerability Mitigation",
            "description": "Prevent SQL injection, command injection, and LDAP injection using parameterized queries and strict input sanitization.",
            "domain": "Input Validation",
            "remediation_guidance": "Use Pydantic input models and parameterized PostgREST queries.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000012",
            "framework_id": "80000000-0000-0000-0000-000000000003",
            "framework_code": "OWASP_TOP_10_2021",
            "control_id": "A05:2021",
            "title": "Security Misconfiguration Hardening",
            "description": "Secure default configurations, disable unneeded ports and services, and remove unnecessary features.",
            "domain": "System Hardening",
            "remediation_guidance": "Scan exposed TCP/UDP ports and isolate perimeter management interfaces.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000013",
            "framework_id": "80000000-0000-0000-0000-000000000003",
            "framework_code": "OWASP_TOP_10_2021",
            "control_id": "A06:2021",
            "title": "Vulnerable and Outdated Components",
            "description": "Continuously inventory client-side and server-side dependencies and monitor for published CVEs.",
            "domain": "Dependency Hygiene",
            "remediation_guidance": "Audit libraries with automated vulnerability scanners.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000014",
            "framework_id": "80000000-0000-0000-0000-000000000004",
            "framework_code": "ISO_27001_2022",
            "control_id": "A.5.9",
            "title": "Inventory of Information and Assets",
            "description": "An inventory of information and other associated assets, including owners, shall be developed and maintained.",
            "domain": "Organizational Controls",
            "remediation_guidance": "Maintain continuous asset inventory with hardware classification and risk levels.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000015",
            "framework_id": "80000000-0000-0000-0000-000000000004",
            "framework_code": "ISO_27001_2022",
            "control_id": "A.8.8",
            "title": "Management of Technical Vulnerabilities",
            "description": "Information about technical vulnerabilities of information systems in use shall be obtained and evaluated.",
            "domain": "Technological Controls",
            "remediation_guidance": "Perform weekly vulnerability scans and track remediation history.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000016",
            "framework_id": "80000000-0000-0000-0000-000000000004",
            "framework_code": "ISO_27001_2022",
            "control_id": "A.8.16",
            "title": "Monitoring Activities",
            "description": "Networks, systems and applications shall be monitored for abnormal behavior and appropriate actions taken.",
            "domain": "Technological Controls",
            "remediation_guidance": "Configure real-time detection rules and automated correlation alerts.",
        },
        {
            "id": "81000000-0000-0000-0000-000000000017",
            "framework_id": "80000000-0000-0000-0000-000000000004",
            "framework_code": "ISO_27001_2022",
            "control_id": "A.8.20",
            "title": "Network Security Controls",
            "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems.",
            "domain": "Perimeter Controls",
            "remediation_guidance": "Enforce approved RFC 1918 scan scopes and perimeter firewall rules.",
        },
    ],
    "compliance_assessments": [
        {
            "id": "82000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "control_id": "81000000-0000-0000-0000-000000000001",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_code": "ID.AM-01",
            "control_title": "Physical Devices and Systems Inventory",
            "status": "Implemented",
            "assigned_owner": "Lead Infrastructure Architect",
            "review_date": "2026-12-15",
            "notes": "Automated network discovery active across all approved subnets.",
            "remediation_notes": "All perimeter assets classified with confidence scores > 90%.",
            "created_at": "2026-10-01T10:00:00Z",
            "updated_at": "2026-10-31T15:00:00Z",
        },
        {
            "id": "82000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "control_id": "81000000-0000-0000-0000-000000000002",
            "framework_id": "80000000-0000-0000-0000-000000000001",
            "framework_code": "NIST_CSF_2_0",
            "control_code": "ID.RA-01",
            "title": "Asset Vulnerability Identification",
            "status": "Partially Implemented",
            "assigned_owner": "Senior Vulnerability Analyst",
            "review_date": "2026-11-20",
            "notes": "Weekly vulnerability scans automated. Integration with secondary air-gapped lab in progress.",
            "remediation_notes": "Pending integration for legacy SCADA subnet.",
            "created_at": "2026-10-01T10:00:00Z",
            "updated_at": "2026-10-31T15:00:00Z",
        },
        {
            "id": "82000000-0000-0000-0000-000000000003",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "control_id": "81000000-0000-0000-0000-000000000006",
            "framework_id": "80000000-0000-0000-0000-000000000002",
            "framework_code": "CIS_CONTROLS_V8",
            "control_code": "CIS-1.1",
            "control_title": "Enterprise Asset Inventory",
            "status": "Implemented",
            "assigned_owner": "Chief Security Architect",
            "review_date": "2026-12-01",
            "notes": "Complete continuous inventory of edge devices and endpoints.",
            "created_at": "2026-10-01T10:00:00Z",
            "updated_at": "2026-10-31T15:00:00Z",
        },
    ],
    "compliance_evidence": [
        {
            "id": "83000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "control_id": "81000000-0000-0000-0000-000000000001",
            "assessment_id": "82000000-0000-0000-0000-000000000001",
            "file_name": "asset_inventory_audit_signed.pdf",
            "file_size": 245120,
            "mime_type": "application/pdf",
            "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "storage_path": "evidence/e4a29a43-089c-4f70-a889-cb4c5b36dc32/audit_signed.pdf",
            "description": "Signed Q3 Asset Inventory Verification Audit",
            "uploaded_by": "00000000-0000-0000-0000-000000000001",
            "uploaded_at": "2026-10-15T12:00:00Z",
        }
    ],
    "security_reports": [
        {
            "id": "84000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "title": "Executive Security Posture Briefing - Q4",
            "report_type": "executive_summary",
            "format": "pdf",
            "status": "Completed",
            "parameters": {"date_range": "30d"},
            "summary_metrics": {"security_score": 78.5, "critical_vulns": 2, "open_incidents": 1},
            "file_size_bytes": 284100,
            "download_url": "/api/v1/reports/84000000-0000-0000-0000-000000000001/download",
            "generated_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-31T18:00:00Z",
            "completed_at": "2026-10-31T18:00:05Z",
        },
        {
            "id": "84000000-0000-0000-0000-000000000002",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "title": "Perimeter Vulnerability Assessment Report",
            "report_type": "vulnerability_assessment",
            "format": "csv",
            "status": "Completed",
            "parameters": {"severity_filter": ["Critical", "High"]},
            "summary_metrics": {"total_findings": 14, "cisa_kev_count": 1},
            "file_size_bytes": 14500,
            "download_url": "/api/v1/reports/84000000-0000-0000-0000-000000000002/download",
            "generated_by": "00000000-0000-0000-0000-000000000001",
            "created_at": "2026-10-30T10:00:00Z",
            "completed_at": "2026-10-30T10:00:02Z",
        }
    ],
    "report_schedules": [],
    "posture_score_history": [
        {
            "id": "85000000-0000-0000-0000-000000000001",
            "organization_id": "e4a29a43-089c-4f70-a889-cb4c5b36dc32",
            "posture_score": 78.5,
            "risk_level": "Low Risk",
            "breakdown": {"vuln_score": 85.0, "asset_score": 80.0, "compliance_score": 70.0},
            "recorded_at": "2026-10-31T12:00:00Z",
        }
    ],
}


class SupabaseService:
    """
    User-scoped Supabase database client.
    Passes user's Bearer token directly to PostgREST to preserve Row Level Security (RLS).
    """

    def __init__(self, user_token: Optional[str] = None):
        self.user_token = user_token
        self._mock_db = _mock_db
        self.is_configured = bool(
            settings.SUPABASE_URL
            and "your-project" not in settings.SUPABASE_URL
            and settings.SUPABASE_ANON_KEY
            and "your-anon" not in settings.SUPABASE_ANON_KEY
        )

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "apikey": settings.SUPABASE_ANON_KEY,
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        if self.user_token:
            headers["Authorization"] = f"Bearer {self.user_token}"
        return headers

    async def get_user_org_membership(self, user_id: str) -> List[Dict[str, Any]]:
        """Returns organizations and roles the user belongs to."""
        if not self.is_configured:
            return [m for m in _mock_db["organization_members"] if m["user_id"] == user_id]

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/organization_members"
        params = {"user_id": f"eq.{user_id}", "select": "organization_id,role"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(url, headers=self._get_headers(), params=params)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.warning(f"Error querying organization memberships: {e}")

        return [m for m in _mock_db["organization_members"] if m["user_id"] == user_id]

    async def verify_org_access(
        self, user_id: str, org_id: str, allowed_roles: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """Verifies organization membership and role."""
        memberships = await self.get_user_org_membership(user_id)
        match = next((m for m in memberships if str(m["organization_id"]) == str(org_id)), None)

        if not match:
            return False, "Not a member of this organization"

        role = match.get("role", "viewer")
        if allowed_roles and role not in allowed_roles:
            return False, f"Role '{role}' is not authorized for this operation"

        return True, role

    # --------------------------------------------------------------------------
    # Scope Management Methods (Sprint 5)
    # --------------------------------------------------------------------------
    async def get_scopes(self, org_id: str) -> List[Dict[str, Any]]:
        """List organization approved/pending network scopes."""
        if not self.is_configured:
            scopes = [s for s in _mock_db["scan_scopes"] if str(s["organization_id"]) == str(org_id)]
            for s in scopes:
                if s.get("expires_at"):
                    try:
                        exp = datetime.fromisoformat(s["expires_at"].replace("Z", "+00:00"))
                        s["is_expired"] = datetime.now(exp.tzinfo) > exp
                    except Exception:
                        s["is_expired"] = False
                else:
                    s["is_expired"] = False
            return scopes

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_scopes"
        params = {"organization_id": f"eq.{org_id}", "select": "*", "order": "created_at.desc"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(url, headers=self._get_headers(), params=params)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.warning(f"Error querying scan scopes: {e}")
        return []

    async def get_scope_by_id(self, org_id: str, scope_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve single scope record."""
        if not self.is_configured:
            scope = next(
                (
                    s
                    for s in _mock_db["scan_scopes"]
                    if str(s["id"]) == str(scope_id) and str(s["organization_id"]) == str(org_id)
                ),
                None,
            )
            if scope and scope.get("expires_at"):
                try:
                    exp = datetime.fromisoformat(scope["expires_at"].replace("Z", "+00:00"))
                    scope["is_expired"] = datetime.now(exp.tzinfo) > exp
                except Exception:
                    scope["is_expired"] = False
            return scope

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_scopes"
        params = {"id": f"eq.{scope_id}", "organization_id": f"eq.{org_id}", "select": "*"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(url, headers=self._get_headers(), params=params)
                if res.status_code == 200 and res.json():
                    return res.json()[0]
        except Exception as e:
            logger.warning(f"Error querying scope by id: {e}")
        return None

    async def create_scope(self, org_id: str, user_id: str, data: ScopeCreate) -> Dict[str, Any]:
        """Submit a new network scope for approval."""
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "target": data.cidr_range,
            "type": "cidr",
            "scope_name": data.scope_name,
            "cidr_range": data.cidr_range,
            "authorization_basis": data.authorization_basis,
            "authorization_status": "Pending",
            "approved_by": None,
            "approved_at": None,
            "expires_at": (datetime.utcnow() + timedelta(days=data.expires_in_days)).isoformat() + "Z",
            "max_scan_rate": data.max_scan_rate,
            "created_at": now,
        }

        if not self.is_configured:
            _mock_db["scan_scopes"].insert(0, record)
            return record

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_scopes"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.post(url, headers=self._get_headers(), json=record)
                if res.status_code in [200, 201] and res.json():
                    return res.json()[0]
        except Exception as e:
            logger.error(f"Error creating scope: {e}")

        _mock_db["scan_scopes"].insert(0, record)
        return record

    async def approve_scope(
        self, org_id: str, scope_id: str, approved_by_id: str, expires_at: Optional[datetime] = None
    ) -> Optional[Dict[str, Any]]:
        """Approve scope for active assessment (restricted to owner/admin)."""
        now = datetime.utcnow().isoformat() + "Z"
        exp = (expires_at or (datetime.utcnow() + timedelta(days=90))).isoformat() + "Z"

        if not self.is_configured:
            scope = await self.get_scope_by_id(org_id, scope_id)
            if scope:
                scope["authorization_status"] = "Approved"
                scope["approved_by"] = approved_by_id
                scope["approved_at"] = now
                scope["expires_at"] = exp
            return scope

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_scopes"
        params = {"id": f"eq.{scope_id}", "organization_id": f"eq.{org_id}"}
        payload = {
            "authorization_status": "Approved",
            "approved_by": approved_by_id,
            "approved_at": now,
            "expires_at": exp,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.patch(url, headers=self._get_headers(), params=params, json=payload)
                if res.status_code == 200 and res.json():
                    return res.json()[0]
        except Exception as e:
            logger.error(f"Error approving scope: {e}")
        return None

    # --------------------------------------------------------------------------
    # Scan Events & Telemetry
    # --------------------------------------------------------------------------
    async def add_scan_event(self, scan_id: str, event_type: str, message: str) -> Dict[str, Any]:
        """Record real-time discovery event for UI timeline."""
        record = {
            "id": str(uuid4()),
            "scan_id": str(scan_id),
            "event_type": event_type,
            "message": message,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        _mock_db["scan_events"].append(record)

        if self.is_configured:
            url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_events"
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(url, headers=self._get_headers(), json=record)
            except Exception as e:
                logger.debug(f"Failed to push scan event to cloud: {e}")

        return record

    async def get_scan_events(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve chronological event timeline for scan."""
        if not self.is_configured:
            return [e for e in _mock_db["scan_events"] if str(e["scan_id"]) == str(scan_id)]

        url = f"{settings.SUPABASE_URL.rstrip('/')}/rest/v1/scan_events"
        params = {"scan_id": f"eq.{scan_id}", "select": "*", "order": "created_at.asc"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                res = await client.get(url, headers=self._get_headers(), params=params)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.warning(f"Error querying scan events: {e}")

        return [e for e in _mock_db["scan_events"] if str(e["scan_id"]) == str(scan_id)]

    # --------------------------------------------------------------------------
    # Asset Synchronization (Safe Upsert)
    # --------------------------------------------------------------------------
    async def synchronize_discovered_host(self, org_id: str, host: Any) -> Dict[str, Any]:
        """
        Safely synchronizes an automatically discovered endpoint into the asset inventory.
        Preserves manually registered descriptions, risk notes, and custom attributes.
        """
        now = datetime.utcnow().isoformat() + "Z"
        existing = next(
            (
                a
                for a in _mock_db["assets"]
                if str(a["organization_id"]) == str(org_id) and a["ip_address"] == host.ip_address
            ),
            None,
        )

        if existing:
            # Safe update: preserve manually registered descriptions & custom risk
            existing["status"] = "Active"
            existing["updated_at"] = now
            if not existing.get("hostname") and host.hostname:
                existing["hostname"] = host.hostname
            if not existing.get("mac_address") and host.mac_address:
                existing["mac_address"] = host.mac_address
            asset_id = existing["id"]
        else:
            # Create new auto-discovered asset
            asset_id = str(uuid4())
            new_asset = {
                "id": asset_id,
                "organization_id": str(org_id),
                "name": host.hostname or f"DISCOVERED-{host.ip_address}",
                "ip_address": host.ip_address,
                "mac_address": host.mac_address,
                "hostname": host.hostname,
                "device_type": (
                    "Server" if any(k in str(host.os_name or "").lower() for k in ["server", "linux", "bsd", "unix"])
                    else "Router" if any(k in str(host.os_name or "").lower() for k in ["router", "cisco", "fortinet", "gateway", "switch"])
                    else "IoT" if any(k in str(host.os_name or "").lower() for k in ["iot", "printer", "camera", "sensor", "embedded"])
                    else "Desktop" if any(k in str(host.os_name or "").lower() for k in ["windows", "desktop", "workstation"])
                    else "Laptop" if any(k in str(host.os_name or "").lower() for k in ["laptop", "macbook"])
                    else "Other"
                ),
                "operating_system": host.os_name,
                "manufacturer": "Auto-Discovered",
                "risk_level": "Unassessed",
                "status": "Active",
                "description": "Automatically identified during authorized network discovery sweep.",
                "discovery_method": "automatic",
                "confidence": 75,
                "evidence": ["Discovered via Nmap TCP Connect / Banner Sweep"],
                "created_at": now,
                "updated_at": now,
            }
            _mock_db["assets"].insert(0, new_asset)

        # Synchronize discovered services (ports)
        for svc in getattr(host, "services", []):
            _mock_db["services"].append({
                "id": str(uuid4()),
                "asset_id": asset_id,
                "port": svc.port,
                "protocol": svc.protocol,
                "service_name": svc.name,
                "service_version": svc.version,
                "state": svc.state,
                "discovered_at": now,
            })

        return {"asset_id": asset_id, "ip_address": host.ip_address}

    # --------------------------------------------------------------------------
    # Existing Asset & Scan CRUD
    # --------------------------------------------------------------------------
    async def get_assets(
        self,
        org_id: str,
        search: Optional[str] = None,
        device_type: Optional[str] = None,
        risk_level: Optional[str] = None,
        status_filter: Optional[str] = None,
        sort_by: str = "updated_at",
        sort_order: str = "desc",
        page: int = 1,
        page_size: int = 10,
    ) -> Tuple[List[Dict[str, Any]], int]:
        assets = [a for a in _mock_db["assets"] if str(a["organization_id"]) == str(org_id)]

        if search and search.strip():
            s = search.lower().strip()
            assets = [
                a
                for a in assets
                if s in a["name"].lower()
                or s in a["ip_address"].lower()
                or (a.get("hostname") and s in a["hostname"].lower())
            ]

        if device_type and device_type != "all":
            assets = [a for a in assets if a["device_type"] == device_type]

        if risk_level and risk_level != "all":
            assets = [a for a in assets if a["risk_level"] == risk_level]

        if status_filter and status_filter != "all":
            assets = [a for a in assets if a["status"] == status_filter]

        is_asc = sort_order == "asc"
        assets.sort(key=lambda x: str(x.get(sort_by, "")), reverse=not is_asc)

        total = len(assets)
        start = (page - 1) * page_size
        end = start + page_size
        return assets[start:end], total

    async def get_asset_by_id(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        return next(
            (
                a
                for a in _mock_db["assets"]
                if str(a["id"]) == str(asset_id) and str(a["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def create_asset(
        self, org_id: str, user_id: str, user_email: str, data: AssetCreate
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "name": data.name,
            "ip_address": data.ip_address,
            "mac_address": data.mac_address,
            "hostname": data.hostname,
            "device_type": data.device_type,
            "operating_system": data.operating_system,
            "manufacturer": data.manufacturer,
            "risk_level": data.risk_level,
            "status": data.status,
            "description": data.description,
            "discovery_method": "manual",
            "confidence": 100,
            "evidence": ["Manual registration by operator"],
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["assets"].insert(0, record)
        return record

    async def update_asset(
        self, org_id: str, asset_id: str, data: AssetUpdate
    ) -> Optional[Dict[str, Any]]:
        asset = await self.get_asset_by_id(org_id, asset_id)
        if not asset:
            return None
        update_data = {k: v for k, v in data.model_dump().items() if v is not None}
        update_data["updated_at"] = datetime.utcnow().isoformat() + "Z"
        asset.update(update_data)
        return asset

    async def delete_asset(self, org_id: str, asset_id: str) -> bool:
        before = len(_mock_db["assets"])
        _mock_db["assets"] = [
            a
            for a in _mock_db["assets"]
            if not (str(a["id"]) == str(asset_id) and str(a["organization_id"]) == str(org_id))
        ]
        return len(_mock_db["assets"]) < before

    async def create_scan_record(
        self,
        org_id: str,
        user_id: str,
        title: str,
        scan_type: str,
        profile: str,
        target_scope: str,
        scope_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "scope_id": scope_id,
            "title": title,
            "type": scan_type,
            "profile": profile,
            "target_scope": target_scope,
            "status": "queued",
            "progress": 0,
            "hosts_discovered": 0,
            "findings_count": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "started_at": now,
            "completed_at": None,
            "initiated_by": user_id,
            "created_at": now,
            "task_id": task_id,
        }
        _mock_db["scans"].insert(0, record)
        return record

    async def get_scan_by_id(self, org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        return next(
            (
                s
                for s in _mock_db["scans"]
                if str(s["id"]) == str(scan_id) and str(s["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def update_scan_state(
        self,
        scan_id: str,
        status: str,
        progress: int,
        hosts_discovered: int = 0,
        error_message: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        scan = next((s for s in _mock_db["scans"] if str(s["id"]) == str(scan_id)), None)
        if scan:
            scan["status"] = status
            scan["progress"] = progress
            scan["hosts_discovered"] = hosts_discovered
            if error_message:
                scan["error_message"] = error_message
            if status in ["completed", "failed", "cancelled"]:
                scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
        return scan

    async def cancel_scan(self, org_id: str, scan_id: str) -> Optional[Dict[str, Any]]:
        scan = await self.get_scan_by_id(org_id, scan_id)
        if scan:
            scan["status"] = "cancelled"
            scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
            await self.add_scan_event(scan_id, "cancelled", "Scan operation cancelled by operator.")
        return scan

    # --------------------------------------------------------------------------
    # Sprint 6: Vulnerability Assessment & Findings Methods
    # --------------------------------------------------------------------------
    async def get_vulnerability_overview(self, org_id: str) -> Dict[str, Any]:
        """Aggregate vulnerability metrics, severity counts, and top affected assets."""
        findings = [
            f for f in _mock_db["vulnerability_findings"]
            if str(f["organization_id"]) == str(org_id)
        ]

        total_findings = len(findings)
        critical_count = sum(1 for f in findings if f["severity"] == "Critical")
        high_count = sum(1 for f in findings if f["severity"] == "High")
        medium_count = sum(1 for f in findings if f["severity"] == "Medium")
        low_count = sum(1 for f in findings if f["severity"] == "Low")
        info_count = sum(1 for f in findings if f["severity"] == "Informational")
        kev_count = sum(1 for f in findings if f.get("is_kev", False))
        resolved_count = sum(1 for f in findings if f.get("status") in ("Resolved", "Accepted Risk", "False Positive"))

        # Asset correlation
        asset_counts: Dict[str, Dict[str, Any]] = {}
        for f in findings:
            aid = str(f["asset_id"])
            if aid not in asset_counts:
                asset_counts[aid] = {
                    "asset_id": aid,
                    "asset_name": f.get("asset_name", "Unknown Host"),
                    "asset_ip": f.get("asset_ip", ""),
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                }
            asset_counts[aid]["total"] += 1
            if f["severity"] == "Critical":
                asset_counts[aid]["critical"] += 1
            elif f["severity"] == "High":
                asset_counts[aid]["high"] += 1

        top_assets = sorted(
            list(asset_counts.values()),
            key=lambda x: (x["critical"], x["high"], x["total"]),
            reverse=True,
        )[:5]

        latest_scan = next(
            (s for s in _mock_db["vulnerability_scans"] if str(s["organization_id"]) == str(org_id)),
            None,
        )

        return {
            "total_findings": total_findings,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "informational_count": info_count,
            "kev_count": kev_count,
            "resolved_count": resolved_count,
            "severity_distribution": {
                "Critical": critical_count,
                "High": high_count,
                "Medium": medium_count,
                "Low": low_count,
                "Informational": info_count,
            },
            "top_affected_assets": top_assets,
            "latest_scan": latest_scan,
        }

    async def get_vulnerability_findings(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        is_kev: Optional[bool] = None,
        asset_id: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        """List and filter vulnerability findings."""
        findings = [
            f for f in _mock_db["vulnerability_findings"]
            if str(f["organization_id"]) == str(org_id)
        ]

        if severity and severity != "all":
            findings = [f for f in findings if f["severity"].lower() == severity.lower()]
        if status and status != "all":
            findings = [f for f in findings if f["status"].lower() == status.lower()]
        if is_kev is not None:
            findings = [f for f in findings if f.get("is_kev") is is_kev]
        if asset_id:
            findings = [f for f in findings if str(f["asset_id"]) == str(asset_id)]
        if search:
            q = search.lower()
            findings = [
                f for f in findings
                if q in f["title"].lower()
                or (f.get("cve_id") and q in f["cve_id"].lower())
                or (f.get("asset_name") and q in f["asset_name"].lower())
                or (f.get("asset_ip") and q in f["asset_ip"].lower())
            ]

        total = len(findings)
        start = (page - 1) * page_size
        paginated = findings[start : start + page_size]

        return {
            "items": paginated,
            "total": total,
            "page": page,
            "page_size": page_size,
        }

    async def get_vulnerability_finding_by_id(
        self, org_id: str, finding_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                f for f in _mock_db["vulnerability_findings"]
                if str(f["id"]) == str(finding_id) and str(f["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def get_vulnerability_findings_by_asset(
        self, org_id: str, asset_id: str
    ) -> List[Dict[str, Any]]:
        return [
            f for f in _mock_db["vulnerability_findings"]
            if str(f["organization_id"]) == str(org_id) and str(f["asset_id"]) == str(asset_id)
        ]

    async def update_vulnerability_finding(
        self, org_id: str, finding_id: str, update_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        finding = await self.get_vulnerability_finding_by_id(org_id, finding_id)
        if not finding:
            return None
        finding.update(update_data)
        finding["updated_at"] = datetime.utcnow().isoformat() + "Z"
        return finding

    async def add_remediation_history(
        self,
        org_id: str,
        finding_id: str,
        previous_status: str,
        new_status: str,
        notes: Optional[str],
        changed_by: Optional[str],
    ) -> Dict[str, Any]:
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "finding_id": str(finding_id),
            "previous_status": previous_status,
            "new_status": new_status,
            "notes": notes,
            "changed_by": changed_by,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        _mock_db["remediation_history"].insert(0, record)
        return record

    async def get_remediation_history(
        self, org_id: str, finding_id: str
    ) -> List[Dict[str, Any]]:
        return [
            r for r in _mock_db["remediation_history"]
            if str(r["organization_id"]) == str(org_id) and str(r["finding_id"]) == str(finding_id)
        ]

    async def create_vulnerability_scan_record(
        self,
        org_id: str,
        user_id: str,
        scope_id: Optional[str],
        scan_type: str,
        scanner_name: str,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "scan_scope_id": scope_id,
            "scan_type": scan_type,
            "scanner_name": scanner_name,
            "status": "queued",
            "started_at": now,
            "completed_at": None,
            "total_assets": 0,
            "total_findings": 0,
            "error_message": None,
            "created_by": user_id,
            "created_at": now,
        }
        _mock_db["vulnerability_scans"].insert(0, record)
        return record

    async def get_vulnerability_scans(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            s for s in _mock_db["vulnerability_scans"]
            if str(s["organization_id"]) == str(org_id)
        ]

    async def get_vulnerability_scan_by_id(
        self, org_id: str, scan_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                s for s in _mock_db["vulnerability_scans"]
                if str(s["id"]) == str(scan_id) and str(s["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def update_vulnerability_scan_state(
        self,
        scan_id: str,
        status: str,
        total_assets: int = 0,
        total_findings: int = 0,
        error_message: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        scan = next(
            (s for s in _mock_db["vulnerability_scans"] if str(s["id"]) == str(scan_id)),
            None,
        )
        if scan:
            scan["status"] = status
            if total_assets > 0:
                scan["total_assets"] = total_assets
            if total_findings > 0:
                scan["total_findings"] = total_findings
            if error_message:
                scan["error_message"] = error_message
            if status in ("completed", "failed", "cancelled"):
                scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
        return scan

    async def cancel_vulnerability_scan(
        self, org_id: str, scan_id: str
    ) -> Optional[Dict[str, Any]]:
        scan = await self.get_vulnerability_scan_by_id(org_id, scan_id)
        if scan:
            scan["status"] = "cancelled"
            scan["completed_at"] = datetime.utcnow().isoformat() + "Z"
        return scan

    async def synchronize_vulnerability_findings(
        self,
        org_id: str,
        scan_id: str,
        normalized_findings: List[NormalizedFinding],
    ) -> Dict[str, int]:
        """
        Deduplicates and persists normalized findings into vulnerability_findings.
        If a finding with same (asset_id, cve_id, title) exists:
          - updates last_detected_at, evidence, prioritization_score
          - preserves existing status if user has acknowledged or resolved it
        If new:
          - creates with status 'Open'
        """
        created = 0
        updated = 0
        now = datetime.utcnow().isoformat() + "Z"

        for nf in normalized_findings:
            # Match existing finding on asset_id and cve_id or title
            existing = next(
                (
                    f for f in _mock_db["vulnerability_findings"]
                    if str(f["organization_id"]) == str(org_id)
                    and str(f["asset_id"]) == str(nf.asset_id)
                    and (
                        (nf.cve_id and f.get("cve_id") == nf.cve_id)
                        or (not nf.cve_id and f.get("title") == nf.title)
                    )
                ),
                None,
            )

            # Retrieve asset info for denormalization
            asset = await self.get_asset_by_id(org_id, nf.asset_id)
            asset_name = asset.get("name") if asset else "Discovered Host"
            asset_ip = str(asset.get("ip_address")) if asset else ""

            if existing:
                existing["last_detected_at"] = now
                existing["scan_id"] = str(scan_id)
                existing["evidence"] = nf.evidence
                existing["remediation"] = nf.remediation
                existing["prioritization_score"] = nf.prioritization_score
                existing["is_kev"] = nf.is_kev
                if nf.kev_metadata:
                    existing["kev_metadata"] = nf.kev_metadata
                updated += 1
            else:
                new_finding = {
                    "id": str(uuid4()),
                    "organization_id": str(org_id),
                    "scan_id": str(scan_id),
                    "asset_id": str(nf.asset_id),
                    "asset_name": asset_name,
                    "asset_ip": asset_ip,
                    "title": nf.title,
                    "description": nf.description,
                    "cve_id": nf.cve_id,
                    "cvss_score": nf.cvss_score,
                    "cvss_version": nf.cvss_version,
                    "severity": nf.severity,
                    "prioritization_score": nf.prioritization_score,
                    "affected_service": nf.affected_service,
                    "affected_version": nf.affected_version,
                    "evidence": nf.evidence,
                    "remediation": nf.remediation,
                    "reference_urls": nf.reference_urls,
                    "is_kev": nf.is_kev,
                    "kev_metadata": nf.kev_metadata,
                    "status": "Open",
                    "first_detected_at": now,
                    "last_detected_at": now,
                    "created_at": now,
                    "updated_at": now,
                }
                _mock_db["vulnerability_findings"].insert(0, new_finding)
                created += 1

        return {"created": created, "updated": updated, "total": len(normalized_findings)}

    # --------------------------------------------------------------------------
    # Sprint 7: Threat Intelligence Methods
    # --------------------------------------------------------------------------
    async def get_threat_intel_overview(self, org_id: str) -> Dict[str, Any]:
        """Calculates IOC distribution, counts by type, and high confidence indicators."""
        indicators = [
            i for i in _mock_db["threat_indicators"]
            if str(i["organization_id"]) == str(org_id)
        ]

        total = len(indicators)
        ips = sum(1 for i in indicators if i["indicator_type"] in ("ipv4", "ipv6"))
        domains = sum(1 for i in indicators if i["indicator_type"] == "domain")
        urls = sum(1 for i in indicators if i["indicator_type"] == "url")
        hashes = sum(1 for i in indicators if i["indicator_type"] in ("sha256", "sha1", "md5"))
        high_conf = sum(1 for i in indicators if i.get("confidence", 0) >= 90)

        type_dist = {
            "ipv4": sum(1 for i in indicators if i["indicator_type"] == "ipv4"),
            "domain": domains,
            "url": urls,
            "hash": hashes,
        }

        recent = sorted(indicators, key=lambda x: x["created_at"], reverse=True)[:5]

        feeds = [f for f in _mock_db["threat_feeds"] if str(f["organization_id"]) == str(org_id)]

        return {
            "total_indicators": total,
            "malicious_ips": ips,
            "malicious_domains": domains,
            "malicious_urls": urls,
            "malicious_hashes": hashes,
            "high_confidence_count": high_conf,
            "feed_updates_count": len(feeds),
            "type_distribution": type_dist,
            "recent_indicators": recent,
        }

    async def get_threat_indicators(
        self,
        org_id: str,
        indicator_type: Optional[str] = None,
        severity: Optional[str] = None,
        threat_category: Optional[str] = None,
        source: Optional[str] = None,
        search: Optional[str] = None,
        min_confidence: Optional[int] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        items = [
            i for i in _mock_db["threat_indicators"]
            if str(i["organization_id"]) == str(org_id)
        ]

        if indicator_type and indicator_type != "all":
            items = [i for i in items if i["indicator_type"].lower() == indicator_type.lower()]
        if severity and severity != "all":
            items = [i for i in items if i["severity"].lower() == severity.lower()]
        if threat_category and threat_category != "all":
            items = [i for i in items if i["threat_category"].lower() == threat_category.lower()]
        if source and source != "all":
            items = [i for i in items if source.lower() in i["source"].lower()]
        if min_confidence is not None:
            items = [i for i in items if i.get("confidence", 0) >= min_confidence]
        if search:
            q = search.lower()
            items = [
                i for i in items
                if q in i["indicator_value"].lower() or (i.get("description") and q in i["description"].lower())
            ]

        total = len(items)
        start = (page - 1) * page_size
        paginated = items[start : start + page_size]

        return {"items": paginated, "total": total, "page": page, "page_size": page_size}

    async def get_threat_indicator_by_id(
        self, org_id: str, indicator_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                i for i in _mock_db["threat_indicators"]
                if str(i["id"]) == str(indicator_id) and str(i["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def create_threat_indicator(
        self, org_id: str, data: Any
    ) -> Dict[str, Any]:
        """Validates, standardizes, deduplicates, and stores an IOC."""
        raw_val = data.indicator_value
        raw_type = data.indicator_type

        # Validate & normalize
        norm_val = IndicatorValidator.validate_and_normalize(raw_type, raw_val)

        # Check duplicate
        existing = next(
            (
                i for i in _mock_db["threat_indicators"]
                if str(i["organization_id"]) == str(org_id)
                and i["indicator_type"] == raw_type
                and i["indicator_value"].lower() == norm_val.lower()
            ),
            None,
        )
        now = datetime.utcnow().isoformat() + "Z"

        if existing:
            existing["last_seen"] = now
            existing["confidence"] = max(existing.get("confidence", 80), data.confidence)
            return existing

        expires_at = None
        if data.expires_in_days:
            expires_at = (datetime.utcnow() + timedelta(days=data.expires_in_days)).isoformat() + "Z"

        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "indicator_type": raw_type,
            "indicator_value": norm_val,
            "source": data.source,
            "threat_category": data.threat_category,
            "confidence": data.confidence,
            "severity": data.severity,
            "first_seen": now,
            "last_seen": now,
            "expires_at": expires_at,
            "description": data.description,
            "reference_url": data.reference_url,
            "created_at": now,
        }
        _mock_db["threat_indicators"].insert(0, record)
        return record

    async def delete_threat_indicator(self, org_id: str, indicator_id: str) -> bool:
        before = len(_mock_db["threat_indicators"])
        _mock_db["threat_indicators"] = [
            i for i in _mock_db["threat_indicators"]
            if not (str(i["id"]) == str(indicator_id) and str(i["organization_id"]) == str(org_id))
        ]
        return len(_mock_db["threat_indicators"]) < before

    # --------------------------------------------------------------------------
    # Threat Feeds Methods
    # --------------------------------------------------------------------------
    async def get_threat_feeds(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            f for f in _mock_db["threat_feeds"]
            if str(f["organization_id"]) == str(org_id)
        ]

    async def sync_threat_feed(self, org_id: str, feed_id: str) -> Dict[str, Any]:
        feed = next(
            (
                f for f in _mock_db["threat_feeds"]
                if str(f["id"]) == str(feed_id) and str(f["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not feed:
            return {"status": "error", "message": "Threat feed not found"}

        now = datetime.utcnow().isoformat() + "Z"
        feed["last_sync_status"] = "running"
        res = await feed_manager.sync_feed(feed["feed_provider"])
        feed["last_sync_at"] = now
        feed["last_sync_status"] = "success"
        feed["indicators_count"] = feed.get("indicators_count", 0) + res.get("indicators_ingested", 0)
        return feed

    # --------------------------------------------------------------------------
    # Security Events Methods
    # --------------------------------------------------------------------------
    async def get_security_events(
        self,
        org_id: str,
        source: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        asset_id: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        events = [
            e for e in _mock_db["security_events"]
            if str(e["organization_id"]) == str(org_id)
        ]

        if source and source != "all":
            events = [e for e in events if e["source"].lower() == source.lower()]
        if severity and severity != "all":
            events = [e for e in events if e["severity"].lower() == severity.lower()]
        if event_type and event_type != "all":
            events = [e for e in events if e["event_type"].lower() == event_type.lower()]
        if asset_id:
            events = [e for e in events if str(e.get("asset_id")) == str(asset_id)]
        if search:
            q = search.lower()
            events = [
                e for e in events
                if q in e["event_description"].lower()
                or (e.get("source_ip") and q in e["source_ip"].lower())
                or (e.get("hostname") and q in e["hostname"].lower())
            ]

        total = len(events)
        start = (page - 1) * page_size
        paginated = events[start : start + page_size]
        return {"items": paginated, "total": total, "page": page, "page_size": page_size}

    async def get_security_event_by_id(
        self, org_id: str, event_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                e for e in _mock_db["security_events"]
                if str(e["id"]) == str(event_id) and str(e["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def create_security_event(
        self, org_id: str, data: Any
    ) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        """
        Stores a normalized security event and immediately evaluates correlation rules.
        Returns (new_event, generated_alerts).
        """
        now = datetime.utcnow().isoformat() + "Z"
        ts = data.event_timestamp.isoformat() + "Z" if data.event_timestamp else now

        event_record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "source": data.source,
            "event_type": data.event_type,
            "severity": data.severity,
            "source_ip": data.source_ip,
            "destination_ip": data.destination_ip,
            "hostname": data.hostname,
            "username": data.username,
            "asset_id": str(data.asset_id) if data.asset_id else None,
            "event_description": data.event_description,
            "event_timestamp": ts,
            "metadata": data.metadata,
            "created_at": now,
        }
        _mock_db["security_events"].insert(0, event_record)

        # Trigger correlation engine
        recent_events = [e for e in _mock_db["security_events"] if str(e["organization_id"]) == str(org_id)]
        rules = [r for r in _mock_db["detection_rules"] if str(r["organization_id"]) == str(org_id) and r.get("is_enabled", True)]
        indicators = [i for i in _mock_db["threat_indicators"] if str(i["organization_id"]) == str(org_id)]
        existing_alerts = [a for a in _mock_db["alerts"] if str(a["organization_id"]) == str(org_id)]

        new_alerts = correlation_engine.evaluate(
            new_event=event_record,
            recent_events=recent_events,
            rules=rules,
            indicators=indicators,
            existing_alerts=existing_alerts,
        )

        for alert in new_alerts:
            _mock_db["alerts"].insert(0, alert)
            # Update last_triggered_at on matched rule
            if alert.get("rule_id"):
                rule = next((r for r in rules if str(r["id"]) == str(alert["rule_id"])), None)
                if rule:
                    rule["last_triggered_at"] = now

        return event_record, new_alerts

    # --------------------------------------------------------------------------
    # Detection Rules Methods
    # --------------------------------------------------------------------------
    async def get_detection_rules(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            r for r in _mock_db["detection_rules"]
            if str(r["organization_id"]) == str(org_id)
        ]

    async def get_detection_rule_by_id(
        self, org_id: str, rule_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                r for r in _mock_db["detection_rules"]
                if str(r["id"]) == str(rule_id) and str(r["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def create_detection_rule(
        self, org_id: str, user_id: str, data: Any
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        rule = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "rule_name": data.rule_name,
            "description": data.description,
            "severity": data.severity,
            "rule_type": data.rule_type,
            "is_enabled": data.is_enabled,
            "threshold": data.threshold,
            "time_window_seconds": data.time_window_seconds,
            "event_conditions": data.event_conditions,
            "last_triggered_at": None,
            "created_by": user_id,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["detection_rules"].insert(0, rule)
        return rule

    async def update_detection_rule(
        self, org_id: str, rule_id: str, data: Any
    ) -> Optional[Dict[str, Any]]:
        rule = await self.get_detection_rule_by_id(org_id, rule_id)
        if not rule:
            return None
        updates = {k: v for k, v in data.model_dump().items() if v is not None}
        updates["updated_at"] = datetime.utcnow().isoformat() + "Z"
        rule.update(updates)
        return rule

    async def toggle_detection_rule(
        self, org_id: str, rule_id: str, is_enabled: bool
    ) -> Optional[Dict[str, Any]]:
        rule = await self.get_detection_rule_by_id(org_id, rule_id)
        if not rule:
            return None
        rule["is_enabled"] = is_enabled
        rule["updated_at"] = datetime.utcnow().isoformat() + "Z"
        return rule

    # --------------------------------------------------------------------------
    # Alert Management Methods
    # --------------------------------------------------------------------------
    async def get_alerts(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source: Optional[str] = None,
        asset_id: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        alerts = [
            a for a in _mock_db["alerts"]
            if str(a["organization_id"]) == str(org_id)
        ]

        if severity and severity != "all":
            alerts = [a for a in alerts if a["severity"].lower() == severity.lower()]
        if status and status != "all":
            alerts = [a for a in alerts if a["status"].lower() == status.lower()]
        if source and source != "all":
            alerts = [a for a in alerts if source.lower() in a["source"].lower()]
        if asset_id:
            alerts = [a for a in alerts if str(a.get("asset_id")) == str(asset_id)]
        if search:
            q = search.lower()
            alerts = [
                a for a in alerts
                if q in a["title"].lower() or q in a["description"].lower()
            ]

        total = len(alerts)
        start = (page - 1) * page_size
        paginated = alerts[start : start + page_size]
        return {"items": paginated, "total": total, "page": page, "page_size": page_size}

    async def get_alert_by_id(
        self, org_id: str, alert_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (
                a for a in _mock_db["alerts"]
                if str(a["id"]) == str(alert_id) and str(a["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def update_alert(
        self, org_id: str, alert_id: str, update_data: Dict[str, Any], changed_by: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not alert:
            return None
        old_status = alert["status"]
        alert.update(update_data)
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"

        # Record history if status changed
        if "status" in update_data and update_data["status"] != old_status:
            _mock_db["alert_history"].insert(
                0,
                {
                    "id": str(uuid4()),
                    "alert_id": str(alert_id),
                    "changed_by": changed_by,
                    "action": "status_change",
                    "previous_state": {"status": old_status},
                    "new_state": {"status": update_data["status"]},
                    "notes": f"Alert status transitioned to {update_data['status']}",
                    "created_at": datetime.utcnow().isoformat() + "Z",
                },
            )
        return alert

    async def assign_alert(
        self, org_id: str, alert_id: str, assigned_to: str, changed_by: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not alert:
            return None
        old_assignee = alert.get("assigned_to")
        alert["assigned_to"] = str(assigned_to)
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"

        _mock_db["alert_history"].insert(
            0,
            {
                "id": str(uuid4()),
                "alert_id": str(alert_id),
                "changed_by": changed_by,
                "action": "assignment",
                "previous_state": {"assigned_to": old_assignee},
                "new_state": {"assigned_to": str(assigned_to)},
                "notes": f"Alert assigned to user {assigned_to}",
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        return alert

    async def add_alert_note(
        self, org_id: str, alert_id: str, author_id: str, note: str
    ) -> Optional[Dict[str, Any]]:
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not alert:
            return None

        record = {
            "id": str(uuid4()),
            "alert_id": str(alert_id),
            "author_id": str(author_id),
            "note": note,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        _mock_db["alert_notes"].insert(0, record)
        return record

    async def get_alert_notes(
        self, org_id: str, alert_id: str
    ) -> List[Dict[str, Any]]:
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not alert:
            return []
        return [
            n for n in _mock_db["alert_notes"]
            if str(n["alert_id"]) == str(alert_id)
        ]

    async def link_alert_incident(
        self, org_id: str, alert_id: str, incident_id: str, changed_by: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not alert:
            return None

        alert["linked_incident_id"] = str(incident_id)
        alert["status"] = "Escalated"
        alert["updated_at"] = datetime.utcnow().isoformat() + "Z"

        _mock_db["alert_history"].insert(
            0,
            {
                "id": str(uuid4()),
                "alert_id": str(alert_id),
                "changed_by": changed_by,
                "action": "incident_link",
                "previous_state": {"linked_incident_id": None},
                "new_state": {"linked_incident_id": str(incident_id), "status": "Escalated"},
                "notes": f"Alert escalated and linked to Incident {incident_id}",
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
        )
        return alert

    # --------------------------------------------------------------------------
    # Sprint 8: Incident Management & Security Operations
    # --------------------------------------------------------------------------
    async def generate_incident_number(self, org_id: str) -> str:
        """Generates a sequential readable incident number per org, e.g. CS-2026-000002."""
        org_incidents = [
            i for i in _mock_db["incidents"]
            if str(i["organization_id"]) == str(org_id)
        ]
        year = datetime.utcnow().year
        seq = len(org_incidents) + 1
        return f"CS-{year}-{seq:06d}"

    async def get_incidents(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        incident_type: Optional[str] = None,
        assigned_to: Optional[str] = None,
        search: Optional[str] = None,
        page: int = 1,
        page_size: int = 50,
    ) -> Dict[str, Any]:
        items = [
            i for i in _mock_db["incidents"]
            if str(i["organization_id"]) == str(org_id)
        ]

        if severity and severity != "all":
            items = [i for i in items if i["severity"].lower() == severity.lower()]
        if status and status != "all":
            items = [i for i in items if i["status"].lower() == status.lower()]
        if incident_type and incident_type != "all":
            items = [i for i in items if i["incident_type"].lower() == incident_type.lower()]
        if assigned_to and assigned_to != "all":
            items = [i for i in items if str(i.get("assigned_to")) == str(assigned_to)]
        if search:
            q = search.lower()
            items = [
                i for i in items
                if q in i["incident_number"].lower()
                or q in i["title"].lower()
                or (i.get("description") and q in i["description"].lower())
            ]

        # Sort newest first
        items.sort(key=lambda x: x["created_at"], reverse=True)
        total = len(items)
        start = (page - 1) * page_size
        paginated = items[start : start + page_size]

        # Attach count metadata
        enriched = []
        for inc in paginated:
            inc_id = inc["id"]
            inc_copy = dict(inc)
            inc_copy["linked_alerts_count"] = sum(1 for a in _mock_db["incident_alerts"] if a["incident_id"] == inc_id)
            inc_copy["notes_count"] = sum(1 for n in _mock_db["incident_notes"] if n["incident_id"] == inc_id)
            inc_copy["evidence_count"] = sum(1 for e in _mock_db["incident_evidence"] if e["incident_id"] == inc_id)
            inc_copy["attack_mappings_count"] = sum(1 for m in _mock_db["incident_attack_mappings"] if m["incident_id"] == inc_id)
            enriched.append(inc_copy)

        return {"items": enriched, "total": total, "page": page, "page_size": page_size}

    async def get_incident_by_id(self, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        inc = next(
            (
                i for i in _mock_db["incidents"]
                if str(i["id"]) == str(incident_id) and str(i["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not inc:
            return None

        inc_copy = dict(inc)
        inc_copy["linked_alerts_count"] = sum(1 for a in _mock_db["incident_alerts"] if a["incident_id"] == str(incident_id))
        inc_copy["notes_count"] = sum(1 for n in _mock_db["incident_notes"] if n["incident_id"] == str(incident_id))
        inc_copy["evidence_count"] = sum(1 for e in _mock_db["incident_evidence"] if e["incident_id"] == str(incident_id))
        inc_copy["attack_mappings_count"] = sum(1 for m in _mock_db["incident_attack_mappings"] if m["incident_id"] == str(incident_id))
        return inc_copy

    async def create_incident(
        self, org_id: str, data: IncidentCreate, created_by: Optional[str]
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        inc_id = str(uuid4())
        inc_num = await self.generate_incident_number(org_id)

        record = {
            "id": inc_id,
            "organization_id": str(org_id),
            "incident_number": inc_num,
            "title": data.title,
            "description": data.description,
            "incident_type": data.incident_type,
            "severity": data.severity,
            "status": "New",
            "priority": data.priority,
            "source": data.source,
            "assigned_to": str(data.assigned_to) if data.assigned_to else None,
            "created_by": str(created_by) if created_by else None,
            "affected_assets": list(data.affected_assets or []),
            "detected_at": now,
            "acknowledged_at": None,
            "investigation_started_at": None,
            "resolved_at": None,
            "closed_at": None,
            "resolution_summary": None,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["incidents"].insert(0, record)

        # Timeline event
        await self.add_timeline_entry(
            org_id,
            inc_id,
            event_type="incident_created",
            description=f"Incident {inc_num} opened: {data.title}",
            actor_id=created_by,
        )

        # Link any initial alerts requested
        if data.initial_alert_ids:
            for alert_id in data.initial_alert_ids:
                await self.link_alert_to_incident(org_id, inc_id, str(alert_id), created_by)

        return await self.get_incident_by_id(org_id, inc_id)

    async def update_incident(
        self, org_id: str, incident_id: str, data: IncidentUpdate, actor_id: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            return None

        real_inc = next(i for i in _mock_db["incidents"] if str(i["id"]) == str(incident_id))
        now = datetime.utcnow().isoformat() + "Z"
        old_status = real_inc.get("status")

        if data.title is not None:
            real_inc["title"] = data.title
        if data.description is not None:
            real_inc["description"] = data.description
        if data.incident_type is not None:
            real_inc["incident_type"] = data.incident_type
        if data.severity is not None:
            real_inc["severity"] = data.severity
        if data.priority is not None:
            real_inc["priority"] = data.priority
        if data.assigned_to is not None:
            real_inc["assigned_to"] = str(data.assigned_to)
        if data.affected_assets is not None:
            real_inc["affected_assets"] = data.affected_assets
        if data.resolution_summary is not None:
            real_inc["resolution_summary"] = data.resolution_summary

        if data.status is not None and data.status != old_status:
            real_inc["status"] = data.status
            if data.status == "Acknowledged" and not real_inc.get("acknowledged_at"):
                real_inc["acknowledged_at"] = now
            elif data.status == "Investigating" and not real_inc.get("investigation_started_at"):
                real_inc["investigation_started_at"] = now
            elif data.status == "Resolved":
                real_inc["resolved_at"] = now
            elif data.status == "Closed":
                real_inc["closed_at"] = now

            await self.add_timeline_entry(
                org_id,
                incident_id,
                event_type="status_change",
                description=f"Status transitioned from {old_status} to {data.status}",
                actor_id=actor_id,
                metadata={"old_status": old_status, "new_status": data.status},
            )

        real_inc["updated_at"] = now
        return await self.get_incident_by_id(org_id, incident_id)

    async def assign_incident(
        self, org_id: str, incident_id: str, assigned_to: str, actor_id: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            return None

        real_inc = next(i for i in _mock_db["incidents"] if str(i["id"]) == str(incident_id))
        now = datetime.utcnow().isoformat() + "Z"
        old_assigned = real_inc.get("assigned_to")
        real_inc["assigned_to"] = str(assigned_to)
        real_inc["updated_at"] = now

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="analyst_assigned",
            description=f"Incident assigned to analyst {assigned_to}",
            actor_id=actor_id,
            metadata={"previous_assigned_to": old_assigned, "new_assigned_to": str(assigned_to)},
        )
        return await self.get_incident_by_id(org_id, incident_id)

    # --------------------------------------------------------------------------
    # Alert-to-Incident Integration
    # --------------------------------------------------------------------------
    async def link_alert_to_incident(
        self, org_id: str, incident_id: str, alert_id: str, actor_id: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        alert = await self.get_alert_by_id(org_id, alert_id)
        if not inc or not alert:
            return None

        # Check if already linked
        existing = next(
            (
                l for l in _mock_db["incident_alerts"]
                if str(l["incident_id"]) == str(incident_id) and str(l["alert_id"]) == str(alert_id)
            ),
            None,
        )
        now = datetime.utcnow().isoformat() + "Z"
        if not existing:
            link_record = {
                "id": str(uuid4()),
                "organization_id": str(org_id),
                "incident_id": str(incident_id),
                "alert_id": str(alert_id),
                "linked_by": str(actor_id) if actor_id else None,
                "linked_at": now,
            }
            _mock_db["incident_alerts"].append(link_record)

        # Update alert
        alert["linked_incident_id"] = str(incident_id)
        alert["status"] = "Escalated"
        alert["updated_at"] = now

        # Add to alert history
        _mock_db["alert_history"].insert(
            0,
            {
                "id": str(uuid4()),
                "alert_id": str(alert_id),
                "changed_by": actor_id,
                "action": "linked_to_incident",
                "previous_state": {"linked_incident_id": None},
                "new_state": {"linked_incident_id": str(incident_id), "status": "Escalated"},
                "notes": f"Linked to incident {inc['incident_number']}",
                "created_at": now,
            },
        )

        # Timeline
        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="alert_linked",
            description=f"Alert '{alert.get('title')}' linked to incident",
            actor_id=actor_id,
            metadata={"alert_id": str(alert_id), "alert_severity": alert.get("severity")},
        )
        return {
            "id": existing["id"] if existing else link_record["id"],
            "incident_id": str(incident_id),
            "alert_id": str(alert_id),
            "linked_by": str(actor_id) if actor_id else None,
            "linked_at": now,
            "alert_title": alert.get("title"),
            "alert_severity": alert.get("severity"),
            "alert_status": alert.get("status"),
        }

    async def unlink_alert_from_incident(
        self, org_id: str, incident_id: str, alert_id: str, actor_id: Optional[str]
    ) -> bool:
        before = len(_mock_db["incident_alerts"])
        _mock_db["incident_alerts"] = [
            l for l in _mock_db["incident_alerts"]
            if not (str(l["incident_id"]) == str(incident_id) and str(l["alert_id"]) == str(alert_id))
        ]
        unlinked = len(_mock_db["incident_alerts"]) < before

        if unlinked:
            alert = await self.get_alert_by_id(org_id, alert_id)
            now = datetime.utcnow().isoformat() + "Z"
            if alert:
                alert["linked_incident_id"] = None
                alert["updated_at"] = now
                _mock_db["alert_history"].insert(
                    0,
                    {
                        "id": str(uuid4()),
                        "alert_id": str(alert_id),
                        "changed_by": actor_id,
                        "action": "unlinked_from_incident",
                        "previous_state": {"linked_incident_id": str(incident_id)},
                        "new_state": {"linked_incident_id": None},
                        "notes": f"Unlinked from incident {incident_id}",
                        "created_at": now,
                    },
                )

            await self.add_timeline_entry(
                org_id,
                incident_id,
                event_type="alert_unlinked",
                description=f"Alert {alert_id} unlinked from incident",
                actor_id=actor_id,
                metadata={"alert_id": str(alert_id)},
            )
        return unlinked

    async def get_incident_alerts(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        links = [
            l for l in _mock_db["incident_alerts"]
            if str(l["incident_id"]) == str(incident_id) and str(l["organization_id"]) == str(org_id)
        ]
        results = []
        for l in links:
            alert = await self.get_alert_by_id(org_id, l["alert_id"])
            results.append({
                "id": l["id"],
                "incident_id": str(incident_id),
                "alert_id": l["alert_id"],
                "linked_by": l.get("linked_by"),
                "linked_at": l["linked_at"],
                "alert_title": alert.get("title") if alert else "Unknown Alert",
                "alert_severity": alert.get("severity") if alert else "Medium",
                "alert_status": alert.get("status") if alert else "Open",
            })
        return results

    # --------------------------------------------------------------------------
    # Notes & Timeline
    # --------------------------------------------------------------------------
    async def get_incident_notes(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        return [
            n for n in _mock_db["incident_notes"]
            if str(n["incident_id"]) == str(incident_id) and str(n["organization_id"]) == str(org_id)
        ]

    async def add_incident_note(
        self, org_id: str, incident_id: str, author_id: Optional[str], note: str
    ) -> Optional[Dict[str, Any]]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            return None

        now = datetime.utcnow().isoformat() + "Z"
        note_record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "author_id": str(author_id) if author_id else None,
            "note": note,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["incident_notes"].append(note_record)

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="note_added",
            description=f"Analyst investigation note recorded",
            actor_id=author_id,
        )
        return note_record

    async def get_incident_timeline(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        events = [
            t for t in _mock_db["incident_timeline"]
            if str(t["incident_id"]) == str(incident_id) and str(t["organization_id"]) == str(org_id)
        ]
        events.sort(key=lambda x: x["created_at"])
        return events

    async def add_timeline_entry(
        self,
        org_id: str,
        incident_id: str,
        event_type: str,
        description: str,
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "event_type": event_type,
            "description": description,
            "actor_id": str(actor_id) if actor_id else None,
            "metadata": metadata or {},
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        _mock_db["incident_timeline"].append(record)
        return record

    # --------------------------------------------------------------------------
    # MITRE ATT&CK Mappings
    # --------------------------------------------------------------------------
    async def get_incident_attack_mappings(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        return [
            m for m in _mock_db["incident_attack_mappings"]
            if str(m["incident_id"]) == str(incident_id) and str(m["organization_id"]) == str(org_id)
        ]

    async def add_incident_attack_mapping(
        self,
        org_id: str,
        incident_id: str,
        technique_id: str,
        confidence: int,
        evidence: Optional[str],
        created_by: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            return None

        technique = attack_service.get_technique_by_id(technique_id)
        if not technique:
            raise ValueError(f"MITRE ATT&CK technique '{technique_id}' is not recognized in knowledge base.")

        # Check duplicate
        existing = next(
            (
                m for m in _mock_db["incident_attack_mappings"]
                if str(m["incident_id"]) == str(incident_id) and m["technique_id"] == technique["id"]
            ),
            None,
        )
        now = datetime.utcnow().isoformat() + "Z"
        if existing:
            existing["confidence"] = confidence
            existing["evidence"] = evidence
            return existing

        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "tactic_id": technique["tactic_id"],
            "tactic_name": technique["tactic_name"],
            "technique_id": technique["id"],
            "technique_name": technique["name"],
            "confidence": confidence,
            "evidence": evidence,
            "created_by": str(created_by) if created_by else None,
            "created_at": now,
        }
        _mock_db["incident_attack_mappings"].append(record)

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="attack_technique_mapped",
            description=f"Mapped MITRE ATT&CK technique {technique['id']} ({technique['name']})",
            actor_id=created_by,
            metadata={"technique_id": technique["id"], "confidence": confidence},
        )
        return record

    async def delete_incident_attack_mapping(self, org_id: str, incident_id: str, mapping_id: str) -> bool:
        before = len(_mock_db["incident_attack_mappings"])
        _mock_db["incident_attack_mappings"] = [
            m for m in _mock_db["incident_attack_mappings"]
            if not (str(m["id"]) == str(mapping_id) and str(m["incident_id"]) == str(incident_id))
        ]
        return len(_mock_db["incident_attack_mappings"]) < before

    # --------------------------------------------------------------------------
    # Evidence Vault
    # --------------------------------------------------------------------------
    async def get_incident_evidence(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        return [
            e for e in _mock_db["incident_evidence"]
            if str(e["incident_id"]) == str(incident_id) and str(e["organization_id"]) == str(org_id)
        ]

    async def get_evidence_by_id(self, org_id: str, incident_id: str, evidence_id: str) -> Optional[Dict[str, Any]]:
        return next(
            (
                e for e in _mock_db["incident_evidence"]
                if str(e["id"]) == str(evidence_id)
                and str(e["incident_id"]) == str(incident_id)
                and str(e["organization_id"]) == str(org_id)
            ),
            None,
        )

    async def add_incident_evidence(
        self, org_id: str, incident_id: str, data: IncidentEvidenceCreate, uploaded_by: Optional[str]
    ) -> Dict[str, Any]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            raise ValueError("Incident not found")

        processed = evidence_service.process_evidence_payload(
            org_id=org_id,
            incident_id=incident_id,
            evidence_name=data.evidence_name,
            evidence_type=data.evidence_type,
            original_filename=data.original_filename,
            mime_type=data.mime_type,
            file_bytes_base64=data.file_bytes_base64,
            file_size=data.file_size,
            description=data.description,
            uploaded_by=uploaded_by,
        )
        now = datetime.utcnow().isoformat() + "Z"
        processed["uploaded_at"] = now
        _mock_db["incident_evidence"].append(processed)

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="evidence_uploaded",
            description=f"Forensic artifact '{data.evidence_name}' ({data.original_filename}) secured in Evidence Vault",
            actor_id=uploaded_by,
            metadata={"sha256": processed["sha256_hash"], "size": processed["file_size"]},
        )
        return processed

    async def delete_incident_evidence(self, org_id: str, incident_id: str, evidence_id: str) -> bool:
        before = len(_mock_db["incident_evidence"])
        _mock_db["incident_evidence"] = [
            e for e in _mock_db["incident_evidence"]
            if not (str(e["id"]) == str(evidence_id) and str(e["incident_id"]) == str(incident_id))
        ]
        return len(_mock_db["incident_evidence"]) < before

    # --------------------------------------------------------------------------
    # Playbooks & Steps
    # --------------------------------------------------------------------------
    async def get_playbooks(self, org_id: str) -> List[Dict[str, Any]]:
        pbs = [
            p for p in _mock_db["playbooks"]
            if str(p["organization_id"]) == str(org_id)
        ]
        results = []
        for pb in pbs:
            pb_copy = dict(pb)
            pb_steps = [
                s for s in _mock_db["playbook_steps"]
                if str(s["playbook_id"]) == str(pb["id"])
            ]
            pb_steps.sort(key=lambda s: s["step_number"])
            pb_copy["steps"] = pb_steps
            results.append(pb_copy)
        return results

    async def get_playbook_by_id(self, org_id: str, playbook_id: str) -> Optional[Dict[str, Any]]:
        pb = next(
            (
                p for p in _mock_db["playbooks"]
                if str(p["id"]) == str(playbook_id) and str(p["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not pb:
            return None
        pb_copy = dict(pb)
        pb_steps = [
            s for s in _mock_db["playbook_steps"]
            if str(s["playbook_id"]) == str(playbook_id)
        ]
        pb_steps.sort(key=lambda s: s["step_number"])
        pb_copy["steps"] = pb_steps
        return pb_copy

    async def create_playbook(self, org_id: str, data: PlaybookCreate, created_by: Optional[str]) -> Dict[str, Any]:
        pb_id = str(uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        pb_record = {
            "id": pb_id,
            "organization_id": str(org_id),
            "playbook_name": data.playbook_name,
            "category": data.category,
            "description": data.description,
            "is_enabled": True,
            "created_by": str(created_by) if created_by else None,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["playbooks"].append(pb_record)

        for s in data.steps:
            step_record = {
                "id": str(uuid4()),
                "playbook_id": pb_id,
                "step_number": s.step_number,
                "step_title": s.step_title,
                "step_description": s.step_description,
                "is_required": s.is_required,
                "created_at": now,
            }
            _mock_db["playbook_steps"].append(step_record)

        return await self.get_playbook_by_id(org_id, pb_id)

    async def update_playbook(self, org_id: str, playbook_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        pb = await self.get_playbook_by_id(org_id, playbook_id)
        if not pb:
            return None

        real_pb = next(p for p in _mock_db["playbooks"] if str(p["id"]) == str(playbook_id))
        for k, v in data.items():
            if v is not None and k in real_pb:
                real_pb[k] = v
        real_pb["updated_at"] = datetime.utcnow().isoformat() + "Z"
        return await self.get_playbook_by_id(org_id, playbook_id)

    async def attach_playbook_to_incident(
        self, org_id: str, incident_id: str, playbook_id: str, assigned_to: Optional[str]
    ) -> Dict[str, Any]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        pb = await self.get_playbook_by_id(org_id, playbook_id)
        if not inc or not pb:
            raise ValueError("Incident or Playbook not found")

        # Check duplicate
        existing = next(
            (
                ip for ip in _mock_db["incident_playbooks"]
                if str(ip["incident_id"]) == str(incident_id) and str(ip["playbook_id"]) == str(playbook_id)
            ),
            None,
        )
        if existing:
            return existing

        now = datetime.utcnow().isoformat() + "Z"
        assignment_id = str(uuid4())
        inc_pb_record = {
            "id": assignment_id,
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "playbook_id": str(playbook_id),
            "playbook_name": pb["playbook_name"],
            "category": pb["category"],
            "status": "In Progress",
            "assigned_to": str(assigned_to) if assigned_to else None,
            "started_at": now,
            "completed_at": None,
        }
        _mock_db["incident_playbooks"].append(inc_pb_record)

        # Seed progress for each step
        for s in pb["steps"]:
            progress_record = {
                "id": str(uuid4()),
                "incident_playbook_id": assignment_id,
                "step_id": str(s["id"]),
                "step_number": s["step_number"],
                "step_title": s["step_title"],
                "status": "Pending",
                "notes": None,
                "completed_by": None,
                "completed_at": None,
            }
            _mock_db["playbook_step_progress"].append(progress_record)

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="playbook_attached",
            description=f"Attached Response Playbook: {pb['playbook_name']}",
            metadata={"playbook_id": str(playbook_id)},
        )
        return inc_pb_record

    async def get_incident_playbooks(self, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        attached = [
            ip for ip in _mock_db["incident_playbooks"]
            if str(ip["incident_id"]) == str(incident_id) and str(ip["organization_id"]) == str(org_id)
        ]
        results = []
        for ip in attached:
            ip_copy = dict(ip)
            steps = [
                sp for sp in _mock_db["playbook_step_progress"]
                if str(sp["incident_playbook_id"]) == str(ip["id"])
            ]
            steps.sort(key=lambda s: s["step_number"])
            ip_copy["step_progress"] = steps
            results.append(ip_copy)
        return results

    async def update_step_progress(
        self,
        org_id: str,
        incident_id: str,
        assignment_id: str,
        step_id: str,
        status: str,
        notes: Optional[str],
        actor_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        progress = next(
            (
                sp for sp in _mock_db["playbook_step_progress"]
                if str(sp["incident_playbook_id"]) == str(assignment_id)
                and (str(sp["step_id"]) == str(step_id) or str(sp["id"]) == str(step_id))
            ),
            None,
        )
        if not progress:
            return None

        now = datetime.utcnow().isoformat() + "Z"
        progress["status"] = status
        if notes:
            progress["notes"] = notes
        if status == "Completed":
            progress["completed_by"] = str(actor_id) if actor_id else None
            progress["completed_at"] = now

        # Check if all steps in this playbook are complete
        all_steps = [
            sp for sp in _mock_db["playbook_step_progress"]
            if str(sp["incident_playbook_id"]) == str(assignment_id)
        ]
        if all_steps and all(s["status"] in ("Completed", "Skipped") for s in all_steps):
            parent = next((p for p in _mock_db["incident_playbooks"] if str(p["id"]) == str(assignment_id)), None)
            if parent:
                parent["status"] = "Completed"
                parent["completed_at"] = now

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="playbook_step_updated",
            description=f"Playbook step '{progress['step_title']}' marked as {status}",
            actor_id=actor_id,
            metadata={"step_id": str(step_id), "status": status},
        )
        return progress

    # --------------------------------------------------------------------------
    # Response Requests & Approvals
    # --------------------------------------------------------------------------
    async def get_response_requests(
        self, org_id: str, incident_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        reqs = [
            r for r in _mock_db["response_requests"]
            if str(r["organization_id"]) == str(org_id)
        ]
        if incident_id:
            reqs = [r for r in reqs if str(r["incident_id"]) == str(incident_id)]

        results = []
        for r in reqs:
            r_copy = dict(r)
            approval = next(
                (a for a in _mock_db["response_approvals"] if str(a["request_id"]) == str(r["id"])),
                None,
            )
            r_copy["approval"] = approval
            results.append(r_copy)
        return results

    async def create_response_request(
        self, org_id: str, incident_id: str, action_type: str, target_resource: str, justification: str, requested_by: Optional[str]
    ) -> Dict[str, Any]:
        inc = await self.get_incident_by_id(org_id, incident_id)
        if not inc:
            raise ValueError("Incident not found")

        req_id = str(uuid4())
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": req_id,
            "organization_id": str(org_id),
            "incident_id": str(incident_id),
            "action_type": action_type,
            "target_resource": target_resource,
            "justification": justification,
            "status": "Pending",
            "requested_by": str(requested_by) if requested_by else None,
            "created_at": now,
            "updated_at": now,
            "approval": None,
        }
        _mock_db["response_requests"].insert(0, record)

        await self.add_timeline_entry(
            org_id,
            incident_id,
            event_type="response_action_requested",
            description=f"Action requested: {action_type} for target '{target_resource}'",
            actor_id=requested_by,
            metadata={"request_id": req_id, "action_type": action_type},
        )
        return record

    async def decide_response_request(
        self, org_id: str, request_id: str, decision: str, decision_notes: str, decided_by: Optional[str]
    ) -> Optional[Dict[str, Any]]:
        req = next(
            (
                r for r in _mock_db["response_requests"]
                if str(r["id"]) == str(request_id) and str(r["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not req:
            return None

        now = datetime.utcnow().isoformat() + "Z"
        req["status"] = decision
        req["updated_at"] = now

        approval_record = {
            "id": str(uuid4()),
            "request_id": str(request_id),
            "decided_by": str(decided_by) if decided_by else None,
            "decision": decision,
            "decision_notes": decision_notes,
            "decided_at": now,
        }
        _mock_db["response_approvals"].append(approval_record)
        req["approval"] = approval_record

        # Append timeline on the incident
        await self.add_timeline_entry(
            org_id,
            req["incident_id"],
            event_type=f"response_{decision.lower()}",
            description=f"Response request for {req['action_type']} was {decision}. Note: {decision_notes}",
            actor_id=decided_by,
            metadata={"request_id": str(request_id), "decision": decision},
        )
        return req

    # --------------------------------------------------------------------------
    # SPRINT 9: AI ASSISTANT, RECOMMENDATIONS & USAGE METHODS
    # --------------------------------------------------------------------------
    async def create_ai_conversation(
        self, org_id: str, user_id: str, title: str = "Security Consultation"
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "user_id": str(user_id),
            "title": title,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db["ai_conversations"].insert(0, record)
        return record

    async def get_ai_conversations(
        self, org_id: str, user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        convs = [
            c for c in _mock_db["ai_conversations"]
            if str(c["organization_id"]) == str(org_id)
            and (user_id is None or str(c["user_id"]) == str(user_id))
        ]
        result = []
        for c in convs:
            msg_count = sum(1 for m in _mock_db["ai_messages"] if str(m["conversation_id"]) == str(c["id"]))
            item = dict(c)
            item["message_count"] = msg_count
            result.append(item)
        return result

    async def get_ai_conversation(
        self, org_id: str, conversation_id: str
    ) -> Optional[Dict[str, Any]]:
        conv = next(
            (
                c for c in _mock_db["ai_conversations"]
                if str(c["id"]) == str(conversation_id) and str(c["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not conv:
            return None
        messages = [
            m for m in _mock_db["ai_messages"]
            if str(m["conversation_id"]) == str(conversation_id)
        ]
        res = dict(conv)
        res["messages"] = sorted(messages, key=lambda x: x.get("created_at", ""))
        return res

    async def delete_ai_conversation(self, org_id: str, conversation_id: str) -> bool:
        idx = next(
            (
                i for i, c in enumerate(_mock_db["ai_conversations"])
                if str(c["id"]) == str(conversation_id) and str(c["organization_id"]) == str(org_id)
            ),
            None,
        )
        if idx is None:
            return False
        _mock_db["ai_conversations"].pop(idx)
        _mock_db["ai_messages"] = [
            m for m in _mock_db["ai_messages"] if str(m["conversation_id"]) != str(conversation_id)
        ]
        return True

    async def add_ai_message(
        self,
        conversation_id: str,
        role: str,
        content: str,
        source_references: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(uuid4()),
            "conversation_id": str(conversation_id),
            "role": role,
            "content": content,
            "source_references": source_references or [],
            "created_at": now,
        }
        _mock_db["ai_messages"].append(record)

        # Update conversation updated_at
        for c in _mock_db["ai_conversations"]:
            if str(c["id"]) == str(conversation_id):
                c["updated_at"] = now
                break

        return record

    async def create_ai_recommendation(
        self,
        org_id: str,
        recommendation_type: str,
        related_entity_type: str,
        related_entity_id: str,
        recommendation: Dict[str, Any],
        model_name: str,
        provider: str,
        recommendation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        now = datetime.utcnow().isoformat() + "Z"
        record = {
            "id": str(recommendation_id) if recommendation_id else str(uuid4()),
            "organization_id": str(org_id),
            "recommendation_type": recommendation_type,
            "related_entity_type": related_entity_type,
            "related_entity_id": str(related_entity_id),
            "recommendation": recommendation,
            "model_name": model_name,
            "provider": provider,
            "status": "Pending Review",
            "reviewed_by": None,
            "reviewed_at": None,
            "review_notes": None,
            "created_at": now,
        }
        _mock_db["ai_recommendations"].insert(0, record)
        return record

    async def get_ai_recommendations(
        self,
        org_id: str,
        recommendation_type: Optional[str] = None,
        related_entity_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        return [
            r for r in _mock_db["ai_recommendations"]
            if str(r["organization_id"]) == str(org_id)
            and (recommendation_type is None or r.get("recommendation_type") == recommendation_type)
            and (related_entity_id is None or str(r.get("related_entity_id")) == str(related_entity_id))
            and (status is None or r.get("status") == status)
        ]

    async def review_ai_recommendation(
        self, org_id: str, recommendation_id: str, reviewer_id: str, decision: str, notes: str
    ) -> Optional[Dict[str, Any]]:
        rec = next(
            (
                r for r in _mock_db["ai_recommendations"]
                if str(r["id"]) == str(recommendation_id) and str(r["organization_id"]) == str(org_id)
            ),
            None,
        )
        if not rec:
            return None
        now = datetime.utcnow().isoformat() + "Z"
        rec["status"] = decision
        rec["reviewed_by"] = str(reviewer_id)
        rec["reviewed_at"] = now
        rec["review_notes"] = notes
        return rec

    async def log_ai_usage(
        self,
        org_id: str,
        user_id: Optional[str],
        provider: str,
        model: str,
        endpoint: str,
        input_tokens: int,
        output_tokens: int,
        estimated_cost: float,
        request_status: str = "success",
        latency_ms: int = 40,
    ) -> Dict[str, Any]:
        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "user_id": str(user_id) if user_id else None,
            "provider": provider,
            "model": model,
            "endpoint": endpoint,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "estimated_cost": estimated_cost,
            "request_status": request_status,
            "latency_ms": latency_ms,
            "created_at": datetime.utcnow().isoformat() + "Z",
        }
        _mock_db["ai_usage_logs"].insert(0, record)
        return record

    async def get_ai_usage_summary(self, org_id: str) -> Dict[str, Any]:
        logs = [l for l in _mock_db["ai_usage_logs"] if str(l["organization_id"]) == str(org_id)]
        total_reqs = len(logs)
        tot_in = sum(l.get("input_tokens", 0) for l in logs)
        tot_out = sum(l.get("output_tokens", 0) for l in logs)
        tot_cost = sum(float(l.get("estimated_cost", 0.0)) for l in logs)

        provider_dist: Dict[str, int] = {}
        for l in logs:
            p = l.get("provider", "mock")
            provider_dist[p] = provider_dist.get(p, 0) + 1

        return {
            "organization_id": org_id,
            "total_requests": total_reqs,
            "total_input_tokens": tot_in,
            "total_output_tokens": tot_out,
            "total_tokens": tot_in + tot_out,
            "estimated_cost_usd": round(tot_cost, 4),
            "provider_breakdown": provider_dist,
            "recent_logs": logs[:10],
        }

    # --------------------------------------------------------------------------
    # Sprint 10: Multi-Tenant Organizations & Saas Methods
    # --------------------------------------------------------------------------
    async def get_user_organizations(self, user_id: str) -> List[Dict[str, Any]]:
        """List all organizations the user is a member of, with membership details."""
        memberships = await self.get_user_org_membership(user_id)
        org_ids = [str(m["organization_id"]) for m in memberships]

        result = []
        for org in _mock_db["organizations"]:
            if str(org["id"]) in org_ids:
                mem = next((m for m in memberships if str(m["organization_id"]) == str(org["id"])), None)
                role = mem.get("role", "viewer") if mem else "viewer"
                count = sum(1 for m in _mock_db["organization_members"] if str(m["organization_id"]) == str(org["id"]))
                sub = await self.get_organization_subscription(str(org["id"]))
                plan_name = sub.get("plan_name", "Professional") if sub else "Professional"

                org_copy = dict(org)
                org_copy["user_role"] = role
                org_copy["member_count"] = count
                org_copy["current_plan"] = plan_name
                result.append(org_copy)
        return result

    async def get_organization(self, org_id: str) -> Optional[Dict[str, Any]]:
        org = next((o for o in _mock_db["organizations"] if str(o["id"]) == str(org_id)), None)
        if not org:
            return None
        count = sum(1 for m in _mock_db["organization_members"] if str(m["organization_id"]) == str(org_id))
        sub = await self.get_organization_subscription(str(org_id))
        plan_name = sub.get("plan_name", "Professional") if sub else "Professional"

        res = dict(org)
        res["member_count"] = count
        res["current_plan"] = plan_name
        return res

    async def create_organization(
        self,
        name: str,
        user_id: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        website: Optional[str] = None,
        industry: Optional[str] = "Technology",
        organization_size: Optional[str] = "11-50 employees",
        country: Optional[str] = "US",
        time_zone: Optional[str] = "UTC",
    ) -> Dict[str, Any]:
        new_id = str(uuid4())
        clean_slug = slug or name.lower().replace(" ", "-").replace(".", "")
        now = datetime.utcnow().isoformat() + "Z"
        org = {
            "id": new_id,
            "name": name,
            "slug": clean_slug,
            "description": description or f"{name} Security Workspace",
            "website": website or f"https://{clean_slug}.example.com",
            "industry": industry or "Technology",
            "organization_size": organization_size or "11-50 employees",
            "country": country or "US",
            "time_zone": time_zone or "UTC",
            "status": "Active",
            "suspension_reason": None,
            "created_at": now,
        }
        _mock_db["organizations"].append(org)

        member = {
            "id": str(uuid4()),
            "organization_id": new_id,
            "user_id": str(user_id),
            "role": "owner",
            "email": "user@example.com",
            "full_name": "Organization Owner",
            "joined_at": now,
            "last_active": now,
        }
        _mock_db["organization_members"].append(member)

        plan = DEFAULT_PLANS["PROFESSIONAL"]
        sub = {
            "id": str(uuid4()),
            "organization_id": new_id,
            "plan_id": plan["id"],
            "plan_name": plan["plan_name"],
            "plan_code": plan["plan_code"],
            "status": "Active",
            "billing_provider": "mock",
            "current_period_start": now,
            "current_period_end": (datetime.utcnow() + timedelta(days=30)).isoformat() + "Z",
            "cancel_at_period_end": False,
            "price": plan["price"],
        }
        _mock_db["organization_subscriptions"].append(sub)

        res = dict(org)
        res["member_count"] = 1
        res["current_plan"] = plan["plan_name"]
        return res

    async def update_organization(self, org_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        org = next((o for o in _mock_db["organizations"] if str(o["id"]) == str(org_id)), None)
        if not org:
            return None
        for k, v in data.items():
            if v is not None and k in ["name", "description", "website", "industry", "organization_size", "country", "time_zone"]:
                org[k] = v
        return await self.get_organization(org_id)

    # --------------------------------------------------------------------------
    # Team & RBAC Methods
    # --------------------------------------------------------------------------
    async def get_organization_members(self, org_id: str) -> List[Dict[str, Any]]:
        members = [m for m in _mock_db["organization_members"] if str(m["organization_id"]) == str(org_id)]
        res = []
        for m in members:
            item = dict(m)
            if "email" not in item:
                item["email"] = f"user-{item.get('user_id', 'unknown')[:6]}@example.com"
            if "joined_at" not in item:
                item["joined_at"] = "2026-01-01T00:00:00Z"
            if "last_active" not in item:
                item["last_active"] = "2026-10-31T12:00:00Z"
            res.append(item)
        return res

    async def update_member_role(self, org_id: str, member_id: str, new_role: str) -> Optional[Dict[str, Any]]:
        member = next((m for m in _mock_db["organization_members"] if str(m["id"]) == str(member_id) and str(m["organization_id"]) == str(org_id)), None)
        if not member:
            return None

        if member.get("role") == "owner" and new_role != "owner":
            other_owners = [
                m for m in _mock_db["organization_members"]
                if str(m["organization_id"]) == str(org_id) and str(m["id"]) != str(member_id) and m.get("role") == "owner"
            ]
            if not other_owners:
                raise ValueError("Cannot demote the last organization owner. Transfer ownership first.")

        member["role"] = new_role
        return member

    async def remove_organization_member(self, org_id: str, member_id: str) -> Tuple[bool, str]:
        member = next((m for m in _mock_db["organization_members"] if str(m["id"]) == str(member_id) and str(m["organization_id"]) == str(org_id)), None)
        if not member:
            return False, "Member not found"

        if member.get("role") == "owner":
            other_owners = [
                m for m in _mock_db["organization_members"]
                if str(m["organization_id"]) == str(org_id) and str(m["id"]) != str(member_id) and m.get("role") == "owner"
            ]
            if not other_owners:
                return False, "Cannot remove the last organization owner"

        _mock_db["organization_members"] = [
            m for m in _mock_db["organization_members"]
            if not (str(m["id"]) == str(member_id) and str(m["organization_id"]) == str(org_id))
        ]
        return True, "Member removed successfully"

    async def create_invitation(self, org_id: str, email: str, role: str, invited_by: Optional[str] = None) -> Dict[str, Any]:
        existing = [
            m for m in _mock_db["organization_members"]
            if str(m["organization_id"]) == str(org_id) and m.get("email", "").lower() == email.lower()
        ]
        if existing:
            raise ValueError(f"User '{email}' is already a member of this organization")

        pending = [
            inv for inv in _mock_db.get("organization_invitations", [])
            if str(inv["organization_id"]) == str(org_id) and inv.get("email", "").lower() == email.lower() and inv.get("status") == "Pending"
        ]
        if pending:
            raise ValueError(f"An active invitation already exists for '{email}'")

        from app.billing.usage import QuotaEnforcementService
        is_allowed, cur, lim, msg = await QuotaEnforcementService.check_quota(self, org_id, "members")
        if not is_allowed:
            raise ValueError(msg)

        now = datetime.utcnow()
        invitation = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "email": email.lower(),
            "role": role,
            "status": "Pending",
            "invited_by": str(invited_by) if invited_by else None,
            "token": secrets.token_urlsafe(32),
            "expires_at": (now + timedelta(days=7)).isoformat() + "Z",
            "created_at": now.isoformat() + "Z",
        }
        if "organization_invitations" not in _mock_db:
            _mock_db["organization_invitations"] = []
        _mock_db["organization_invitations"].insert(0, invitation)
        return invitation

    async def get_invitations(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            inv for inv in _mock_db.get("organization_invitations", [])
            if str(inv["organization_id"]) == str(org_id)
        ]

    async def resend_invitation(self, org_id: str, inv_id: str) -> Optional[Dict[str, Any]]:
        inv = next((i for i in _mock_db.get("organization_invitations", []) if str(i["id"]) == str(inv_id) and str(i["organization_id"]) == str(org_id)), None)
        if not inv:
            return None
        now = datetime.utcnow()
        inv["expires_at"] = (now + timedelta(days=7)).isoformat() + "Z"
        inv["status"] = "Pending"
        return inv

    async def cancel_invitation(self, org_id: str, inv_id: str) -> bool:
        inv = next((i for i in _mock_db.get("organization_invitations", []) if str(i["id"]) == str(inv_id) and str(i["organization_id"]) == str(org_id)), None)
        if not inv:
            return False
        inv["status"] = "Cancelled"
        return True

    # --------------------------------------------------------------------------
    # Subscriptions & Billing
    # --------------------------------------------------------------------------
    async def get_subscription_plans(self) -> List[Dict[str, Any]]:
        return list(DEFAULT_PLANS.values())

    async def get_organization_subscription(self, org_id: str) -> Optional[Dict[str, Any]]:
        subs = _mock_db.get("organization_subscriptions", [])
        return next((s for s in subs if str(s["organization_id"]) == str(org_id)), None)

    async def set_organization_subscription(self, org_id: str, sub_data: Dict[str, Any]) -> Dict[str, Any]:
        if "organization_subscriptions" not in _mock_db:
            _mock_db["organization_subscriptions"] = []

        existing = next((s for s in _mock_db["organization_subscriptions"] if str(s["organization_id"]) == str(org_id)), None)
        if existing:
            existing.update(sub_data)
            return existing
        else:
            _mock_db["organization_subscriptions"].append(sub_data)
            return sub_data

    async def get_monthly_scan_usage(self, org_id: str) -> int:
        now = datetime.utcnow()
        start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start_iso = start_of_month.isoformat()

        disc_scans = [
            s for s in _mock_db.get("scans", [])
            if str(s.get("organization_id")) == str(org_id) and str(s.get("created_at", "")) >= start_iso
        ]
        vuln_scans = [
            s for s in _mock_db.get("vulnerability_scans", [])
            if str(s.get("organization_id")) == str(org_id) and str(s.get("created_at", "")) >= start_iso
        ]
        return len(disc_scans) + len(vuln_scans)

    # --------------------------------------------------------------------------
    # API Key Management
    # --------------------------------------------------------------------------
    async def create_api_key(
        self,
        org_id: str,
        key_name: str,
        scopes: List[str],
        expires_in_days: Optional[int] = 90,
        created_by: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str]:
        raw_secret = secrets.token_urlsafe(32)
        raw_key = f"cs_live_{raw_secret}"
        key_prefix = raw_key[:12]
        key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        now = datetime.utcnow()
        expires_at = (now + timedelta(days=expires_in_days)).isoformat() + "Z" if expires_in_days else None

        record = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "key_name": key_name,
            "key_prefix": key_prefix,
            "key_hash": key_hash,
            "scopes": scopes,
            "created_at": now.isoformat() + "Z",
            "expires_at": expires_at,
            "last_used_at": None,
            "is_revoked": False,
            "created_by": str(created_by) if created_by else None,
        }
        if "api_keys" not in _mock_db:
            _mock_db["api_keys"] = []
        _mock_db["api_keys"].insert(0, record)

        return record, raw_key

    async def get_api_keys(self, org_id: str) -> List[Dict[str, Any]]:
        keys = [k for k in _mock_db.get("api_keys", []) if str(k["organization_id"]) == str(org_id)]
        clean_keys = []
        for k in keys:
            copy_k = {key: val for key, val in k.items() if key != "key_hash"}
            clean_keys.append(copy_k)
        return clean_keys

    async def revoke_api_key(self, org_id: str, key_id: str) -> bool:
        key = next((k for k in _mock_db.get("api_keys", []) if str(k["id"]) == str(key_id) and str(k["organization_id"]) == str(org_id)), None)
        if not key:
            return False
        key["is_revoked"] = True
        return True

    async def rotate_api_key(self, org_id: str, key_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        key = next((k for k in _mock_db.get("api_keys", []) if str(k["id"]) == str(key_id) and str(k["organization_id"]) == str(org_id)), None)
        if not key:
            return None, None
        key["is_revoked"] = True
        return await self.create_api_key(
            org_id=org_id,
            key_name=key["key_name"],
            scopes=key.get("scopes", ["read:assets"]),
            created_by=key.get("created_by"),
        )

    # --------------------------------------------------------------------------
    # Platform Admin Operations
    # --------------------------------------------------------------------------
    async def get_platform_overview(self) -> Dict[str, Any]:
        total_orgs = len(_mock_db.get("organizations", []))
        users = set(m.get("user_id") for m in _mock_db.get("organization_members", []))
        total_users = len(users)

        subs = _mock_db.get("organization_subscriptions", [])
        active_subs = sum(1 for s in subs if s.get("status") == "Active")
        trial_orgs = sum(1 for s in subs if s.get("status") == "Trial")
        suspended_orgs = sum(1 for o in _mock_db.get("organizations", []) if o.get("status") == "Suspended")
        total_assets = len(_mock_db.get("assets", []))

        return {
            "total_users": total_users,
            "total_organizations": total_orgs,
            "active_subscriptions": active_subs,
            "trial_organizations": trial_orgs,
            "suspended_organizations": suspended_orgs,
            "total_assets_monitored": total_assets,
            "background_worker_health": "Operational",
            "api_gateway_health": "Operational",
            "db_connectivity": "Connected",
        }

    async def get_platform_organizations(self) -> List[Dict[str, Any]]:
        res = []
        for org in _mock_db.get("organizations", []):
            o_id = str(org["id"])
            members_cnt = sum(1 for m in _mock_db.get("organization_members", []) if str(m["organization_id"]) == o_id)
            sub = next((s for s in _mock_db.get("organization_subscriptions", []) if str(s["organization_id"]) == o_id), None)
            item = dict(org)
            item["member_count"] = members_cnt
            item["current_plan"] = sub.get("plan_name", "Professional") if sub else "None"
            res.append(item)
        return res

    async def get_platform_users(self) -> List[Dict[str, Any]]:
        users_map: Dict[str, Dict[str, Any]] = {}
        for m in _mock_db.get("organization_members", []):
            uid = str(m.get("user_id"))
            if uid not in users_map:
                users_map[uid] = {
                    "id": uid,
                    "email": m.get("email", f"user-{uid[:6]}@example.com"),
                    "full_name": m.get("full_name", f"User {uid[:6]}"),
                    "joined_at": m.get("joined_at", "2026-01-01T00:00:00Z"),
                    "last_active": m.get("last_active", "2026-10-31T12:00:00Z"),
                    "organizations": [],
                }
            org = next((o for o in _mock_db.get("organizations", []) if str(o["id"]) == str(m.get("organization_id"))), None)
            org_name = org.get("name", "Unknown Org") if org else "Unknown Org"
            users_map[uid]["organizations"].append({
                "organization_id": m.get("organization_id"),
                "organization_name": org_name,
                "role": m.get("role", "viewer"),
            })
        return list(users_map.values())

    async def suspend_organization(self, org_id: str, reason: str, admin_id: str) -> Optional[Dict[str, Any]]:
        org = next((o for o in _mock_db["organizations"] if str(o["id"]) == str(org_id)), None)
        if not org:
            return None
        org["status"] = "Suspended"
        org["suspension_reason"] = reason
        log = {
            "id": str(uuid4()),
            "action": "SUSPEND_ORGANIZATION",
            "organization_id": org_id,
            "admin_id": admin_id,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        if "platform_audit_logs" not in _mock_db:
            _mock_db["platform_audit_logs"] = []
        _mock_db["platform_audit_logs"].append(log)
        return org

    # --------------------------------------------------------------------------
    # Sprint 11: Compliance Management & Reporting
    # --------------------------------------------------------------------------
    async def get_compliance_frameworks(self) -> List[Dict[str, Any]]:
        return list(_mock_db.get("compliance_frameworks", []))

    async def get_compliance_controls(self, framework_code: Optional[str] = None) -> List[Dict[str, Any]]:
        controls = _mock_db.get("compliance_controls", [])
        if framework_code:
            controls = [c for c in controls if c.get("framework_code") == framework_code]
        return list(controls)

    async def get_compliance_controls_with_status(
        self,
        org_id: str,
        framework_code: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        controls = await self.get_compliance_controls(framework_code)
        if domain:
            controls = [c for c in controls if domain.lower() in (c.get("domain") or "").lower()]

        assessments = await self.get_compliance_assessments(org_id)
        evidence = await self.get_compliance_evidence(org_id)

        res = []
        for c in controls:
            c_copy = dict(c)
            match = next((a for a in assessments if str(a.get("control_id")) == str(c["id"])), None)
            ev_count = sum(1 for e in evidence if str(e.get("control_id")) == str(c["id"]))

            c_copy["current_status"] = match.get("status", "Not Assessed") if match else "Not Assessed"
            c_copy["assigned_owner"] = match.get("assigned_owner") if match else None
            c_copy["review_date"] = match.get("review_date") if match else None
            c_copy["notes"] = match.get("notes") if match else None
            c_copy["evidence_count"] = ev_count
            res.append(c_copy)
        return res

    async def get_compliance_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            a for a in _mock_db.get("compliance_assessments", [])
            if str(a.get("organization_id")) == str(org_id)
        ]

    async def upsert_compliance_assessment(
        self,
        org_id: str,
        control_id: str,
        status: str,
        assigned_owner: Optional[str] = None,
        review_date: Optional[str] = None,
        notes: Optional[str] = None,
        remediation_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        control = next((c for c in _mock_db.get("compliance_controls", []) if str(c["id"]) == str(control_id)), None)
        if not control:
            raise ValueError(f"Control '{control_id}' not found")

        existing = next(
            (a for a in _mock_db.get("compliance_assessments", []) if str(a.get("organization_id")) == str(org_id) and str(a.get("control_id")) == str(control_id)),
            None
        )
        now = datetime.utcnow().isoformat() + "Z"

        if existing:
            existing["status"] = status
            if assigned_owner is not None: existing["assigned_owner"] = assigned_owner
            if review_date is not None: existing["review_date"] = review_date
            if notes is not None: existing["notes"] = notes
            if remediation_notes is not None: existing["remediation_notes"] = remediation_notes
            existing["updated_at"] = now
            return existing

        new_ass = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "control_id": str(control_id),
            "framework_id": str(control["framework_id"]),
            "framework_code": control["framework_code"],
            "control_code": control["control_id"],
            "control_title": control["title"],
            "status": status,
            "assigned_owner": assigned_owner,
            "review_date": review_date,
            "notes": notes,
            "remediation_notes": remediation_notes,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db.setdefault("compliance_assessments", []).append(new_ass)
        return new_ass

    async def update_compliance_assessment(
        self, org_id: str, assessment_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        ass = next(
            (a for a in _mock_db.get("compliance_assessments", []) if str(a["id"]) == str(assessment_id) and str(a["organization_id"]) == str(org_id)),
            None
        )
        if not ass:
            return None
        for k, v in data.items():
            if v is not None:
                ass[k] = str(v) if k == "review_date" else v
        ass["updated_at"] = datetime.utcnow().isoformat() + "Z"
        return ass

    async def create_compliance_evidence(self, record: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("compliance_evidence", []).insert(0, record)
        return record

    async def get_compliance_evidence(
        self,
        org_id: str,
        control_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        evidence = [e for e in _mock_db.get("compliance_evidence", []) if str(e.get("organization_id")) == str(org_id)]
        if control_id:
            evidence = [e for e in evidence if str(e.get("control_id")) == str(control_id)]
        if assessment_id:
            evidence = [e for e in evidence if str(e.get("assessment_id")) == str(assessment_id)]
        return evidence

    async def delete_compliance_evidence(self, org_id: str, evidence_id: str) -> bool:
        before_len = len(_mock_db.get("compliance_evidence", []))
        _mock_db["compliance_evidence"] = [
            e for e in _mock_db.get("compliance_evidence", [])
            if not (str(e.get("id")) == str(evidence_id) and str(e.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["compliance_evidence"]) < before_len

    async def create_security_report(self, record: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("security_reports", []).insert(0, record)
        return record

    async def get_security_reports(
        self, org_id: str, report_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        reports = [r for r in _mock_db.get("security_reports", []) if str(r.get("organization_id")) == str(org_id)]
        if report_type:
            reports = [r for r in reports if r.get("report_type") == report_type]
        return reports

    async def get_security_report_by_id(
        self, org_id: str, report_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (r for r in _mock_db.get("security_reports", []) if str(r.get("id")) == str(report_id) and str(r.get("organization_id")) == str(org_id)),
            None
        )

    async def get_compliance_summary(self, org_id: str) -> Dict[str, Any]:
        from app.services.compliance_service import compliance_service
        return await compliance_service.get_compliance_summary(self, org_id)

    # --------------------------------------------------------------------------
    # SPRINT 12: ADVANCED NETWORK MONITORING & REAL-TIME SOC
    # --------------------------------------------------------------------------
    def _ensure_monitoring_seeds(self, org_id: str):
        if "monitoring_agents" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["monitoring_agents"] = [
                {
                    "id": "21000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "agent_name": "Edge-Perimeter-Sensor-01",
                    "hostname": "fw-01.edge.nexus.internal",
                    "ip_address": "192.168.10.1",
                    "mac_address": "00:1A:2B:3C:4D:5E",
                    "os_type": "Linux Ubuntu 22.04 LTS",
                    "agent_version": "1.2.0",
                    "api_key_hash": hashlib.sha256("cs_mon_test_key_edge_01".encode()).hexdigest(),
                    "api_key_prefix": "cs_mon_test",
                    "status": "Active",
                    "last_heartbeat_at": now,
                    "registered_at": "2026-10-01T00:00:00Z",
                    "config": {"reporting_interval_seconds": 30, "capture_telemetry": True, "capture_system_metrics": True},
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "21000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "agent_name": "DB-Core-Telemetry-Agent",
                    "hostname": "db-01.core.nexus.internal",
                    "ip_address": "192.168.10.2",
                    "mac_address": "00:1A:2B:3C:4D:5F",
                    "os_type": "Linux Debian 12",
                    "agent_version": "1.2.0",
                    "api_key_hash": hashlib.sha256("cs_mon_test_key_db_02".encode()).hexdigest(),
                    "api_key_prefix": "cs_mon_test",
                    "status": "Active",
                    "last_heartbeat_at": now,
                    "registered_at": "2026-10-01T00:00:00Z",
                    "config": {"reporting_interval_seconds": 30, "capture_telemetry": True, "capture_system_metrics": True},
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "monitoring_rules" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["monitoring_rules"] = [
                {
                    "id": "22000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "rule_name": "Excessive Network Byte Volume Spike",
                    "rule_type": "traffic_spike",
                    "description": "Flags sudden flow volumes exceeding 5MB within observation window",
                    "severity": "High",
                    "threshold": 5000000.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {"max_mb": 5},
                    "last_triggered_at": "2026-10-31T14:30:00Z",
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "22000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "rule_name": "Unauthorized High-Risk Port Ingress",
                    "rule_type": "unexpected_port",
                    "description": "Alerts on ingress connections to unapproved ports (4444, 1337, 6667, 31337)",
                    "severity": "High",
                    "threshold": 1.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {"restricted_ports": [4444, 1337, 6667, 31337, 8888, 3389]},
                    "last_triggered_at": "2026-10-31T14:32:00Z",
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "22000000-0000-0000-0000-000000000003",
                    "organization_id": org_id,
                    "rule_name": "Suspicious Outbound Connection",
                    "rule_type": "suspicious_outbound",
                    "description": "Detects outbound sessions directed at external exploit listeners",
                    "severity": "Critical",
                    "threshold": 1.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {},
                    "last_triggered_at": None,
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "device_health_metrics" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["device_health_metrics"] = [
                {
                    "id": "23000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "cpu_utilization_pct": 34.5,
                    "memory_utilization_pct": 58.2,
                    "disk_utilization_pct": 42.1,
                    "network_interface_status": "Up",
                    "health_state": "Healthy",
                    "recorded_at": now,
                },
                {
                    "id": "23000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000002",
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "cpu_utilization_pct": 78.4,
                    "memory_utilization_pct": 82.1,
                    "disk_utilization_pct": 88.5,
                    "network_interface_status": "Up",
                    "health_state": "Warning",
                    "recorded_at": now,
                }
            ]

        if "network_anomalies" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["network_anomalies"] = [
                {
                    "id": "24000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "source_asset": "192.168.10.1",
                    "event_category": "unexpected_port",
                    "severity": "High",
                    "rule_name": "Unauthorized High-Risk Port Ingress",
                    "rule_id": "22000000-0000-0000-0000-000000000002",
                    "evidence": {
                        "destination_port": 4444,
                        "service_tag": "Metasploit/Suspicious",
                        "source_ip": "198.51.100.42",
                        "destination_ip": "192.168.10.1",
                        "protocol": "TCP",
                    },
                    "confidence": 92,
                    "recommended_investigation": "Inspect firewall gateway logs for unauthorized ingress probe on Metasploit port 4444 from 198.51.100.42.",
                    "status": "Open",
                    "detected_at": "2026-10-31T14:32:00Z",
                    "created_at": "2026-10-31T14:32:00Z",
                },
                {
                    "id": "24000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "source_asset": "192.168.10.2",
                    "event_category": "traffic_spike",
                    "severity": "Medium",
                    "rule_name": "Excessive Network Byte Volume Spike",
                    "rule_id": "22000000-0000-0000-0000-000000000001",
                    "evidence": {
                        "byte_count": 14800000,
                        "threshold": 5000000.0,
                        "source_ip": "192.168.10.2",
                        "destination_ip": "203.0.113.195",
                        "packet_count": 11200,
                    },
                    "confidence": 85,
                    "recommended_investigation": "Audit sudden 14.8 MB database backup sync to external destination 203.0.113.195.",
                    "status": "Open",
                    "detected_at": "2026-10-31T14:30:00Z",
                    "created_at": "2026-10-31T14:30:00Z",
                }
            ]

        if "network_telemetry" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["network_telemetry"] = [
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "interface": "eth0",
                    "source_ip": "192.168.10.1",
                    "destination_ip": "1.1.1.1",
                    "protocol": "DNS",
                    "source_port": 54210,
                    "destination_port": 53,
                    "packet_count": 45,
                    "byte_count": 4820,
                    "direction": "Outbound",
                    "captured_at": now,
                    "created_at": now,
                },
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "interface": "eth0",
                    "source_ip": "203.0.113.88",
                    "destination_ip": "192.168.10.1",
                    "protocol": "HTTPS",
                    "source_port": 49210,
                    "destination_port": 443,
                    "packet_count": 320,
                    "byte_count": 420000,
                    "direction": "Inbound",
                    "captured_at": now,
                    "created_at": now,
                },
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000002",
                    "interface": "eth0",
                    "source_ip": "192.168.10.2",
                    "destination_ip": "192.168.10.1",
                    "protocol": "TCP",
                    "source_port": 5432,
                    "destination_port": 5432,
                    "packet_count": 890,
                    "byte_count": 1820000,
                    "direction": "Internal",
                    "captured_at": now,
                    "created_at": now,
                }
            ]

    async def create_monitoring_agent(self, agent_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(agent_record["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_agents", []).insert(0, agent_record)
        return agent_record

    async def get_monitoring_agents(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [a for a in _mock_db.get("monitoring_agents", []) if str(a.get("organization_id")) == str(org_id)]

    async def get_monitoring_agent_by_id(self, agent_id: str) -> Optional[Dict[str, Any]]:
        for a in _mock_db.get("monitoring_agents", []):
            if str(a.get("id")) == str(agent_id):
                return a
        return None

    async def update_monitoring_agent_heartbeat(self, agent_id: str, heartbeat_at: str) -> bool:
        for a in _mock_db.get("monitoring_agents", []):
            if str(a.get("id")) == str(agent_id):
                a["last_heartbeat_at"] = heartbeat_at
                a["updated_at"] = heartbeat_at
                return True
        return False

    async def bulk_create_telemetry(self, telemetry_records: List[Dict[str, Any]]) -> int:
        if not telemetry_records:
            return 0
        org_id = str(telemetry_records[0]["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("network_telemetry", []).extend(telemetry_records)
        return len(telemetry_records)

    async def get_network_telemetry(self, org_id: str, time_window_seconds: int = 3600) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [t for t in _mock_db.get("network_telemetry", []) if str(t.get("organization_id")) == str(org_id)]

    async def create_device_health_metric(self, metric_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(metric_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("device_health_metrics", []).insert(0, metric_data)
        return metric_data

    async def get_latest_device_health_metrics(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        all_metrics = [m for m in _mock_db.get("device_health_metrics", []) if str(m.get("organization_id")) == str(org_id)]
        # deduplicate by agent_id (latest first)
        latest_by_agent: Dict[str, Dict[str, Any]] = {}
        for m in all_metrics:
            ag_id = m.get("agent_id")
            if ag_id and ag_id not in latest_by_agent:
                latest_by_agent[ag_id] = m
        return list(latest_by_agent.values())

    async def create_network_anomaly(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(anomaly_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("network_anomalies", []).insert(0, anomaly_data)
        return anomaly_data

    async def get_network_anomalies(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        anomalies = [a for a in _mock_db.get("network_anomalies", []) if str(a.get("organization_id")) == str(org_id)]
        if status:
            anomalies = [a for a in anomalies if a.get("status") == status]
        return anomalies

    async def create_monitoring_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(rule_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_rules", []).insert(0, rule_data)
        return rule_data

    async def get_monitoring_rules(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [r for r in _mock_db.get("monitoring_rules", []) if str(r.get("organization_id")) == str(org_id)]

    async def update_monitoring_rule(self, org_id: str, rule_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        for r in _mock_db.get("monitoring_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        r[k] = v
                r["updated_at"] = datetime.utcnow().isoformat() + "Z"
                return r
        return None

    async def create_monitoring_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(event_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_events", []).insert(0, event_data)
        return event_data

    async def get_monitoring_events(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        events = [e for e in _mock_db.get("monitoring_events", []) if str(e.get("organization_id")) == str(org_id)]
        return events[:limit]

    async def get_latest_telemetry_timestamp(self, org_id: str) -> Optional[str]:
        self._ensure_monitoring_seeds(org_id)
        telemetry = _mock_db.get("network_telemetry", [])
        for t in reversed(telemetry):
            if str(t.get("organization_id")) == str(org_id):
                return t.get("captured_at")
        return None

    # --------------------------------------------------------------------------
    # SPRINT 13: SECURITY ORCHESTRATION, AUTOMATION & RESPONSE (SOAR)
    # --------------------------------------------------------------------------
    def _ensure_soar_seeds(self, org_id: str):
        if "soar_workflows" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_workflows"] = [
                {
                    "id": "31000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "name": "Suspicious Login Response",
                    "description": "Correlates repeated authentication failures, alerts analyst, and requests account suspension",
                    "category": "identity_access",
                    "trigger_type": "repeated_auth_failures",
                    "trigger_conditions": {"failure_threshold": 3, "window_seconds": 300},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Auth Failure Burst", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "condition", "name": "Verify Failure Count > 3", "parameters": {"field": "severity", "value": "High"}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "asset_lookup", "name": "Enrich Ingress Host Info", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "create_incident", "name": "Open Unauthorized Access Incident", "parameters": {"title": "Credential Stuffing Incident"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "send_notification", "name": "Dispatch SOC On-Call Alert", "parameters": {"channel": "in_app"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "request_approval", "name": "Request Targeted Account Lockout", "parameters": {"action_type": "account_suspension", "justification": "Credential stuffing lock"}},
                        {"id": str(uuid4()), "step_order": 7, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "name": "Malware Alert Investigation",
                    "description": "Correlates critical malware alerts against threat intelligence and creates formal case file",
                    "category": "incident_response",
                    "trigger_type": "new_critical_alert",
                    "trigger_conditions": {"severity": "Critical"},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Critical Malware Alert", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Correlate IOC Threat Reputation", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "vulnerability_lookup", "name": "Check Host CVE Exposure", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "create_incident", "name": "Escalate to P1 Incident", "parameters": {"title": "Malware Breach Incident"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request Host Network Quarantine", "parameters": {"action_type": "asset_isolation", "justification": "Active malware propagation defense"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "generate_report", "name": "Generate Forensic Summary", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 7, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000003",
                    "organization_id": org_id,
                    "name": "Critical Vulnerability Remediation Escalation",
                    "description": "Triages newly discovered high-severity CVEs against CISA KEV catalog and assigns engineers",
                    "category": "vulnerability_management",
                    "trigger_type": "new_high_vulnerability",
                    "trigger_conditions": {"min_cvss": 9.0},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on CVE Finding", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "severity_check", "name": "Verify CVSS >= 9.0", "parameters": {"min_severity": "Critical"}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "asset_lookup", "name": "Locate Production Assets", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "assign_analyst", "name": "Assign Infrastructure Lead", "parameters": {"analyst_name": "Elena Rostova (SecOps Lead)"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request Emergency Hotfix Approval", "parameters": {"action_type": "vulnerability_remediation", "justification": "CISA KEV weaponized exploit"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000004",
                    "organization_id": org_id,
                    "name": "Suspicious Network Traffic & C2 Investigation",
                    "description": "Automated triage of anomalous egress flows directed at external listening ports",
                    "category": "network_security",
                    "trigger_type": "suspicious_network_activity",
                    "trigger_conditions": {"ports": [4444, 1337]},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Anomaly", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Query AlienVault OTX & CISA", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "add_incident_note", "name": "Document Traffic Signatures", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "request_approval", "name": "Request Perimeter Egress Block", "parameters": {"action_type": "firewall_rule_review", "justification": "Egress flow on port 4444"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000005",
                    "organization_id": org_id,
                    "name": "Phishing Email Indicator Triage",
                    "description": "Extracts domains and URL indicators, checks URLhaus, and notifies the team",
                    "category": "threat_hunting",
                    "trigger_type": "threat_intel_ioc_match",
                    "trigger_conditions": {"category": "phishing"},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on IOC Match", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Query URLhaus Database", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "create_incident", "name": "Open Phishing Incident", "parameters": {"title": "Phishing Campaign Ingress"}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "send_notification", "name": "Broadcast Email Advisory", "parameters": {"channel": "email"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request DNS Sinkhole / Domain Block", "parameters": {"action_type": "block_indicator", "justification": "Active phishing domain defense"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "soar_action_approvals" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_action_approvals"] = [
                {
                    "id": "32000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "execution_id": "33000000-0000-0000-0000-000000000001",
                    "workflow_name": "Suspicious Login Response",
                    "action_type": "account_suspension",
                    "target_resource": "dev-user-svc@apexcyberdefense.io",
                    "justification": "12 failed Kerberos authentications within 90 seconds from unapproved subnet",
                    "requested_by": "00000000-0000-0000-0000-000000000001",
                    "approver_id": None,
                    "decision": "Pending",
                    "decision_notes": None,
                    "decided_at": None,
                    "created_at": now,
                    "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z",
                    "execution_result": {},
                }
            ]

        if "soar_workflow_executions" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_workflow_executions"] = [
                {
                    "id": "33000000-0000-0000-0000-000000000001",
                    "workflow_id": "31000000-0000-0000-0000-000000000001",
                    "workflow_name": "Suspicious Login Response",
                    "organization_id": org_id,
                    "trigger_source": "repeated_auth_failures",
                    "status": "Waiting_Approval",
                    "started_at": now,
                    "completed_at": None,
                    "duration_ms": 680,
                    "context_data": {"user": "dev-user-svc", "ip": "198.51.100.42", "severity": "High"},
                    "error_message": None,
                    "retry_count": 0,
                    "triggered_by": "00000000-0000-0000-0000-000000000001",
                    "created_at": now,
                    "steps": [
                        {
                            "id": str(uuid4()),
                            "step_name": "Trigger on Auth Failure Burst",
                            "step_type": "trigger",
                            "status": "Completed",
                            "started_at": now,
                            "completed_at": now,
                            "input_payload": {},
                            "output_payload": {"acknowledged": True},
                        },
                        {
                            "id": str(uuid4()),
                            "step_name": "Request Targeted Account Lockout",
                            "step_type": "request_approval",
                            "status": "Waiting_Approval",
                            "started_at": now,
                            "completed_at": now,
                            "input_payload": {"action": "account_suspension"},
                            "output_payload": {"status": "Pending"},
                        },
                    ],
                    "logs": [
                        {
                            "id": str(uuid4()),
                            "timestamp": now,
                            "log_level": "INFO",
                            "message": "Playbook 'Suspicious Login Response' initiated by event correlation engine",
                            "payload": {},
                        },
                        {
                            "id": str(uuid4()),
                            "timestamp": now,
                            "log_level": "INFO",
                            "message": "Disruptive action 'account_suspension' requires SOC analyst authorization",
                            "payload": {},
                        },
                    ],
                }
            ]

    async def create_soar_workflow(self, wf_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(wf_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_workflows", []).insert(0, wf_record)
        return wf_record

    async def get_soar_workflows(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        wfs = [w for w in _mock_db.get("soar_workflows", []) if str(w.get("organization_id")) == str(org_id)]
        if status:
            wfs = [w for w in wfs if w.get("status") == status]
        return wfs

    async def get_soar_workflow_by_id(self, org_id: str, workflow_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for w in _mock_db.get("soar_workflows", []):
            if str(w.get("id")) == str(workflow_id) and str(w.get("organization_id")) == str(org_id):
                return w
        return None

    async def update_soar_workflow(self, org_id: str, workflow_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for w in _mock_db.get("soar_workflows", []):
            if str(w.get("id")) == str(workflow_id) and str(w.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        w[k] = v
                w["updated_at"] = datetime.utcnow().isoformat() + "Z"
                return w
        return None

    async def create_soar_execution(self, execution_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(execution_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_workflow_executions", []).insert(0, execution_record)
        return execution_record

    async def get_soar_executions(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        execs = [e for e in _mock_db.get("soar_workflow_executions", []) if str(e.get("organization_id")) == str(org_id)]
        if status:
            execs = [e for e in execs if e.get("status") == status]
        return execs

    async def get_soar_execution_by_id(self, org_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for e in _mock_db.get("soar_workflow_executions", []):
            if str(e.get("id")) == str(execution_id) and str(e.get("organization_id")) == str(org_id):
                return e
        return None

    async def update_soar_execution(self, org_id: str, execution_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for e in _mock_db.get("soar_workflow_executions", []):
            if str(e.get("id")) == str(execution_id) and str(e.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        e[k] = v
                return e
        return None

    async def create_soar_approval(self, approval_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(approval_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_action_approvals", []).insert(0, approval_record)
        return approval_record

    async def get_soar_approvals(self, org_id: str, decision: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        approvals = [a for a in _mock_db.get("soar_action_approvals", []) if str(a.get("organization_id")) == str(org_id)]
        if decision:
            approvals = [a for a in approvals if a.get("decision") == decision]
        return approvals

    async def get_soar_approval_by_id(self, org_id: str, approval_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for a in _mock_db.get("soar_action_approvals", []):
            if str(a.get("id")) == str(approval_id) and str(a.get("organization_id")) == str(org_id):
                return a
        return None

    async def update_soar_approval(self, org_id: str, approval_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for a in _mock_db.get("soar_action_approvals", []):
            if str(a.get("id")) == str(approval_id) and str(a.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        a[k] = v
                return a
        return None

    async def get_soar_notification_templates(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "Critical Security Incident Alert",
                "channel": "email",
                "subject": "[CRITICAL] {{incident_title}} Detected by CyberShield SOAR",
                "body_template": "An automated response playbook has triaged high-severity activity on {{asset_name}}.",
                "is_default": True,
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "SOAR Action Approval Request",
                "channel": "in_app",
                "subject": "Authorization Needed: {{action_type}}",
                "body_template": "Playbook {{playbook_name}} requires analyst approval to execute {{action_type}} on {{target}}.",
                "is_default": True,
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "SIEM / Webhook Dispatcher",
                "channel": "webhook",
                "subject": None,
                "body_template": '{"event": "soar_execution", "status": "{{status}}", "playbook": "{{playbook_name}}"}',
                "is_default": False,
                "created_at": datetime.utcnow().isoformat() + "Z",
            }
        ]

    async def create_soar_notification_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("soar_notification_deliveries", []).insert(0, delivery)
        return delivery

    # --------------------------------------------------------------------------
    # SPRINT 14: AI THREAT DETECTION, UEBA & PREDICTIVE INTELLIGENCE
    # --------------------------------------------------------------------------
    def _ensure_ai_detection_seeds(self, org_id: str):
        if _mock_db.get(f"ai_detection_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc).isoformat()

        # 1. Models Registry
        m1_id = "d0000001-0000-0000-0000-000000000001"
        m2_id = "d0000002-0000-0000-0000-000000000002"
        m3_id = "d0000003-0000-0000-0000-000000000003"

        models = [
            {
                "id": m1_id,
                "organization_id": org_id,
                "model_name": "IsolationForest-NetworkAnomalies",
                "model_type": "isolation_forest",
                "description": "Unsupervised ensemble anomaly detector identifying out-of-profile egress and telemetry spikes",
                "active_version": "1.0.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.915,
                    "recall": 0.884,
                    "f1_score": 0.899,
                    "false_positive_rate": 0.042,
                    "detection_rate": 0.884,
                },
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": m2_id,
                "organization_id": org_id,
                "model_name": "UEBA-Statistical-Baseline",
                "model_type": "statistical_baseline",
                "description": "Rolling 14-day asset behavior baseline model detecting z-score variance in authentication and connection frequency",
                "active_version": "2.1.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.892,
                    "recall": 0.920,
                    "f1_score": 0.906,
                    "false_positive_rate": 0.051,
                    "detection_rate": 0.920,
                },
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": m3_id,
                "organization_id": org_id,
                "model_name": "RuleEnsemble-ThreatHeuristics",
                "model_type": "rule_engine",
                "description": "Deterministic rule correlation engine evaluating IOC feeds, high-risk destination ports, and rapid brute force attempts",
                "active_version": "1.4.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.960,
                    "recall": 0.840,
                    "f1_score": 0.896,
                    "false_positive_rate": 0.018,
                    "detection_rate": 0.840,
                },
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_models", []).extend(models)

        # Versions
        versions = [
            {
                "id": str(uuid4()),
                "model_id": m1_id,
                "version": "1.0.0",
                "dataset_reference": "netflow_enterprise_baseline_v1",
                "training_samples_count": 4500,
                "hyperparameters": {"n_estimators": 100, "contamination": 0.08},
                "evaluation_metrics": {"precision": 0.915, "recall": 0.884, "f1_score": 0.899},
                "is_active": True,
                "trained_at": now,
                "deployed_at": now,
            },
            {
                "id": str(uuid4()),
                "model_id": m2_id,
                "version": "2.1.0",
                "dataset_reference": "ueba_auth_telemetry_v2",
                "training_samples_count": 6200,
                "hyperparameters": {"window_days": 14, "sigma_threshold": 3.0},
                "evaluation_metrics": {"precision": 0.892, "recall": 0.920, "f1_score": 0.906},
                "is_active": True,
                "trained_at": now,
                "deployed_at": now,
            },
        ]
        _mock_db.setdefault("ai_model_versions", []).extend(versions)

        # 2. Rules
        rules = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Excessive Outbound Egress Volume",
                "rule_type": "statistical_threshold",
                "description": "Flags assets transmitting >10MB outbound in 5 minutes exceeding 3.0x historical baseline",
                "severity": "Critical",
                "data_sources": ["network_monitoring", "agent_telemetry"],
                "threshold_config": {"egress_bytes_window": 10485760, "window_minutes": 5},
                "evaluation_interval_seconds": 180,
                "is_enabled": True,
                "matched_events_count": 14,
                "false_positive_count": 1,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Repeated SSH/RDP Auth Failures",
                "rule_type": "behavioral_deviation",
                "description": "Identifies brute-force authentication spikes with failed attempt ratio > 80%",
                "severity": "High",
                "data_sources": ["auth_events"],
                "threshold_config": {"failed_attempts": 5, "window_seconds": 60},
                "evaluation_interval_seconds": 60,
                "is_enabled": True,
                "matched_events_count": 28,
                "false_positive_count": 2,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "High-Risk Destination Port Probing",
                "rule_type": "ioc_matching",
                "description": "Detects internal connections to C2 staging ports 4444, 1337, or unexpected SMB/RDP egress",
                "severity": "High",
                "data_sources": ["network_monitoring"],
                "threshold_config": {"monitored_ports": [4444, 1337, 8888, 3389]},
                "evaluation_interval_seconds": 300,
                "is_enabled": True,
                "matched_events_count": 6,
                "false_positive_count": 0,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Anomalous Protocol Entropy Spike",
                "rule_type": "event_correlation",
                "description": "Flags hosts communicating across erratic port distributions indicating network reconnaissance",
                "severity": "Medium",
                "data_sources": ["network_monitoring"],
                "threshold_config": {"entropy_threshold": 2.2},
                "evaluation_interval_seconds": 600,
                "is_enabled": True,
                "matched_events_count": 9,
                "false_positive_count": 1,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_rules", []).extend(rules)

        # 3. Detection Results
        d1_id = "e0000001-0000-0000-0000-000000000001"
        d2_id = "e0000002-0000-0000-0000-000000000002"
        d3_id = "e0000003-0000-0000-0000-000000000003"
        d4_id = "e0000004-0000-0000-0000-000000000004"

        detections = [
            {
                "id": d1_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000001",
                "source_asset_name": "Core-App-Cluster-Node-01",
                "detection_category": "suspicious_outbound",
                "severity": "Critical",
                "confidence_score": 0.92,
                "anomaly_score": 0.88,
                "detection_method": "ml_isolation_forest",
                "supporting_evidence": {
                    "outbound_bytes": 14200000,
                    "baseline_mean_bytes": 450000,
                    "sigma_deviation": 3.42,
                    "unique_destinations": 48,
                    "target_protocol": "TCP/4444",
                },
                "recommended_investigation": "Inspect endpoint process tree on 192.168.10.15 for unauthorized sockets and verify C2 feed matches.",
                "model_version": "1.0.0",
                "status": "investigating",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d2_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000002",
                "source_asset_name": "Auth-Gateway-Proxy-02",
                "detection_category": "repeated_auth_failures",
                "severity": "High",
                "confidence_score": 0.89,
                "anomaly_score": 0.79,
                "detection_method": "ueba_behavioral",
                "supporting_evidence": {
                    "failed_attempts": 32,
                    "window_seconds": 60,
                    "target_service": "SSH/22",
                    "origin_subnets": ["198.51.100.0/24"],
                },
                "recommended_investigation": "Review authentication audit logs and check for automated credential brute-forcing.",
                "model_version": "2.1.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d3_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000003",
                "source_asset_name": "DMZ-Edge-Firewall",
                "detection_category": "unusual_port",
                "severity": "Medium",
                "confidence_score": 0.84,
                "anomaly_score": 0.68,
                "detection_method": "statistical_baseline",
                "supporting_evidence": {
                    "unusual_ports": [8089, 9001],
                    "historical_frequency": 0.02,
                },
                "recommended_investigation": "Verify whether management interface ports were opened for authorized telemetry.",
                "model_version": "1.0.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d4_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000004",
                "source_asset_name": "Workstation-Engineering-14",
                "detection_category": "threat_intel_match",
                "severity": "High",
                "confidence_score": 0.95,
                "anomaly_score": 0.85,
                "detection_method": "deterministic_rule",
                "supporting_evidence": {
                    "matched_ioc": "198.51.100.23",
                    "ioc_type": "ipv4",
                    "feed_name": "EmergingThreats C2 Feed",
                },
                "recommended_investigation": "Isolate engineering workstation and scan for payload dropper execution.",
                "model_version": "1.4.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_results", []).extend(detections)

        # 4. Investigations
        investigations = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "detection_id": d1_id,
                "status": "Reviewing",
                "assigned_analyst": "00000000-0000-0000-0000-000000000001",
                "analyst_notes": "Forensic memory dump acquired. Investigating parent process for port 4444 outbound connection.",
                "findings_summary": "Process python3 spawning /bin/sh reverse shell.",
                "timeline_events": [
                    {"timestamp": now, "actor": "IsolationForest Engine", "action": "Anomaly detected (score 0.88)"},
                    {"timestamp": now, "actor": "Senior Analyst", "action": "Assigned to case and initiated triage"},
                ],
                "confirmed_at": None,
                "resolved_at": None,
                "created_at": now,
                "updated_at": now,
            }
        ]
        _mock_db.setdefault("ai_detection_investigations", []).extend(investigations)

        # 5. Risk Predictions
        predictions = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000001",
                "asset_name": "Core-App-Cluster-Node-01",
                "asset_ip": "192.168.10.15",
                "risk_score": 86,
                "risk_level": "Critical",
                "risk_trend": "increasing",
                "contributing_factors": [
                    {"factor": "Known Exploited Vulnerability", "impact": "+25", "detail": "CVE-2024-3400 (CISA KEV)"},
                    {"factor": "Suspicious Outbound Telemetry", "impact": "+20", "detail": "14.2 MB burst to unmapped external IP"},
                    {"factor": "Asset Criticality Tier", "impact": "+15", "detail": "Production Application Node"},
                    {"factor": "Multi-Port Probe Activity", "impact": "+10", "detail": "Elevated protocol entropy"},
                ],
                "confidence_score": 0.92,
                "data_coverage_score": 0.89,
                "recommended_remediation_priority": "P1",
                "predicted_at": now,
                "created_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000002",
                "asset_name": "Auth-Gateway-Proxy-02",
                "asset_ip": "192.168.10.22",
                "risk_score": 72,
                "risk_level": "High",
                "risk_trend": "increasing",
                "contributing_factors": [
                    {"factor": "Repeated Authentication Failures", "impact": "+25", "detail": "32 failed SSH attempts in 60s"},
                    {"factor": "Internet-Facing Boundary", "impact": "+15", "detail": "Direct public ingress on port 22"},
                ],
                "confidence_score": 0.88,
                "data_coverage_score": 0.85,
                "recommended_remediation_priority": "P2",
                "predicted_at": now,
                "created_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000003",
                "asset_name": "DMZ-Edge-Firewall",
                "asset_ip": "192.168.10.1",
                "risk_score": 45,
                "risk_level": "Medium",
                "risk_trend": "stable",
                "contributing_factors": [
                    {"factor": "Unusual Port Telemetry", "impact": "+15", "detail": "Ports 8089, 9001 detected"},
                    {"factor": "Up-to-Date Patch Compliance", "impact": "-10", "detail": "Zero unresolved CVEs"},
                ],
                "confidence_score": 0.84,
                "data_coverage_score": 0.92,
                "recommended_remediation_priority": "P3",
                "predicted_at": now,
                "created_at": now,
            },
        ]
        _mock_db.setdefault("ai_risk_predictions", []).extend(predictions)

        _mock_db[f"ai_detection_seeded_{org_id}"] = True

    async def get_ai_detection_models(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [m for m in _mock_db.get("ai_detection_models", []) if str(m.get("organization_id")) == str(org_id)]

    async def create_ai_detection_model(self, model: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_models", []).insert(0, model)
        return model

    async def get_ai_model_versions(self, org_id: str, model_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [v for v in _mock_db.get("ai_model_versions", []) if str(v.get("model_id")) == str(model_id)]

    async def create_ai_model_version(self, version: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_model_versions", []).insert(0, version)
        return version

    async def get_ai_detection_rules(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [r for r in _mock_db.get("ai_detection_rules", []) if str(r.get("organization_id")) == str(org_id)]

    async def get_ai_detection_rule_by_id(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for r in _mock_db.get("ai_detection_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                return r
        return None

    async def create_ai_detection_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_rules", []).insert(0, rule)
        return rule

    async def update_ai_detection_rule(self, org_id: str, rule_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for r in _mock_db.get("ai_detection_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        r[k] = v
                return r
        return None

    async def get_ai_detection_results(
        self, org_id: str, category: Optional[str] = None, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        res = [d for d in _mock_db.get("ai_detection_results", []) if str(d.get("organization_id")) == str(org_id)]
        if category:
            res = [d for d in res if d.get("detection_category") == category]
        if severity:
            res = [d for d in res if d.get("severity") == severity]
        return res

    async def get_ai_detection_result_by_id(self, org_id: str, detection_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for d in _mock_db.get("ai_detection_results", []):
            if str(d.get("id")) == str(detection_id) and str(d.get("organization_id")) == str(org_id):
                return d
        return None

    async def create_ai_detection_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_results", []).insert(0, result)
        return result

    async def update_ai_detection_result(self, org_id: str, detection_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for d in _mock_db.get("ai_detection_results", []):
            if str(d.get("id")) == str(detection_id) and str(d.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        d[k] = v
                return d
        return None

    async def get_ai_detection_investigations(self, org_id: str, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        invs = [i for i in _mock_db.get("ai_detection_investigations", []) if str(i.get("organization_id")) == str(org_id)]
        if status_filter:
            invs = [i for i in invs if i.get("status") == status_filter]
        return invs

    async def get_ai_detection_investigation_by_id(self, org_id: str, inv_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for i in _mock_db.get("ai_detection_investigations", []):
            if str(i.get("id")) == str(inv_id) and str(i.get("organization_id")) == str(org_id):
                return i
        return None

    async def create_ai_detection_investigation(self, inv: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_investigations", []).insert(0, inv)
        return inv

    async def update_ai_detection_investigation(self, org_id: str, inv_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for i in _mock_db.get("ai_detection_investigations", []):
            if str(i.get("id")) == str(inv_id) and str(i.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        i[k] = v
                return i
        return None

    async def create_ai_detection_feedback(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_feedback", []).insert(0, feedback)
        return feedback

    async def get_ai_risk_predictions(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [p for p in _mock_db.get("ai_risk_predictions", []) if str(p.get("organization_id")) == str(org_id)]

    # --------------------------------------------------------------------------
    # SPRINT 15: ENTERPRISE INTEGRATIONS & EXTERNAL SECURITY ECOSYSTEM
    # --------------------------------------------------------------------------
    def _ensure_integrations_seeds(self, org_id: str):
        if _mock_db.get(f"integrations_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc).isoformat()

        int1_id = "f0000001-0000-0000-0000-000000000001"
        int2_id = "f0000002-0000-0000-0000-000000000002"
        int3_id = "f0000003-0000-0000-0000-000000000003"
        int4_id = "f0000004-0000-0000-0000-000000000004"
        int5_id = "f0000005-0000-0000-0000-000000000005"
        int6_id = "f0000006-0000-0000-0000-000000000006"

        integrations = [
            {
                "id": int1_id,
                "organization_id": org_id,
                "name": "Splunk Enterprise SIEM",
                "slug": "splunk",
                "category": "siem",
                "provider": "Splunk",
                "description": "HTTP Event Collector (HEC) forwarder streaming normalized security alerts and incidents to Splunk SIEM",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"endpoint_url": "https://splunk-hec.corp.internal:8088/services/collector", "index": "cybershield_events"},
                "secret_masked": "hec_...9x4b",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int2_id,
                "organization_id": org_id,
                "name": "Microsoft Sentinel",
                "slug": "sentinel",
                "category": "siem",
                "provider": "Microsoft",
                "description": "Log Analytics ingestion connector synchronizing anomalous threat detections and SOAR executions",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"workspace_id": "ws-sec-88091", "log_type": "CyberShieldSecurityEvents"},
                "secret_masked": "ms_k...4k2p",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int3_id,
                "organization_id": org_id,
                "name": "Slack Incident Operations",
                "slug": "slack",
                "category": "communication",
                "provider": "Slack",
                "description": "Real-time critical alert dispatch, incident escalation notices, and human-in-the-loop approval requests",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"channel": "#soc-incident-war-room", "alert_severity_threshold": "High"},
                "secret_masked": "xoxb...8921",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int4_id,
                "organization_id": org_id,
                "name": "Microsoft Teams SOC Bridge",
                "slug": "teams",
                "category": "communication",
                "provider": "Microsoft",
                "description": "Interactive webhook notifications for security event correlation and SOAR containment gates",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"channel": "SOC Team Operations", "webhook_url": "https://outlook.office.com/webhook/sec"},
                "secret_masked": "mste...1102",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int5_id,
                "organization_id": org_id,
                "name": "CISA Known Exploited Vulnerabilities",
                "slug": "cisa_kev",
                "category": "threat_intelligence",
                "provider": "CISA",
                "description": "Automated synchronization of actively exploited zero-day and CVE catalogs",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "sync_interval_hours": 6},
                "secret_masked": None,
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int6_id,
                "organization_id": org_id,
                "name": "AWS Security & CloudTrail",
                "slug": "aws_security",
                "category": "cloud_security",
                "provider": "AWS",
                "description": "Read-only inventory sync and GuardDuty finding correlation without destructive infrastructure modification",
                "connection_status": "Pending_Configuration",
                "is_enabled": False,
                "health_status": "Healthy",
                "config": {"region": "us-east-1", "iam_role_arn": "arn:aws:iam::123456789012:role/CyberShieldReadOnlyAudit"},
                "secret_masked": None,
                "last_synced_at": None,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("integrations", []).extend(integrations)

        # Webhook Endpoints
        wh1_id = "a0000001-0000-0000-0000-000000000001"
        wh2_id = "a0000002-0000-0000-0000-000000000002"

        webhooks = [
            {
                "id": wh1_id,
                "organization_id": org_id,
                "name": "Corporate SIEM Syslog Webhook Bridge",
                "url": "https://siem-collector.apexcorp.com/hooks/v1",
                "description": "Delivers JSON security alerts and containment decisions to central SOC infrastructure",
                "secret_token": "whsec_9876543210abcdef9876543210abcdef",
                "is_active": True,
                "events": ["alert.created", "incident.created", "soar.execution_completed"],
                "retry_limit": 3,
                "timeout_seconds": 10,
                "failure_count": 0,
                "last_triggered_at": now,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": wh2_id,
                "organization_id": org_id,
                "name": "Jira IT Service Management Webhook",
                "url": "https://jira.apexcorp.com/rest/api/2/issue",
                "description": "Auto-creates service management escalation tickets upon confirmed high-severity incidents",
                "secret_token": "whsec_1234567890abcdef1234567890abcdef",
                "is_active": True,
                "events": ["incident.created", "compliance.updated"],
                "retry_limit": 3,
                "timeout_seconds": 10,
                "failure_count": 0,
                "last_triggered_at": now,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("webhook_endpoints", []).extend(webhooks)

        # Delivery Logs
        logs = [
            {
                "id": str(uuid4()),
                "integration_id": int1_id,
                "organization_id": org_id,
                "integration_name": "Splunk Enterprise SIEM",
                "event_type": "alert_export",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"alert_id": "ALT-2026-0812", "severity": "High", "asset": "192.168.10.15"},
                "error_summary": None,
                "duration_ms": 35,
                "delivered_at": now,
            },
            {
                "id": str(uuid4()),
                "integration_id": int3_id,
                "organization_id": org_id,
                "integration_name": "Slack Incident Operations",
                "event_type": "notification_dispatch",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"incident_id": "INC-2026-0042", "urgency": "High", "channel": "#soc-incident-war-room"},
                "error_summary": None,
                "duration_ms": 42,
                "delivered_at": now,
            },
            {
                "id": str(uuid4()),
                "integration_id": int2_id,
                "organization_id": org_id,
                "integration_name": "Microsoft Sentinel",
                "event_type": "incident_sync",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"records_synced": 3, "table": "CyberShieldSecurityEvents"},
                "error_summary": None,
                "duration_ms": 56,
                "delivered_at": now,
            },
        ]
        _mock_db.setdefault("integration_delivery_logs", []).extend(logs)

        # Webhook Delivery Attempts
        attempts = [
            {
                "id": str(uuid4()),
                "webhook_id": wh1_id,
                "organization_id": org_id,
                "event_type": "alert.created",
                "idempotency_key": f"idem_{uuid4().hex[:12]}",
                "payload": {"alert_id": "ALT-2026-0812", "severity": "High"},
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_number": 1,
                "response_body": '{"status": "acknowledged", "delivery_id": "del-8819"}',
                "error_message": None,
                "duration_ms": 28,
                "created_at": now,
            }
        ]
        _mock_db.setdefault("webhook_delivery_attempts", []).extend(attempts)

        _mock_db[f"integrations_seeded_{org_id}"] = True

    async def get_integrations(self, org_id: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        items = [i for i in _mock_db.get("integrations", []) if str(i.get("organization_id")) == str(org_id)]
        if category:
            items = [i for i in items if i.get("category") == category]
        return items

    async def get_integration_by_id(self, org_id: str, integration_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for i in _mock_db.get("integrations", []):
            if str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id):
                return i
        return None

    async def create_integration(self, integration: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integrations", []).insert(0, integration)
        return integration

    async def update_integration(self, org_id: str, integration_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for i in _mock_db.get("integrations", []):
            if str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        i[k] = v
                return i
        return None

    async def delete_integration(self, org_id: str, integration_id: str) -> bool:
        self._ensure_integrations_seeds(org_id)
        existing = _mock_db.get("integrations", [])
        before_len = len(existing)
        _mock_db["integrations"] = [
            i for i in existing
            if not (str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["integrations"]) < before_len

    async def create_integration_credential(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_credentials", []).insert(0, cred)
        return cred

    async def create_integration_sync_history(self, sync_rec: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_sync_history", []).insert(0, sync_rec)
        return sync_rec

    async def get_integration_delivery_logs(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [l for l in _mock_db.get("integration_delivery_logs", []) if str(l.get("organization_id")) == str(org_id)]

    async def create_integration_delivery_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_delivery_logs", []).insert(0, log)
        return log

    async def get_webhook_endpoints(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [w for w in _mock_db.get("webhook_endpoints", []) if str(w.get("organization_id")) == str(org_id)]

    async def get_webhook_endpoint_by_id(self, org_id: str, hook_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for w in _mock_db.get("webhook_endpoints", []):
            if str(w.get("id")) == str(hook_id) and str(w.get("organization_id")) == str(org_id):
                return w
        return None

    async def create_webhook_endpoint(self, hook: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("webhook_endpoints", []).insert(0, hook)
        return hook

    async def update_webhook_endpoint(self, org_id: str, hook_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for w in _mock_db.get("webhook_endpoints", []):
            if str(w.get("id")) == str(hook_id) and str(w.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        w[k] = v
                return w
        return None

    async def get_webhook_delivery_attempts(self, org_id: str, hook_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [
            a for a in _mock_db.get("webhook_delivery_attempts", [])
            if str(a.get("organization_id")) == str(org_id) and str(a.get("webhook_id")) == str(hook_id)
        ]

    async def get_webhook_delivery_attempt_by_id(self, org_id: str, delivery_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for a in _mock_db.get("webhook_delivery_attempts", []):
            if str(a.get("id")) == str(delivery_id) and str(a.get("organization_id")) == str(org_id):
                return a
        return None

    async def update_webhook_delivery_attempt(self, org_id: str, delivery_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for a in _mock_db.get("webhook_delivery_attempts", []):
            if str(a.get("id")) == str(delivery_id) and str(a.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        a[k] = v
                return a
        return None

    async def reactivate_organization(self, org_id: str, admin_id: str) -> Optional[Dict[str, Any]]:
        org = next((o for o in _mock_db["organizations"] if str(o["id"]) == str(org_id)), None)
        if not org:
            return None
        org["status"] = "Active"
        org["suspension_reason"] = None
        log = {
            "id": str(uuid4()),
            "action": "REACTIVATE_ORGANIZATION",
            "organization_id": org_id,
            "admin_id": admin_id,
            "reason": "Administrative reactivation",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        if "platform_audit_logs" not in _mock_db:
            _mock_db["platform_audit_logs"] = []
        _mock_db["platform_audit_logs"].append(log)
        return org

    # --------------------------------------------------------------------------
    # Sprint 11: Compliance Management & Reporting
    # --------------------------------------------------------------------------
    async def get_compliance_frameworks(self) -> List[Dict[str, Any]]:
        return list(_mock_db.get("compliance_frameworks", []))

    async def get_compliance_controls(self, framework_code: Optional[str] = None) -> List[Dict[str, Any]]:
        controls = _mock_db.get("compliance_controls", [])
        if framework_code:
            controls = [c for c in controls if c.get("framework_code") == framework_code]
        return list(controls)

    async def get_compliance_controls_with_status(
        self,
        org_id: str,
        framework_code: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        controls = await self.get_compliance_controls(framework_code)
        if domain:
            controls = [c for c in controls if domain.lower() in (c.get("domain") or "").lower()]

        assessments = await self.get_compliance_assessments(org_id)
        evidence = await self.get_compliance_evidence(org_id)

        res = []
        for c in controls:
            c_copy = dict(c)
            match = next((a for a in assessments if str(a.get("control_id")) == str(c["id"])), None)
            ev_count = sum(1 for e in evidence if str(e.get("control_id")) == str(c["id"]))

            c_copy["current_status"] = match.get("status", "Not Assessed") if match else "Not Assessed"
            c_copy["assigned_owner"] = match.get("assigned_owner") if match else None
            c_copy["review_date"] = match.get("review_date") if match else None
            c_copy["notes"] = match.get("notes") if match else None
            c_copy["evidence_count"] = ev_count
            res.append(c_copy)
        return res

    async def get_compliance_assessments(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            a for a in _mock_db.get("compliance_assessments", [])
            if str(a.get("organization_id")) == str(org_id)
        ]

    async def upsert_compliance_assessment(
        self,
        org_id: str,
        control_id: str,
        status: str,
        assigned_owner: Optional[str] = None,
        review_date: Optional[str] = None,
        notes: Optional[str] = None,
        remediation_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        control = next((c for c in _mock_db.get("compliance_controls", []) if str(c["id"]) == str(control_id)), None)
        if not control:
            raise ValueError(f"Control '{control_id}' not found")

        existing = next(
            (a for a in _mock_db.get("compliance_assessments", []) if str(a.get("organization_id")) == str(org_id) and str(a.get("control_id")) == str(control_id)),
            None
        )
        now = datetime.utcnow().isoformat() + "Z"

        if existing:
            existing["status"] = status
            if assigned_owner is not None: existing["assigned_owner"] = assigned_owner
            if review_date is not None: existing["review_date"] = review_date
            if notes is not None: existing["notes"] = notes
            if remediation_notes is not None: existing["remediation_notes"] = remediation_notes
            existing["updated_at"] = now
            return existing

        new_ass = {
            "id": str(uuid4()),
            "organization_id": str(org_id),
            "control_id": str(control_id),
            "framework_id": str(control["framework_id"]),
            "framework_code": control["framework_code"],
            "control_code": control["control_id"],
            "control_title": control["title"],
            "status": status,
            "assigned_owner": assigned_owner,
            "review_date": review_date,
            "notes": notes,
            "remediation_notes": remediation_notes,
            "created_at": now,
            "updated_at": now,
        }
        _mock_db.setdefault("compliance_assessments", []).append(new_ass)
        return new_ass

    async def update_compliance_assessment(
        self, org_id: str, assessment_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        ass = next(
            (a for a in _mock_db.get("compliance_assessments", []) if str(a["id"]) == str(assessment_id) and str(a["organization_id"]) == str(org_id)),
            None
        )
        if not ass:
            return None
        for k, v in data.items():
            if v is not None:
                ass[k] = str(v) if k == "review_date" else v
        ass["updated_at"] = datetime.utcnow().isoformat() + "Z"
        return ass

    async def create_compliance_evidence(self, record: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("compliance_evidence", []).insert(0, record)
        return record

    async def get_compliance_evidence(
        self,
        org_id: str,
        control_id: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        evidence = [e for e in _mock_db.get("compliance_evidence", []) if str(e.get("organization_id")) == str(org_id)]
        if control_id:
            evidence = [e for e in evidence if str(e.get("control_id")) == str(control_id)]
        if assessment_id:
            evidence = [e for e in evidence if str(e.get("assessment_id")) == str(assessment_id)]
        return evidence

    async def delete_compliance_evidence(self, org_id: str, evidence_id: str) -> bool:
        before_len = len(_mock_db.get("compliance_evidence", []))
        _mock_db["compliance_evidence"] = [
            e for e in _mock_db.get("compliance_evidence", [])
            if not (str(e.get("id")) == str(evidence_id) and str(e.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["compliance_evidence"]) < before_len

    async def create_security_report(self, record: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("security_reports", []).insert(0, record)
        return record

    async def get_security_reports(
        self, org_id: str, report_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        reports = [r for r in _mock_db.get("security_reports", []) if str(r.get("organization_id")) == str(org_id)]
        if report_type:
            reports = [r for r in reports if r.get("report_type") == report_type]
        return reports

    async def get_security_report_by_id(
        self, org_id: str, report_id: str
    ) -> Optional[Dict[str, Any]]:
        return next(
            (r for r in _mock_db.get("security_reports", []) if str(r.get("id")) == str(report_id) and str(r.get("organization_id")) == str(org_id)),
            None
        )

    async def get_compliance_summary(self, org_id: str) -> Dict[str, Any]:
        from app.services.compliance_service import compliance_service
        return await compliance_service.get_compliance_summary(self, org_id)

    # --------------------------------------------------------------------------
    # SPRINT 12: ADVANCED NETWORK MONITORING & REAL-TIME SOC
    # --------------------------------------------------------------------------
    def _ensure_monitoring_seeds(self, org_id: str):
        if "monitoring_agents" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["monitoring_agents"] = [
                {
                    "id": "21000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "agent_name": "Edge-Perimeter-Sensor-01",
                    "hostname": "fw-01.edge.nexus.internal",
                    "ip_address": "192.168.10.1",
                    "mac_address": "00:1A:2B:3C:4D:5E",
                    "os_type": "Linux Ubuntu 22.04 LTS",
                    "agent_version": "1.2.0",
                    "api_key_hash": hashlib.sha256("cs_mon_test_key_edge_01".encode()).hexdigest(),
                    "api_key_prefix": "cs_mon_test",
                    "status": "Active",
                    "last_heartbeat_at": now,
                    "registered_at": "2026-10-01T00:00:00Z",
                    "config": {"reporting_interval_seconds": 30, "capture_telemetry": True, "capture_system_metrics": True},
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "21000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "agent_name": "DB-Core-Telemetry-Agent",
                    "hostname": "db-01.core.nexus.internal",
                    "ip_address": "192.168.10.2",
                    "mac_address": "00:1A:2B:3C:4D:5F",
                    "os_type": "Linux Debian 12",
                    "agent_version": "1.2.0",
                    "api_key_hash": hashlib.sha256("cs_mon_test_key_db_02".encode()).hexdigest(),
                    "api_key_prefix": "cs_mon_test",
                    "status": "Active",
                    "last_heartbeat_at": now,
                    "registered_at": "2026-10-01T00:00:00Z",
                    "config": {"reporting_interval_seconds": 30, "capture_telemetry": True, "capture_system_metrics": True},
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "monitoring_rules" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["monitoring_rules"] = [
                {
                    "id": "22000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "rule_name": "Excessive Network Byte Volume Spike",
                    "rule_type": "traffic_spike",
                    "description": "Flags sudden flow volumes exceeding 5MB within observation window",
                    "severity": "High",
                    "threshold": 5000000.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {"max_mb": 5},
                    "last_triggered_at": "2026-10-31T14:30:00Z",
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "22000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "rule_name": "Unauthorized High-Risk Port Ingress",
                    "rule_type": "unexpected_port",
                    "description": "Alerts on ingress connections to unapproved ports (4444, 1337, 6667, 31337)",
                    "severity": "High",
                    "threshold": 1.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {"restricted_ports": [4444, 1337, 6667, 31337, 8888, 3389]},
                    "last_triggered_at": "2026-10-31T14:32:00Z",
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "22000000-0000-0000-0000-000000000003",
                    "organization_id": org_id,
                    "rule_name": "Suspicious Outbound Connection",
                    "rule_type": "suspicious_outbound",
                    "description": "Detects outbound sessions directed at external exploit listeners",
                    "severity": "Critical",
                    "threshold": 1.0,
                    "time_window_seconds": 60,
                    "is_enabled": True,
                    "parameters": {},
                    "last_triggered_at": None,
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "device_health_metrics" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["device_health_metrics"] = [
                {
                    "id": "23000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "cpu_utilization_pct": 34.5,
                    "memory_utilization_pct": 58.2,
                    "disk_utilization_pct": 42.1,
                    "network_interface_status": "Up",
                    "health_state": "Healthy",
                    "recorded_at": now,
                },
                {
                    "id": "23000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000002",
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "cpu_utilization_pct": 78.4,
                    "memory_utilization_pct": 82.1,
                    "disk_utilization_pct": 88.5,
                    "network_interface_status": "Up",
                    "health_state": "Warning",
                    "recorded_at": now,
                }
            ]

        if "network_anomalies" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["network_anomalies"] = [
                {
                    "id": "24000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "asset_id": "11111111-1111-1111-1111-111111111111",
                    "source_asset": "192.168.10.1",
                    "event_category": "unexpected_port",
                    "severity": "High",
                    "rule_name": "Unauthorized High-Risk Port Ingress",
                    "rule_id": "22000000-0000-0000-0000-000000000002",
                    "evidence": {
                        "destination_port": 4444,
                        "service_tag": "Metasploit/Suspicious",
                        "source_ip": "198.51.100.42",
                        "destination_ip": "192.168.10.1",
                        "protocol": "TCP",
                    },
                    "confidence": 92,
                    "recommended_investigation": "Inspect firewall gateway logs for unauthorized ingress probe on Metasploit port 4444 from 198.51.100.42.",
                    "status": "Open",
                    "detected_at": "2026-10-31T14:32:00Z",
                    "created_at": "2026-10-31T14:32:00Z",
                },
                {
                    "id": "24000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "source_asset": "192.168.10.2",
                    "event_category": "traffic_spike",
                    "severity": "Medium",
                    "rule_name": "Excessive Network Byte Volume Spike",
                    "rule_id": "22000000-0000-0000-0000-000000000001",
                    "evidence": {
                        "byte_count": 14800000,
                        "threshold": 5000000.0,
                        "source_ip": "192.168.10.2",
                        "destination_ip": "203.0.113.195",
                        "packet_count": 11200,
                    },
                    "confidence": 85,
                    "recommended_investigation": "Audit sudden 14.8 MB database backup sync to external destination 203.0.113.195.",
                    "status": "Open",
                    "detected_at": "2026-10-31T14:30:00Z",
                    "created_at": "2026-10-31T14:30:00Z",
                }
            ]

        if "network_telemetry" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["network_telemetry"] = [
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "interface": "eth0",
                    "source_ip": "192.168.10.1",
                    "destination_ip": "1.1.1.1",
                    "protocol": "DNS",
                    "source_port": 54210,
                    "destination_port": 53,
                    "packet_count": 45,
                    "byte_count": 4820,
                    "direction": "Outbound",
                    "captured_at": now,
                    "created_at": now,
                },
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000001",
                    "interface": "eth0",
                    "source_ip": "203.0.113.88",
                    "destination_ip": "192.168.10.1",
                    "protocol": "HTTPS",
                    "source_port": 49210,
                    "destination_port": 443,
                    "packet_count": 320,
                    "byte_count": 420000,
                    "direction": "Inbound",
                    "captured_at": now,
                    "created_at": now,
                },
                {
                    "id": str(uuid4()),
                    "organization_id": org_id,
                    "agent_id": "21000000-0000-0000-0000-000000000002",
                    "interface": "eth0",
                    "source_ip": "192.168.10.2",
                    "destination_ip": "192.168.10.1",
                    "protocol": "TCP",
                    "source_port": 5432,
                    "destination_port": 5432,
                    "packet_count": 890,
                    "byte_count": 1820000,
                    "direction": "Internal",
                    "captured_at": now,
                    "created_at": now,
                }
            ]

    async def create_monitoring_agent(self, agent_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(agent_record["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_agents", []).insert(0, agent_record)
        return agent_record

    async def get_monitoring_agents(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [a for a in _mock_db.get("monitoring_agents", []) if str(a.get("organization_id")) == str(org_id)]

    async def get_monitoring_agent_by_id(self, agent_id: str) -> Optional[Dict[str, Any]]:
        for a in _mock_db.get("monitoring_agents", []):
            if str(a.get("id")) == str(agent_id):
                return a
        return None

    async def update_monitoring_agent_heartbeat(self, agent_id: str, heartbeat_at: str) -> bool:
        for a in _mock_db.get("monitoring_agents", []):
            if str(a.get("id")) == str(agent_id):
                a["last_heartbeat_at"] = heartbeat_at
                a["updated_at"] = heartbeat_at
                return True
        return False

    async def bulk_create_telemetry(self, telemetry_records: List[Dict[str, Any]]) -> int:
        if not telemetry_records:
            return 0
        org_id = str(telemetry_records[0]["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("network_telemetry", []).extend(telemetry_records)
        return len(telemetry_records)

    async def get_network_telemetry(self, org_id: str, time_window_seconds: int = 3600) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [t for t in _mock_db.get("network_telemetry", []) if str(t.get("organization_id")) == str(org_id)]

    async def create_device_health_metric(self, metric_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(metric_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("device_health_metrics", []).insert(0, metric_data)
        return metric_data

    async def get_latest_device_health_metrics(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        all_metrics = [m for m in _mock_db.get("device_health_metrics", []) if str(m.get("organization_id")) == str(org_id)]
        # deduplicate by agent_id (latest first)
        latest_by_agent: Dict[str, Dict[str, Any]] = {}
        for m in all_metrics:
            ag_id = m.get("agent_id")
            if ag_id and ag_id not in latest_by_agent:
                latest_by_agent[ag_id] = m
        return list(latest_by_agent.values())

    async def create_network_anomaly(self, anomaly_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(anomaly_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("network_anomalies", []).insert(0, anomaly_data)
        return anomaly_data

    async def get_network_anomalies(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        anomalies = [a for a in _mock_db.get("network_anomalies", []) if str(a.get("organization_id")) == str(org_id)]
        if status:
            anomalies = [a for a in anomalies if a.get("status") == status]
        return anomalies

    async def create_monitoring_rule(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(rule_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_rules", []).insert(0, rule_data)
        return rule_data

    async def get_monitoring_rules(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        return [r for r in _mock_db.get("monitoring_rules", []) if str(r.get("organization_id")) == str(org_id)]

    async def update_monitoring_rule(self, org_id: str, rule_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        for r in _mock_db.get("monitoring_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        r[k] = v
                r["updated_at"] = datetime.utcnow().isoformat() + "Z"
                return r
        return None

    async def create_monitoring_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(event_data["organization_id"])
        self._ensure_monitoring_seeds(org_id)
        _mock_db.setdefault("monitoring_events", []).insert(0, event_data)
        return event_data

    async def get_monitoring_events(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        self._ensure_monitoring_seeds(org_id)
        events = [e for e in _mock_db.get("monitoring_events", []) if str(e.get("organization_id")) == str(org_id)]
        return events[:limit]

    async def get_latest_telemetry_timestamp(self, org_id: str) -> Optional[str]:
        self._ensure_monitoring_seeds(org_id)
        telemetry = _mock_db.get("network_telemetry", [])
        for t in reversed(telemetry):
            if str(t.get("organization_id")) == str(org_id):
                return t.get("captured_at")
        return None

    # --------------------------------------------------------------------------
    # SPRINT 13: SECURITY ORCHESTRATION, AUTOMATION & RESPONSE (SOAR)
    # --------------------------------------------------------------------------
    def _ensure_soar_seeds(self, org_id: str):
        if "soar_workflows" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_workflows"] = [
                {
                    "id": "31000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "name": "Suspicious Login Response",
                    "description": "Correlates repeated authentication failures, alerts analyst, and requests account suspension",
                    "category": "identity_access",
                    "trigger_type": "repeated_auth_failures",
                    "trigger_conditions": {"failure_threshold": 3, "window_seconds": 300},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Auth Failure Burst", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "condition", "name": "Verify Failure Count > 3", "parameters": {"field": "severity", "value": "High"}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "asset_lookup", "name": "Enrich Ingress Host Info", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "create_incident", "name": "Open Unauthorized Access Incident", "parameters": {"title": "Credential Stuffing Incident"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "send_notification", "name": "Dispatch SOC On-Call Alert", "parameters": {"channel": "in_app"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "request_approval", "name": "Request Targeted Account Lockout", "parameters": {"action_type": "account_suspension", "justification": "Credential stuffing lock"}},
                        {"id": str(uuid4()), "step_order": 7, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000002",
                    "organization_id": org_id,
                    "name": "Malware Alert Investigation",
                    "description": "Correlates critical malware alerts against threat intelligence and creates formal case file",
                    "category": "incident_response",
                    "trigger_type": "new_critical_alert",
                    "trigger_conditions": {"severity": "Critical"},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Critical Malware Alert", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Correlate IOC Threat Reputation", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "vulnerability_lookup", "name": "Check Host CVE Exposure", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "create_incident", "name": "Escalate to P1 Incident", "parameters": {"title": "Malware Breach Incident"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request Host Network Quarantine", "parameters": {"action_type": "asset_isolation", "justification": "Active malware propagation defense"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "generate_report", "name": "Generate Forensic Summary", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 7, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000003",
                    "organization_id": org_id,
                    "name": "Critical Vulnerability Remediation Escalation",
                    "description": "Triages newly discovered high-severity CVEs against CISA KEV catalog and assigns engineers",
                    "category": "vulnerability_management",
                    "trigger_type": "new_high_vulnerability",
                    "trigger_conditions": {"min_cvss": 9.0},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on CVE Finding", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "severity_check", "name": "Verify CVSS >= 9.0", "parameters": {"min_severity": "Critical"}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "asset_lookup", "name": "Locate Production Assets", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "assign_analyst", "name": "Assign Infrastructure Lead", "parameters": {"analyst_name": "Elena Rostova (SecOps Lead)"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request Emergency Hotfix Approval", "parameters": {"action_type": "vulnerability_remediation", "justification": "CISA KEV weaponized exploit"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000004",
                    "organization_id": org_id,
                    "name": "Suspicious Network Traffic & C2 Investigation",
                    "description": "Automated triage of anomalous egress flows directed at external listening ports",
                    "category": "network_security",
                    "trigger_type": "suspicious_network_activity",
                    "trigger_conditions": {"ports": [4444, 1337]},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on Anomaly", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Query AlienVault OTX & CISA", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "add_incident_note", "name": "Document Traffic Signatures", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "request_approval", "name": "Request Perimeter Egress Block", "parameters": {"action_type": "firewall_rule_review", "justification": "Egress flow on port 4444"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                },
                {
                    "id": "31000000-0000-0000-0000-000000000005",
                    "organization_id": org_id,
                    "name": "Phishing Email Indicator Triage",
                    "description": "Extracts domains and URL indicators, checks URLhaus, and notifies the team",
                    "category": "threat_hunting",
                    "trigger_type": "threat_intel_ioc_match",
                    "trigger_conditions": {"category": "phishing"},
                    "status": "Published",
                    "is_enabled": True,
                    "version": 1,
                    "steps": [
                        {"id": str(uuid4()), "step_order": 1, "step_type": "trigger", "name": "Trigger on IOC Match", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 2, "step_type": "threat_intel_lookup", "name": "Query URLhaus Database", "parameters": {}},
                        {"id": str(uuid4()), "step_order": 3, "step_type": "create_incident", "name": "Open Phishing Incident", "parameters": {"title": "Phishing Campaign Ingress"}},
                        {"id": str(uuid4()), "step_order": 4, "step_type": "send_notification", "name": "Broadcast Email Advisory", "parameters": {"channel": "email"}},
                        {"id": str(uuid4()), "step_order": 5, "step_type": "request_approval", "name": "Request DNS Sinkhole / Domain Block", "parameters": {"action_type": "block_indicator", "justification": "Active phishing domain defense"}},
                        {"id": str(uuid4()), "step_order": 6, "step_type": "end_workflow", "name": "Conclude Playbook", "parameters": {}},
                    ],
                    "created_at": "2026-10-01T00:00:00Z",
                    "updated_at": now,
                }
            ]

        if "soar_action_approvals" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_action_approvals"] = [
                {
                    "id": "32000000-0000-0000-0000-000000000001",
                    "organization_id": org_id,
                    "execution_id": "33000000-0000-0000-0000-000000000001",
                    "workflow_name": "Suspicious Login Response",
                    "action_type": "account_suspension",
                    "target_resource": "dev-user-svc@apexcyberdefense.io",
                    "justification": "12 failed Kerberos authentications within 90 seconds from unapproved subnet",
                    "requested_by": "00000000-0000-0000-0000-000000000001",
                    "approver_id": None,
                    "decision": "Pending",
                    "decision_notes": None,
                    "decided_at": None,
                    "created_at": now,
                    "expires_at": (datetime.utcnow() + timedelta(hours=24)).isoformat() + "Z",
                    "execution_result": {},
                }
            ]

        if "soar_workflow_executions" not in _mock_db:
            now = datetime.utcnow().isoformat() + "Z"
            _mock_db["soar_workflow_executions"] = [
                {
                    "id": "33000000-0000-0000-0000-000000000001",
                    "workflow_id": "31000000-0000-0000-0000-000000000001",
                    "workflow_name": "Suspicious Login Response",
                    "organization_id": org_id,
                    "trigger_source": "repeated_auth_failures",
                    "status": "Waiting_Approval",
                    "started_at": now,
                    "completed_at": None,
                    "duration_ms": 680,
                    "context_data": {"user": "dev-user-svc", "ip": "198.51.100.42", "severity": "High"},
                    "error_message": None,
                    "retry_count": 0,
                    "triggered_by": "00000000-0000-0000-0000-000000000001",
                    "created_at": now,
                    "steps": [
                        {
                            "id": str(uuid4()),
                            "step_name": "Trigger on Auth Failure Burst",
                            "step_type": "trigger",
                            "status": "Completed",
                            "started_at": now,
                            "completed_at": now,
                            "input_payload": {},
                            "output_payload": {"acknowledged": True},
                        },
                        {
                            "id": str(uuid4()),
                            "step_name": "Request Targeted Account Lockout",
                            "step_type": "request_approval",
                            "status": "Waiting_Approval",
                            "started_at": now,
                            "completed_at": now,
                            "input_payload": {"action": "account_suspension"},
                            "output_payload": {"status": "Pending"},
                        },
                    ],
                    "logs": [
                        {
                            "id": str(uuid4()),
                            "timestamp": now,
                            "log_level": "INFO",
                            "message": "Playbook 'Suspicious Login Response' initiated by event correlation engine",
                            "payload": {},
                        },
                        {
                            "id": str(uuid4()),
                            "timestamp": now,
                            "log_level": "INFO",
                            "message": "Disruptive action 'account_suspension' requires SOC analyst authorization",
                            "payload": {},
                        },
                    ],
                }
            ]

    async def create_soar_workflow(self, wf_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(wf_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_workflows", []).insert(0, wf_record)
        return wf_record

    async def get_soar_workflows(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        wfs = [w for w in _mock_db.get("soar_workflows", []) if str(w.get("organization_id")) == str(org_id)]
        if status:
            wfs = [w for w in wfs if w.get("status") == status]
        return wfs

    async def get_soar_workflow_by_id(self, org_id: str, workflow_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for w in _mock_db.get("soar_workflows", []):
            if str(w.get("id")) == str(workflow_id) and str(w.get("organization_id")) == str(org_id):
                return w
        return None

    async def update_soar_workflow(self, org_id: str, workflow_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for w in _mock_db.get("soar_workflows", []):
            if str(w.get("id")) == str(workflow_id) and str(w.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        w[k] = v
                w["updated_at"] = datetime.utcnow().isoformat() + "Z"
                return w
        return None

    async def create_soar_execution(self, execution_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(execution_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_workflow_executions", []).insert(0, execution_record)
        return execution_record

    async def get_soar_executions(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        execs = [e for e in _mock_db.get("soar_workflow_executions", []) if str(e.get("organization_id")) == str(org_id)]
        if status:
            execs = [e for e in execs if e.get("status") == status]
        return execs

    async def get_soar_execution_by_id(self, org_id: str, execution_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for e in _mock_db.get("soar_workflow_executions", []):
            if str(e.get("id")) == str(execution_id) and str(e.get("organization_id")) == str(org_id):
                return e
        return None

    async def update_soar_execution(self, org_id: str, execution_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for e in _mock_db.get("soar_workflow_executions", []):
            if str(e.get("id")) == str(execution_id) and str(e.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        e[k] = v
                return e
        return None

    async def create_soar_approval(self, approval_record: Dict[str, Any]) -> Dict[str, Any]:
        org_id = str(approval_record["organization_id"])
        self._ensure_soar_seeds(org_id)
        _mock_db.setdefault("soar_action_approvals", []).insert(0, approval_record)
        return approval_record

    async def get_soar_approvals(self, org_id: str, decision: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        approvals = [a for a in _mock_db.get("soar_action_approvals", []) if str(a.get("organization_id")) == str(org_id)]
        if decision:
            approvals = [a for a in approvals if a.get("decision") == decision]
        return approvals

    async def get_soar_approval_by_id(self, org_id: str, approval_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for a in _mock_db.get("soar_action_approvals", []):
            if str(a.get("id")) == str(approval_id) and str(a.get("organization_id")) == str(org_id):
                return a
        return None

    async def update_soar_approval(self, org_id: str, approval_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_soar_seeds(org_id)
        for a in _mock_db.get("soar_action_approvals", []):
            if str(a.get("id")) == str(approval_id) and str(a.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        a[k] = v
                return a
        return None

    async def get_soar_notification_templates(self, org_id: str) -> List[Dict[str, Any]]:
        return [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "Critical Security Incident Alert",
                "channel": "email",
                "subject": "[CRITICAL] {{incident_title}} Detected by CyberShield SOAR",
                "body_template": "An automated response playbook has triaged high-severity activity on {{asset_name}}.",
                "is_default": True,
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "SOAR Action Approval Request",
                "channel": "in_app",
                "subject": "Authorization Needed: {{action_type}}",
                "body_template": "Playbook {{playbook_name}} requires analyst approval to execute {{action_type}} on {{target}}.",
                "is_default": True,
                "created_at": datetime.utcnow().isoformat() + "Z",
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "template_name": "SIEM / Webhook Dispatcher",
                "channel": "webhook",
                "subject": None,
                "body_template": '{"event": "soar_execution", "status": "{{status}}", "playbook": "{{playbook_name}}"}',
                "is_default": False,
                "created_at": datetime.utcnow().isoformat() + "Z",
            }
        ]

    async def create_soar_notification_delivery(self, delivery: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("soar_notification_deliveries", []).insert(0, delivery)
        return delivery

    # --------------------------------------------------------------------------
    # SPRINT 14: AI THREAT DETECTION, UEBA & PREDICTIVE INTELLIGENCE
    # --------------------------------------------------------------------------
    def _ensure_ai_detection_seeds(self, org_id: str):
        if _mock_db.get(f"ai_detection_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc).isoformat()

        # 1. Models Registry
        m1_id = "d0000001-0000-0000-0000-000000000001"
        m2_id = "d0000002-0000-0000-0000-000000000002"
        m3_id = "d0000003-0000-0000-0000-000000000003"

        models = [
            {
                "id": m1_id,
                "organization_id": org_id,
                "model_name": "IsolationForest-NetworkAnomalies",
                "model_type": "isolation_forest",
                "description": "Unsupervised ensemble anomaly detector identifying out-of-profile egress and telemetry spikes",
                "active_version": "1.0.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.915,
                    "recall": 0.884,
                    "f1_score": 0.899,
                    "false_positive_rate": 0.042,
                    "detection_rate": 0.884,
                },
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": m2_id,
                "organization_id": org_id,
                "model_name": "UEBA-Statistical-Baseline",
                "model_type": "statistical_baseline",
                "description": "Rolling 14-day asset behavior baseline model detecting z-score variance in authentication and connection frequency",
                "active_version": "2.1.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.892,
                    "recall": 0.920,
                    "f1_score": 0.906,
                    "false_positive_rate": 0.051,
                    "detection_rate": 0.920,
                },
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": m3_id,
                "organization_id": org_id,
                "model_name": "RuleEnsemble-ThreatHeuristics",
                "model_type": "rule_engine",
                "description": "Deterministic rule correlation engine evaluating IOC feeds, high-risk destination ports, and rapid brute force attempts",
                "active_version": "1.4.0",
                "status": "active",
                "is_production_ready": True,
                "evaluation_metrics": {
                    "precision": 0.960,
                    "recall": 0.840,
                    "f1_score": 0.896,
                    "false_positive_rate": 0.018,
                    "detection_rate": 0.840,
                },
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_models", []).extend(models)

        # Versions
        versions = [
            {
                "id": str(uuid4()),
                "model_id": m1_id,
                "version": "1.0.0",
                "dataset_reference": "netflow_enterprise_baseline_v1",
                "training_samples_count": 4500,
                "hyperparameters": {"n_estimators": 100, "contamination": 0.08},
                "evaluation_metrics": {"precision": 0.915, "recall": 0.884, "f1_score": 0.899},
                "is_active": True,
                "trained_at": now,
                "deployed_at": now,
            },
            {
                "id": str(uuid4()),
                "model_id": m2_id,
                "version": "2.1.0",
                "dataset_reference": "ueba_auth_telemetry_v2",
                "training_samples_count": 6200,
                "hyperparameters": {"window_days": 14, "sigma_threshold": 3.0},
                "evaluation_metrics": {"precision": 0.892, "recall": 0.920, "f1_score": 0.906},
                "is_active": True,
                "trained_at": now,
                "deployed_at": now,
            },
        ]
        _mock_db.setdefault("ai_model_versions", []).extend(versions)

        # 2. Rules
        rules = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Excessive Outbound Egress Volume",
                "rule_type": "statistical_threshold",
                "description": "Flags assets transmitting >10MB outbound in 5 minutes exceeding 3.0x historical baseline",
                "severity": "Critical",
                "data_sources": ["network_monitoring", "agent_telemetry"],
                "threshold_config": {"egress_bytes_window": 10485760, "window_minutes": 5},
                "evaluation_interval_seconds": 180,
                "is_enabled": True,
                "matched_events_count": 14,
                "false_positive_count": 1,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Repeated SSH/RDP Auth Failures",
                "rule_type": "behavioral_deviation",
                "description": "Identifies brute-force authentication spikes with failed attempt ratio > 80%",
                "severity": "High",
                "data_sources": ["auth_events"],
                "threshold_config": {"failed_attempts": 5, "window_seconds": 60},
                "evaluation_interval_seconds": 60,
                "is_enabled": True,
                "matched_events_count": 28,
                "false_positive_count": 2,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "High-Risk Destination Port Probing",
                "rule_type": "ioc_matching",
                "description": "Detects internal connections to C2 staging ports 4444, 1337, or unexpected SMB/RDP egress",
                "severity": "High",
                "data_sources": ["network_monitoring"],
                "threshold_config": {"monitored_ports": [4444, 1337, 8888, 3389]},
                "evaluation_interval_seconds": 300,
                "is_enabled": True,
                "matched_events_count": 6,
                "false_positive_count": 0,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "rule_name": "Anomalous Protocol Entropy Spike",
                "rule_type": "event_correlation",
                "description": "Flags hosts communicating across erratic port distributions indicating network reconnaissance",
                "severity": "Medium",
                "data_sources": ["network_monitoring"],
                "threshold_config": {"entropy_threshold": 2.2},
                "evaluation_interval_seconds": 600,
                "is_enabled": True,
                "matched_events_count": 9,
                "false_positive_count": 1,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_rules", []).extend(rules)

        # 3. Detection Results
        d1_id = "e0000001-0000-0000-0000-000000000001"
        d2_id = "e0000002-0000-0000-0000-000000000002"
        d3_id = "e0000003-0000-0000-0000-000000000003"
        d4_id = "e0000004-0000-0000-0000-000000000004"

        detections = [
            {
                "id": d1_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000001",
                "source_asset_name": "Core-App-Cluster-Node-01",
                "detection_category": "suspicious_outbound",
                "severity": "Critical",
                "confidence_score": 0.92,
                "anomaly_score": 0.88,
                "detection_method": "ml_isolation_forest",
                "supporting_evidence": {
                    "outbound_bytes": 14200000,
                    "baseline_mean_bytes": 450000,
                    "sigma_deviation": 3.42,
                    "unique_destinations": 48,
                    "target_protocol": "TCP/4444",
                },
                "recommended_investigation": "Inspect endpoint process tree on 192.168.10.15 for unauthorized sockets and verify C2 feed matches.",
                "model_version": "1.0.0",
                "status": "investigating",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d2_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000002",
                "source_asset_name": "Auth-Gateway-Proxy-02",
                "detection_category": "repeated_auth_failures",
                "severity": "High",
                "confidence_score": 0.89,
                "anomaly_score": 0.79,
                "detection_method": "ueba_behavioral",
                "supporting_evidence": {
                    "failed_attempts": 32,
                    "window_seconds": 60,
                    "target_service": "SSH/22",
                    "origin_subnets": ["198.51.100.0/24"],
                },
                "recommended_investigation": "Review authentication audit logs and check for automated credential brute-forcing.",
                "model_version": "2.1.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d3_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000003",
                "source_asset_name": "DMZ-Edge-Firewall",
                "detection_category": "unusual_port",
                "severity": "Medium",
                "confidence_score": 0.84,
                "anomaly_score": 0.68,
                "detection_method": "statistical_baseline",
                "supporting_evidence": {
                    "unusual_ports": [8089, 9001],
                    "historical_frequency": 0.02,
                },
                "recommended_investigation": "Verify whether management interface ports were opened for authorized telemetry.",
                "model_version": "1.0.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
            {
                "id": d4_id,
                "organization_id": org_id,
                "source_asset_id": "00000000-0000-0000-0000-000000000004",
                "source_asset_name": "Workstation-Engineering-14",
                "detection_category": "threat_intel_match",
                "severity": "High",
                "confidence_score": 0.95,
                "anomaly_score": 0.85,
                "detection_method": "deterministic_rule",
                "supporting_evidence": {
                    "matched_ioc": "198.51.100.23",
                    "ioc_type": "ipv4",
                    "feed_name": "EmergingThreats C2 Feed",
                },
                "recommended_investigation": "Isolate engineering workstation and scan for payload dropper execution.",
                "model_version": "1.4.0",
                "status": "new",
                "detected_at": now,
                "created_at": now,
            },
        ]
        _mock_db.setdefault("ai_detection_results", []).extend(detections)

        # 4. Investigations
        investigations = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "detection_id": d1_id,
                "status": "Reviewing",
                "assigned_analyst": "00000000-0000-0000-0000-000000000001",
                "analyst_notes": "Forensic memory dump acquired. Investigating parent process for port 4444 outbound connection.",
                "findings_summary": "Process python3 spawning /bin/sh reverse shell.",
                "timeline_events": [
                    {"timestamp": now, "actor": "IsolationForest Engine", "action": "Anomaly detected (score 0.88)"},
                    {"timestamp": now, "actor": "Senior Analyst", "action": "Assigned to case and initiated triage"},
                ],
                "confirmed_at": None,
                "resolved_at": None,
                "created_at": now,
                "updated_at": now,
            }
        ]
        _mock_db.setdefault("ai_detection_investigations", []).extend(investigations)

        # 5. Risk Predictions
        predictions = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000001",
                "asset_name": "Core-App-Cluster-Node-01",
                "asset_ip": "192.168.10.15",
                "risk_score": 86,
                "risk_level": "Critical",
                "risk_trend": "increasing",
                "contributing_factors": [
                    {"factor": "Known Exploited Vulnerability", "impact": "+25", "detail": "CVE-2024-3400 (CISA KEV)"},
                    {"factor": "Suspicious Outbound Telemetry", "impact": "+20", "detail": "14.2 MB burst to unmapped external IP"},
                    {"factor": "Asset Criticality Tier", "impact": "+15", "detail": "Production Application Node"},
                    {"factor": "Multi-Port Probe Activity", "impact": "+10", "detail": "Elevated protocol entropy"},
                ],
                "confidence_score": 0.92,
                "data_coverage_score": 0.89,
                "recommended_remediation_priority": "P1",
                "predicted_at": now,
                "created_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000002",
                "asset_name": "Auth-Gateway-Proxy-02",
                "asset_ip": "192.168.10.22",
                "risk_score": 72,
                "risk_level": "High",
                "risk_trend": "increasing",
                "contributing_factors": [
                    {"factor": "Repeated Authentication Failures", "impact": "+25", "detail": "32 failed SSH attempts in 60s"},
                    {"factor": "Internet-Facing Boundary", "impact": "+15", "detail": "Direct public ingress on port 22"},
                ],
                "confidence_score": 0.88,
                "data_coverage_score": 0.85,
                "recommended_remediation_priority": "P2",
                "predicted_at": now,
                "created_at": now,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "asset_id": "00000000-0000-0000-0000-000000000003",
                "asset_name": "DMZ-Edge-Firewall",
                "asset_ip": "192.168.10.1",
                "risk_score": 45,
                "risk_level": "Medium",
                "risk_trend": "stable",
                "contributing_factors": [
                    {"factor": "Unusual Port Telemetry", "impact": "+15", "detail": "Ports 8089, 9001 detected"},
                    {"factor": "Up-to-Date Patch Compliance", "impact": "-10", "detail": "Zero unresolved CVEs"},
                ],
                "confidence_score": 0.84,
                "data_coverage_score": 0.92,
                "recommended_remediation_priority": "P3",
                "predicted_at": now,
                "created_at": now,
            },
        ]
        _mock_db.setdefault("ai_risk_predictions", []).extend(predictions)

        _mock_db[f"ai_detection_seeded_{org_id}"] = True

    async def get_ai_detection_models(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [m for m in _mock_db.get("ai_detection_models", []) if str(m.get("organization_id")) == str(org_id)]

    async def create_ai_detection_model(self, model: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_models", []).insert(0, model)
        return model

    async def get_ai_model_versions(self, org_id: str, model_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [v for v in _mock_db.get("ai_model_versions", []) if str(v.get("model_id")) == str(model_id)]

    async def create_ai_model_version(self, version: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_model_versions", []).insert(0, version)
        return version

    async def get_ai_detection_rules(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [r for r in _mock_db.get("ai_detection_rules", []) if str(r.get("organization_id")) == str(org_id)]

    async def get_ai_detection_rule_by_id(self, org_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for r in _mock_db.get("ai_detection_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                return r
        return None

    async def create_ai_detection_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_rules", []).insert(0, rule)
        return rule

    async def update_ai_detection_rule(self, org_id: str, rule_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for r in _mock_db.get("ai_detection_rules", []):
            if str(r.get("id")) == str(rule_id) and str(r.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        r[k] = v
                return r
        return None

    async def get_ai_detection_results(
        self, org_id: str, category: Optional[str] = None, severity: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        res = [d for d in _mock_db.get("ai_detection_results", []) if str(d.get("organization_id")) == str(org_id)]
        if category:
            res = [d for d in res if d.get("detection_category") == category]
        if severity:
            res = [d for d in res if d.get("severity") == severity]
        return res

    async def get_ai_detection_result_by_id(self, org_id: str, detection_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for d in _mock_db.get("ai_detection_results", []):
            if str(d.get("id")) == str(detection_id) and str(d.get("organization_id")) == str(org_id):
                return d
        return None

    async def create_ai_detection_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_results", []).insert(0, result)
        return result

    async def update_ai_detection_result(self, org_id: str, detection_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for d in _mock_db.get("ai_detection_results", []):
            if str(d.get("id")) == str(detection_id) and str(d.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        d[k] = v
                return d
        return None

    async def get_ai_detection_investigations(self, org_id: str, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        invs = [i for i in _mock_db.get("ai_detection_investigations", []) if str(i.get("organization_id")) == str(org_id)]
        if status_filter:
            invs = [i for i in invs if i.get("status") == status_filter]
        return invs

    async def get_ai_detection_investigation_by_id(self, org_id: str, inv_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for i in _mock_db.get("ai_detection_investigations", []):
            if str(i.get("id")) == str(inv_id) and str(i.get("organization_id")) == str(org_id):
                return i
        return None

    async def create_ai_detection_investigation(self, inv: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_investigations", []).insert(0, inv)
        return inv

    async def update_ai_detection_investigation(self, org_id: str, inv_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        for i in _mock_db.get("ai_detection_investigations", []):
            if str(i.get("id")) == str(inv_id) and str(i.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        i[k] = v
                return i
        return None

    async def create_ai_detection_feedback(self, feedback: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("ai_detection_feedback", []).insert(0, feedback)
        return feedback

    async def get_ai_risk_predictions(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_ai_detection_seeds(org_id)
        return [p for p in _mock_db.get("ai_risk_predictions", []) if str(p.get("organization_id")) == str(org_id)]

    # --------------------------------------------------------------------------
    # SPRINT 15: ENTERPRISE INTEGRATIONS & EXTERNAL SECURITY ECOSYSTEM
    # --------------------------------------------------------------------------
    def _ensure_integrations_seeds(self, org_id: str):
        if _mock_db.get(f"integrations_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc).isoformat()

        int1_id = "f0000001-0000-0000-0000-000000000001"
        int2_id = "f0000002-0000-0000-0000-000000000002"
        int3_id = "f0000003-0000-0000-0000-000000000003"
        int4_id = "f0000004-0000-0000-0000-000000000004"
        int5_id = "f0000005-0000-0000-0000-000000000005"
        int6_id = "f0000006-0000-0000-0000-000000000006"

        integrations = [
            {
                "id": int1_id,
                "organization_id": org_id,
                "name": "Splunk Enterprise SIEM",
                "slug": "splunk",
                "category": "siem",
                "provider": "Splunk",
                "description": "HTTP Event Collector (HEC) forwarder streaming normalized security alerts and incidents to Splunk SIEM",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"endpoint_url": "https://splunk-hec.corp.internal:8088/services/collector", "index": "cybershield_events"},
                "secret_masked": "hec_...9x4b",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int2_id,
                "organization_id": org_id,
                "name": "Microsoft Sentinel",
                "slug": "sentinel",
                "category": "siem",
                "provider": "Microsoft",
                "description": "Log Analytics ingestion connector synchronizing anomalous threat detections and SOAR executions",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"workspace_id": "ws-sec-88091", "log_type": "CyberShieldSecurityEvents"},
                "secret_masked": "ms_k...4k2p",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int3_id,
                "organization_id": org_id,
                "name": "Slack Incident Operations",
                "slug": "slack",
                "category": "communication",
                "provider": "Slack",
                "description": "Real-time critical alert dispatch, incident escalation notices, and human-in-the-loop approval requests",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"channel": "#soc-incident-war-room", "alert_severity_threshold": "High"},
                "secret_masked": "xoxb...8921",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int4_id,
                "organization_id": org_id,
                "name": "Microsoft Teams SOC Bridge",
                "slug": "teams",
                "category": "communication",
                "provider": "Microsoft",
                "description": "Interactive webhook notifications for security event correlation and SOAR containment gates",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"channel": "SOC Team Operations", "webhook_url": "https://outlook.office.com/webhook/sec"},
                "secret_masked": "mste...1102",
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int5_id,
                "organization_id": org_id,
                "name": "CISA Known Exploited Vulnerabilities",
                "slug": "cisa_kev",
                "category": "threat_intelligence",
                "provider": "CISA",
                "description": "Automated synchronization of actively exploited zero-day and CVE catalogs",
                "connection_status": "Connected",
                "is_enabled": True,
                "health_status": "Healthy",
                "config": {"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "sync_interval_hours": 6},
                "secret_masked": None,
                "last_synced_at": now,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": int6_id,
                "organization_id": org_id,
                "name": "AWS Security & CloudTrail",
                "slug": "aws_security",
                "category": "cloud_security",
                "provider": "AWS",
                "description": "Read-only inventory sync and GuardDuty finding correlation without destructive infrastructure modification",
                "connection_status": "Pending_Configuration",
                "is_enabled": False,
                "health_status": "Healthy",
                "config": {"region": "us-east-1", "iam_role_arn": "arn:aws:iam::123456789012:role/CyberShieldReadOnlyAudit"},
                "secret_masked": None,
                "last_synced_at": None,
                "error_message": None,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("integrations", []).extend(integrations)

        # Webhook Endpoints
        wh1_id = "a0000001-0000-0000-0000-000000000001"
        wh2_id = "a0000002-0000-0000-0000-000000000002"

        webhooks = [
            {
                "id": wh1_id,
                "organization_id": org_id,
                "name": "Corporate SIEM Syslog Webhook Bridge",
                "url": "https://siem-collector.apexcorp.com/hooks/v1",
                "description": "Delivers JSON security alerts and containment decisions to central SOC infrastructure",
                "secret_token": "whsec_9876543210abcdef9876543210abcdef",
                "is_active": True,
                "events": ["alert.created", "incident.created", "soar.execution_completed"],
                "retry_limit": 3,
                "timeout_seconds": 10,
                "failure_count": 0,
                "last_triggered_at": now,
                "created_at": now,
                "updated_at": now,
            },
            {
                "id": wh2_id,
                "organization_id": org_id,
                "name": "Jira IT Service Management Webhook",
                "url": "https://jira.apexcorp.com/rest/api/2/issue",
                "description": "Auto-creates service management escalation tickets upon confirmed high-severity incidents",
                "secret_token": "whsec_1234567890abcdef1234567890abcdef",
                "is_active": True,
                "events": ["incident.created", "compliance.updated"],
                "retry_limit": 3,
                "timeout_seconds": 10,
                "failure_count": 0,
                "last_triggered_at": now,
                "created_at": now,
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("webhook_endpoints", []).extend(webhooks)

        # Delivery Logs
        logs = [
            {
                "id": str(uuid4()),
                "integration_id": int1_id,
                "organization_id": org_id,
                "integration_name": "Splunk Enterprise SIEM",
                "event_type": "alert_export",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"alert_id": "ALT-2026-0812", "severity": "High", "asset": "192.168.10.15"},
                "error_summary": None,
                "duration_ms": 35,
                "delivered_at": now,
            },
            {
                "id": str(uuid4()),
                "integration_id": int3_id,
                "organization_id": org_id,
                "integration_name": "Slack Incident Operations",
                "event_type": "notification_dispatch",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"incident_id": "INC-2026-0042", "urgency": "High", "channel": "#soc-incident-war-room"},
                "error_summary": None,
                "duration_ms": 42,
                "delivered_at": now,
            },
            {
                "id": str(uuid4()),
                "integration_id": int2_id,
                "organization_id": org_id,
                "integration_name": "Microsoft Sentinel",
                "event_type": "incident_sync",
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_count": 1,
                "payload_summary": {"records_synced": 3, "table": "CyberShieldSecurityEvents"},
                "error_summary": None,
                "duration_ms": 56,
                "delivered_at": now,
            },
        ]
        _mock_db.setdefault("integration_delivery_logs", []).extend(logs)

        # Webhook Delivery Attempts
        attempts = [
            {
                "id": str(uuid4()),
                "webhook_id": wh1_id,
                "organization_id": org_id,
                "event_type": "alert.created",
                "idempotency_key": f"idem_{uuid4().hex[:12]}",
                "payload": {"alert_id": "ALT-2026-0812", "severity": "High"},
                "status": "Delivered",
                "http_status_code": 200,
                "attempt_number": 1,
                "response_body": '{"status": "acknowledged", "delivery_id": "del-8819"}',
                "error_message": None,
                "duration_ms": 28,
                "created_at": now,
            }
        ]
        _mock_db.setdefault("webhook_delivery_attempts", []).extend(attempts)

        _mock_db[f"integrations_seeded_{org_id}"] = True

    async def get_integrations(self, org_id: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        items = [i for i in _mock_db.get("integrations", []) if str(i.get("organization_id")) == str(org_id)]
        if category:
            items = [i for i in items if i.get("category") == category]
        return items

    async def get_integration_by_id(self, org_id: str, integration_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for i in _mock_db.get("integrations", []):
            if str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id):
                return i
        return None

    async def create_integration(self, integration: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integrations", []).insert(0, integration)
        return integration

    async def update_integration(self, org_id: str, integration_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for i in _mock_db.get("integrations", []):
            if str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        i[k] = v
                return i
        return None

    async def delete_integration(self, org_id: str, integration_id: str) -> bool:
        self._ensure_integrations_seeds(org_id)
        existing = _mock_db.get("integrations", [])
        before_len = len(existing)
        _mock_db["integrations"] = [
            i for i in existing
            if not (str(i.get("id")) == str(integration_id) and str(i.get("organization_id")) == str(org_id))
        ]
        return len(_mock_db["integrations"]) < before_len

    async def create_integration_credential(self, cred: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_credentials", []).insert(0, cred)
        return cred

    async def create_integration_sync_history(self, sync_rec: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_sync_history", []).insert(0, sync_rec)
        return sync_rec

    async def get_integration_delivery_logs(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [l for l in _mock_db.get("integration_delivery_logs", []) if str(l.get("organization_id")) == str(org_id)]

    async def create_integration_delivery_log(self, log: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("integration_delivery_logs", []).insert(0, log)
        return log

    async def get_webhook_endpoints(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [w for w in _mock_db.get("webhook_endpoints", []) if str(w.get("organization_id")) == str(org_id)]

    async def get_webhook_endpoint_by_id(self, org_id: str, hook_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for w in _mock_db.get("webhook_endpoints", []):
            if str(w.get("id")) == str(hook_id) and str(w.get("organization_id")) == str(org_id):
                return w
        return None

    async def create_webhook_endpoint(self, hook: Dict[str, Any]) -> Dict[str, Any]:
        _mock_db.setdefault("webhook_endpoints", []).insert(0, hook)
        return hook

    async def update_webhook_endpoint(self, org_id: str, hook_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for w in _mock_db.get("webhook_endpoints", []):
            if str(w.get("id")) == str(hook_id) and str(w.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        w[k] = v
                return w
        return None

    async def get_webhook_delivery_attempts(self, org_id: str, hook_id: str) -> List[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        return [
            a for a in _mock_db.get("webhook_delivery_attempts", [])
            if str(a.get("organization_id")) == str(org_id) and str(a.get("webhook_id")) == str(hook_id)
        ]

    async def get_webhook_delivery_attempt_by_id(self, org_id: str, delivery_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for a in _mock_db.get("webhook_delivery_attempts", []):
            if str(a.get("id")) == str(delivery_id) and str(a.get("organization_id")) == str(org_id):
                return a
        return None

    async def update_webhook_delivery_attempt(self, org_id: str, delivery_id: str, update_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_integrations_seeds(org_id)
        for a in _mock_db.get("webhook_delivery_attempts", []):
            if str(a.get("id")) == str(delivery_id) and str(a.get("organization_id")) == str(org_id):
                for k, v in update_data.items():
                    if v is not None:
                        a[k] = v
                return a
        return None

    def _ensure_sprint17_seeds(self, org_id: str) -> None:
        if _mock_db.get(f"sprint17_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)
        two_days_ago = now - timedelta(days=2)

        # 1. Threat Hunting Cases
        th_case_1_id = "11111111-2222-3333-4444-555555555501"
        th_case_2_id = "11111111-2222-3333-4444-555555555502"
        th_case_3_id = "11111111-2222-3333-4444-555555555503"

        th_cases = [
            {
                "id": th_case_1_id,
                "organization_id": org_id,
                "case_number": "TH-2026-00101",
                "title": "Suspicious Kerberoasting & Lateral Movement Hunting",
                "objective": "Detect unconstrained Kerberos ticket requests and abnormal NTLM/Kerberos authentication spikes across DC-01 and core servers.",
                "hypothesis": "Potential compromised service account executing lateral movement via SPN scanning.",
                "status": "Investigating",
                "priority": "P1",
                "assigned_to": "00000000-0000-0000-0000-000000000001",
                "created_by": "00000000-0000-0000-0000-000000000001",
                "start_time": two_days_ago,
                "end_time": None,
                "selected_asset_ids": [],
                "filter_criteria": {"event_category": "auth", "port": 88},
                "summary_findings": "Multiple high-entropy SPN requests discovered originating from 192.168.10.45.",
                "created_at": two_days_ago,
                "updated_at": yesterday,
            },
            {
                "id": th_case_2_id,
                "organization_id": org_id,
                "case_number": "TH-2026-00102",
                "title": "External C2 Beaconing Pattern Search",
                "objective": "Identify jittered periodic HTTP/HTTPS and DNS traffic to unclassified apex domains.",
                "hypothesis": "Adversary Command and Control channel active on isolated workstation.",
                "status": "Suspicious Activity Found",
                "priority": "P2",
                "assigned_to": "00000000-0000-0000-0000-000000000001",
                "created_by": "00000000-0000-0000-0000-000000000001",
                "start_time": yesterday,
                "end_time": None,
                "selected_asset_ids": [],
                "filter_criteria": {"event_category": "network", "ioc_type": "domain"},
                "summary_findings": "Periodic outbound sessions targeting c2-sync-payload.org at 60s intervals.",
                "created_at": yesterday,
                "updated_at": now,
            },
            {
                "id": th_case_3_id,
                "organization_id": org_id,
                "case_number": "TH-2026-00103",
                "title": "Encrypted Web Shell Activity Detection",
                "objective": "Inspect outbound reverse-shell TCP sessions originating from public web frontend servers.",
                "hypothesis": "Apache container exploited via remote code execution payload.",
                "status": "Escalated",
                "priority": "P1",
                "assigned_to": "00000000-0000-0000-0000-000000000001",
                "created_by": "00000000-0000-0000-0000-000000000001",
                "start_time": now - timedelta(hours=12),
                "end_time": now,
                "selected_asset_ids": [],
                "filter_criteria": {"event_category": "network", "port": 4444},
                "summary_findings": "Escalated to P1 Incident INC-2026-00031 for forensic evidence preservation.",
                "created_at": now - timedelta(hours=12),
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("threat_hunting_cases", []).extend(th_cases)

        # 2. Threat Hunting Queries
        th_queries = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "hunting_case_id": th_case_1_id,
                "name": "High Severity Authentication Failures",
                "description": "Searches for Kerberos/NTLM authentication failures with High severity.",
                "filter_params": {"event_category": "auth", "severity": "High"},
                "match_count": 14,
                "is_saved": True,
                "created_by": "00000000-0000-0000-0000-000000000001",
                "created_at": two_days_ago,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "hunting_case_id": th_case_2_id,
                "name": "Unusual Outbound C2 Port Activity",
                "description": "Filters for outbound traffic over non-standard and shell ports.",
                "filter_params": {"event_category": "network", "port": 4444},
                "match_count": 8,
                "is_saved": True,
                "created_by": "00000000-0000-0000-0000-000000000001",
                "created_at": yesterday,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "hunting_case_id": th_case_2_id,
                "name": "Known Adversary IP 198.51.100.45",
                "description": "Correlates telemetry against high-confidence CobaltStrike IP.",
                "filter_params": {"ioc_type": "ipv4", "ioc_value": "198.51.100.45"},
                "match_count": 32,
                "is_saved": True,
                "created_by": "00000000-0000-0000-0000-000000000001",
                "created_at": yesterday,
            },
        ]
        _mock_db.setdefault("threat_hunting_queries", []).extend(th_queries)

        # 3. Threat Hunting Findings
        th_findings = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "hunting_case_id": th_case_1_id,
                "title": "Abnormal TGS Ticket Requests for SPN MSSQLSvc",
                "finding_type": "credential_misuse",
                "severity": "High",
                "is_confirmed": True,
                "affected_asset_id": None,
                "evidence_summary": "Over 45 Ticket Granting Service (TGS) requests within 3 minutes from internal host 192.168.10.45.",
                "mitre_tactic_name": "Credential Access",
                "mitre_technique_id": "T1558.003",
                "recommendations": "Rotate MSSQLSvc service account password and enforce AES256-only Kerberos encryption.",
                "created_at": yesterday,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "hunting_case_id": th_case_2_id,
                "title": "Periodic HTTPS Beaconing to c2-sync-payload[.]org",
                "finding_type": "ioc_match",
                "severity": "Critical",
                "is_confirmed": True,
                "affected_asset_id": None,
                "evidence_summary": "Exact interval beaconing to 198.51.100.45 every 60s (+/- 5% jitter) matching known adversary command and control infrastructure.",
                "mitre_tactic_name": "Command and Control",
                "mitre_technique_id": "T1071.001",
                "recommendations": "Block c2-sync-payload.org at boundary proxy and isolate host PIVOT-WS-09 immediately.",
                "created_at": now - timedelta(hours=6),
            },
        ]
        _mock_db.setdefault("threat_hunting_findings", []).extend(th_findings)

        # 4. Digital Forensics Cases
        for_case_1_id = "22222222-3333-4444-5555-666666666601"
        for_case_2_id = "22222222-3333-4444-5555-666666666602"

        for_cases = [
            {
                "id": for_case_1_id,
                "organization_id": org_id,
                "case_number": "FOR-2026-00088",
                "title": "Primary Domain Controller Ticket Forgery Investigation",
                "description": "Comprehensive digital forensics analysis following suspected Kerberoasting and DC memory dump attempt.",
                "investigation_objective": "Establish root cause, reconstruct adversary timeline, assess compromised credentials, and verify integrity of core credentials database.",
                "status": "Analysis",
                "priority": "P1",
                "assigned_investigator_id": "00000000-0000-0000-0000-000000000001",
                "related_incident_id": None,
                "related_hunting_case_id": th_case_1_id,
                "conclusion_summary": None,
                "created_by": "00000000-0000-0000-0000-000000000001",
                "created_at": yesterday,
                "updated_at": now,
            },
            {
                "id": for_case_2_id,
                "organization_id": org_id,
                "case_number": "FOR-2026-00089",
                "title": "DMZ Web Cluster Reverse Shell Incident",
                "description": "Post-incident forensics examination of Apache reverse proxy container compromise.",
                "investigation_objective": "Identify entry vector, recover uploaded web shell artifacts, and verify if persistence mechanisms were established.",
                "status": "Evidence Collection",
                "priority": "P2",
                "assigned_investigator_id": "00000000-0000-0000-0000-000000000001",
                "related_incident_id": None,
                "related_hunting_case_id": th_case_3_id,
                "conclusion_summary": None,
                "created_by": "00000000-0000-0000-0000-000000000001",
                "created_at": now - timedelta(hours=8),
                "updated_at": now,
            },
        ]
        _mock_db.setdefault("forensic_cases", []).extend(for_cases)

        # 5. Forensic Evidence Items
        ev_1_id = "33333333-4444-5555-6666-777777777701"
        ev_2_id = "33333333-4444-5555-6666-777777777702"
        ev_3_id = "33333333-4444-5555-6666-777777777703"

        ev_1_sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        ev_2_sha = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        ev_3_sha = "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"

        ev_items = [
            {
                "id": ev_1_id,
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "evidence_name": "DC-01 Security Event Log Export",
                "category": "log_file",
                "original_filename": "dc01_security_evtx_export.json",
                "storage_path": f"evidence/{org_id}/{for_case_1_id}/{ev_1_id}/dc01_security_evtx_export.json",
                "mime_type": "application/json",
                "file_size": 4194304,
                "sha256_hash": ev_1_sha,
                "md5_hash": "c4ca4238a0b923820dcc509a6f75849b",
                "uploaded_by": "00000000-0000-0000-0000-000000000001",
                "description": "Raw exported security audit event logs from DC-01 covering 48-hour incident window.",
                "is_derived": False,
                "parent_evidence_id": None,
                "transformation_notes": None,
                "integrity_status": "Verified",
                "last_verified_at": now,
                "created_at": yesterday,
            },
            {
                "id": ev_2_id,
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "evidence_name": "DMZ Gateway Network Flow Capture",
                "category": "network_metadata_pcap",
                "original_filename": "dmz_flow_capture_20261031.pcap",
                "storage_path": f"evidence/{org_id}/{for_case_1_id}/{ev_2_id}/dmz_flow_capture_20261031.pcap",
                "mime_type": "application/vnd.tcpdump.pcap",
                "file_size": 15728640,
                "sha256_hash": ev_2_sha,
                "md5_hash": "c81e728d9d4c2f636f067f89cc14862c",
                "uploaded_by": "00000000-0000-0000-0000-000000000001",
                "description": "Bilateral network packet capture during active exploitation phase.",
                "is_derived": False,
                "parent_evidence_id": None,
                "transformation_notes": None,
                "integrity_status": "Verified",
                "last_verified_at": now,
                "created_at": yesterday,
            },
            {
                "id": ev_3_id,
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "evidence_name": "Normalized Kerberos Auth Records",
                "category": "csv_export",
                "original_filename": "dc01_normalized_auth_failures.csv",
                "storage_path": f"evidence/{org_id}/{for_case_1_id}/{ev_3_id}/dc01_normalized_auth_failures.csv",
                "mime_type": "text/csv",
                "file_size": 131072,
                "sha256_hash": ev_3_sha,
                "md5_hash": "eccbc87e4b5ce2fe28308fd9f2a7baf3",
                "uploaded_by": "00000000-0000-0000-0000-000000000001",
                "description": "Extracted Event 4625 and 4769 records from primary log dump.",
                "is_derived": True,
                "parent_evidence_id": ev_1_id,
                "transformation_notes": "Derived via safe static log normalization pipeline.",
                "integrity_status": "Verified",
                "last_verified_at": now,
                "created_at": now - timedelta(hours=10),
            },
        ]
        _mock_db.setdefault("forensic_evidence_items", []).extend(ev_items)

        # 6. Tamper-Evident Chain of Custody for Evidence 1
        genesis_hash = hashlib.sha256(f"{'0'*64}:{ev_1_id}:Evidence Collection Officer:Collected:{(yesterday - timedelta(minutes=15)).isoformat()}:{{}}".encode()).hexdigest()
        upload_hash = hashlib.sha256(f"{genesis_hash}:{ev_1_id}:Chief Security Architect:Uploaded:{yesterday.isoformat()}:{{}}".encode()).hexdigest()
        verify_hash = hashlib.sha256(f"{upload_hash}:{ev_1_id}:Integrity Verifier:Integrity_Verified:{now.isoformat()}:{{}}".encode()).hexdigest()

        custody_events = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "evidence_id": ev_1_id,
                "actor_id": "00000000-0000-0000-0000-000000000001",
                "actor_name": "Evidence Collection Officer",
                "action": "Collected",
                "timestamp": yesterday - timedelta(minutes=15),
                "previous_record_hash": "0" * 64,
                "current_record_hash": genesis_hash,
                "metadata": {"_is_seeded_block": True, "acquisition_tool": "CyberShield Evidence Harvester"},
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "evidence_id": ev_1_id,
                "actor_id": "00000000-0000-0000-0000-000000000001",
                "actor_name": "Chief Security Architect",
                "action": "Uploaded",
                "timestamp": yesterday,
                "previous_record_hash": genesis_hash,
                "current_record_hash": upload_hash,
                "metadata": {"_is_seeded_block": True, "storage_vault": "secure-s3-glacier"},
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "evidence_id": ev_1_id,
                "actor_id": "00000000-0000-0000-0000-000000000001",
                "actor_name": "Integrity Verifier",
                "action": "Integrity_Verified",
                "timestamp": now,
                "previous_record_hash": upload_hash,
                "current_record_hash": verify_hash,
                "metadata": {"_is_seeded_block": True, "status": "Passed"},
            },
        ]
        _mock_db.setdefault("forensic_custody_events", []).extend(custody_events)

        # 7. Forensic Case Notes
        notes = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "author_id": "00000000-0000-0000-0000-000000000001",
                "author_name": "Chief Security Architect",
                "note_type": "Confirmed_Observation",
                "content": "Extracted Kerberos Event 4769 demonstrates encryption downgrade to RC4-HMAC (Ticket Encryption Type: 0x17) indicating intentional roasting attempt.",
                "created_at": yesterday,
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "author_id": "00000000-0000-0000-0000-000000000001",
                "author_name": "Chief Security Architect",
                "note_type": "Analyst_Hypothesis",
                "content": "Adversary likely obtained initial domain foothold through phishing campaign targeting marketing workstation PIVOT-WS-09.",
                "created_at": now - timedelta(hours=14),
            },
        ]
        _mock_db.setdefault("forensic_case_notes", []).extend(notes)

        # 8. Forensic Reports
        reports = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "forensic_case_id": for_case_1_id,
                "report_number": "REP-FOR-2026-00042",
                "title": "Comprehensive Forensics Examination: DC-01 Kerberoasting & Lateral Movement Attack",
                "author_id": "00000000-0000-0000-0000-000000000001",
                "author_name": "Chief Security Architect",
                "scope_and_authorization": "Authorized under mandate #CYBER-2026-001 by Chief Information Security Officer for Apex CyberDefense infrastructure.",
                "executive_summary": "On October 31, 2026, anomalous Kerberos ticket-granting activity was detected originating from subnet 192.168.10.0/24...",
                "evidence_inventory_summary": [
                    {"name": "DC-01 Security Event Log Export", "sha256": ev_1_sha, "integrity": "Verified"},
                    {"name": "DMZ Gateway Network Flow Capture", "sha256": ev_2_sha, "integrity": "Verified"},
                ],
                "chain_of_custody_verified": True,
                "analysis_methodology": "Adhering to NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response. Evidence was acquired bit-stream, integrity validated with SHA-256 hash chains, and analyzed in an isolated static parsing environment.",
                "confirmed_findings": [
                    {"finding": "RC4 Kerberos Ticket Downgrade targeting SPN MSSQLSvc", "severity": "High", "mitre": "T1558.003"},
                    {"finding": "Outbound encrypted beaconing to 198.51.100.45", "severity": "Critical", "mitre": "T1071.001"},
                ],
                "analyst_hypotheses": [
                    {"hypothesis": "Initial access gained via spearphishing attachment on workstation PIVOT-WS-09.", "confidence": "Medium-High"}
                ],
                "mitre_attack_mappings": [
                    {"tactic": "Credential Access", "technique_id": "T1558.003", "name": "Kerberoasting"},
                    {"tactic": "Command and Control", "technique_id": "T1071.001", "name": "Web Protocols"},
                ],
                "limitations": "Endpoint memory dumps were not captured prior to system reboot; volatile process states were reconstructed from Sysmon telemetry.",
                "recommendations": [
                    {"priority": "Immediate", "action": "Rotate passwords for all Active Directory service accounts."},
                    {"priority": "Immediate", "action": "Enforce AES-only Kerberos encryption policy across domain controllers."},
                ],
                "conclusion": "Threat was successfully contained before domain database exfiltration occurred. All compromised credentials were reset.",
                "file_format": "json",
                "created_at": now - timedelta(hours=4),
            }
        ]
        _mock_db.setdefault("forensic_reports", []).extend(reports)

        _mock_db[f"sprint17_seeded_{org_id}"] = True

    def _ensure_sprint18_seeds(self, org_id: str) -> None:
        if _mock_db.get(f"sprint18_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)
        two_days_ago = now - timedelta(days=2)

        # 1. Identity Providers
        idp_1_id = "11111111-2222-3333-4444-555555555551"
        idp_2_id = "11111111-2222-3333-4444-555555555552"
        idps = [
            {
                "id": idp_1_id,
                "organization_id": org_id,
                "name": "Corporate Microsoft Entra ID",
                "provider_type": "azure_ad",
                "issuer_url": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/v2.0",
                "client_id": "9a7b5f12-04e8-4c12-8924-f7e812d89001",
                "client_secret_encrypted": "enc_sec_placeholder_azure_ad_secret_masked",
                "client_secret_last4": "8901",
                "authorization_url": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/authorize",
                "token_url": "https://login.microsoftonline.com/72f988bf-86f1-41af-91ab-2d7cd011db47/oauth2/v2.0/token",
                "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
                "saml_metadata_url": None,
                "saml_entity_id": None,
                "saml_acs_url": None,
                "domains": ["apexcyberdefense.io", "corp.apexcyber.com"],
                "is_enabled": True,
                "enforce_sso": False,
                "sync_profile_attributes": True,
                "default_role": "analyst",
                "metadata": {"tenant_id": "72f988bf-86f1-41af-91ab-2d7cd011db47"},
                "created_at": two_days_ago.isoformat(),
                "updated_at": yesterday.isoformat(),
            },
            {
                "id": idp_2_id,
                "organization_id": org_id,
                "name": "Okta Workforce IAM (Staging)",
                "provider_type": "okta",
                "issuer_url": "https://apexcyber.okta.com",
                "client_id": "0oa2k89x1p8Lkq902h7",
                "client_secret_encrypted": "enc_sec_placeholder_okta_secret_masked",
                "client_secret_last4": "2h7a",
                "authorization_url": "https://apexcyber.okta.com/oauth2/v1/authorize",
                "token_url": "https://apexcyber.okta.com/oauth2/v1/token",
                "userinfo_url": "https://apexcyber.okta.com/oauth2/v1/userinfo",
                "saml_metadata_url": None,
                "saml_entity_id": None,
                "saml_acs_url": None,
                "domains": ["staging.apexcyberdefense.io"],
                "is_enabled": False,
                "enforce_sso": False,
                "sync_profile_attributes": True,
                "default_role": "viewer",
                "metadata": {},
                "created_at": yesterday.isoformat(),
                "updated_at": yesterday.isoformat(),
            }
        ]
        _mock_db.setdefault("identity_providers", []).extend(idps)

        # 2. Domain Verifications
        domains = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "identity_provider_id": idp_1_id,
                "domain_name": "apexcyberdefense.io",
                "verification_token": "cybershield-verify=d7a9f821e4bc901a88b209fa",
                "status": "verified",
                "verified_at": two_days_ago.isoformat(),
                "last_checked_at": now.isoformat(),
                "dns_records_found": [{"type": "TXT", "value": "cybershield-verify=d7a9f821e4bc901a88b209fa"}],
                "created_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "identity_provider_id": idp_1_id,
                "domain_name": "corp.apexcyber.com",
                "verification_token": "cybershield-verify=8b23c914efaac811200199fe",
                "status": "pending",
                "verified_at": None,
                "last_checked_at": yesterday.isoformat(),
                "dns_records_found": [],
                "created_at": yesterday.isoformat(),
            }
        ]
        _mock_db.setdefault("identity_domain_verifications", []).extend(domains)

        # 3. Organization Identity Policies
        org_policy = {
            "id": str(uuid4()),
            "organization_id": org_id,
            "mfa_required": False,
            "mfa_enforced_roles": ["owner", "admin"],
            "sso_required": False,
            "sso_bypass_allowed_for_breakglass": True,
            "breakglass_email": "breakglass@apexcyberdefense.io",
            "session_idle_timeout_minutes": 60,
            "session_absolute_timeout_hours": 24,
            "max_concurrent_sessions_per_user": 5,
            "allowed_ip_cidrs": [],
            "allowed_email_domains": ["apexcyberdefense.io", "corp.apexcyber.com"],
            "require_step_up_for_sensitive_actions": True,
            "created_at": two_days_ago.isoformat(),
            "updated_at": yesterday.isoformat(),
        }
        _mock_db.setdefault("organization_identity_policies", []).append(org_policy)

        # 4. User Security Preferences
        default_user_id = "00000000-0000-0000-0000-000000000001"
        user_prefs = {
            "id": str(uuid4()),
            "user_id": default_user_id,
            "organization_id": org_id,
            "mfa_enabled": False,
            "totp_secret_encrypted": None,
            "totp_enrolled_at": None,
            "hashed_recovery_codes": [],
            "recovery_codes_generated_at": None,
            "current_aal": "aal1",
            "webauthn_credentials": [],
            "created_at": two_days_ago.isoformat(),
            "updated_at": yesterday.isoformat(),
        }
        _mock_db.setdefault("user_security_preferences", []).append(user_prefs)

        # 5. Session Security Metadata
        sess_1_id = "sess-0000-0000-0000-000000000001"
        sess_2_id = "sess-0000-0000-0000-000000000002"
        sess_3_id = "sess-0000-0000-0000-000000000003"
        sessions = [
            {
                "id": sess_1_id,
                "user_id": default_user_id,
                "organization_id": org_id,
                "session_token_hash": "tokhash_current_active_session_001",
                "device_type": "desktop",
                "browser": "Chrome 131.0",
                "os": "macOS 15.1",
                "ip_address": "192.168.1.100",
                "approx_location": "San Francisco, CA, US",
                "is_suspicious": False,
                "suspicion_reasons": [],
                "aal_level": "aal1",
                "created_at": (now - timedelta(hours=3)).isoformat(),
                "last_active_at": now.isoformat(),
                "expires_at": (now + timedelta(hours=21)).isoformat(),
                "revoked_at": None,
                "revoked_reason": None,
            },
            {
                "id": sess_2_id,
                "user_id": default_user_id,
                "organization_id": org_id,
                "session_token_hash": "tokhash_mobile_active_session_002",
                "device_type": "mobile",
                "browser": "Safari Mobile 18.1",
                "os": "iOS 18.1",
                "ip_address": "172.56.21.89",
                "approx_location": "San Jose, CA, US",
                "is_suspicious": False,
                "suspicion_reasons": [],
                "aal_level": "aal1",
                "created_at": (now - timedelta(hours=8)).isoformat(),
                "last_active_at": (now - timedelta(minutes=45)).isoformat(),
                "expires_at": (now + timedelta(hours=16)).isoformat(),
                "revoked_at": None,
                "revoked_reason": None,
            },
            {
                "id": sess_3_id,
                "user_id": default_user_id,
                "organization_id": org_id,
                "session_token_hash": "tokhash_suspicious_session_003",
                "device_type": "desktop",
                "browser": "Headless Chrome / Curl",
                "os": "Linux x86_64",
                "ip_address": "203.0.113.19",
                "approx_location": "Bucharest, RO",
                "is_suspicious": True,
                "suspicion_reasons": ["Unrecognized geographic origin (Romania)", "Impossible travel speed from California (<15m)"],
                "aal_level": "aal1",
                "created_at": (now - timedelta(minutes=20)).isoformat(),
                "last_active_at": (now - timedelta(minutes=18)).isoformat(),
                "expires_at": (now + timedelta(hours=23)).isoformat(),
                "revoked_at": None,
                "revoked_reason": None,
            }
        ]
        _mock_db.setdefault("session_security_metadata", []).extend(sessions)

        # 6. Access Policies (Zero Trust ABAC / RBAC)
        policies = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "name": "Administrative Full Authorization",
                "description": "Full access grant for Organization Owners and Security Administrators across all modules.",
                "resource_type": "all",
                "action": "all",
                "effect": "allow",
                "allowed_roles": ["owner", "admin"],
                "require_mfa": False,
                "min_aal": "aal1",
                "ip_whitelist": [],
                "is_enabled": True,
                "priority": 10,
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "name": "Enforce MFA for Digital Forensics Evidence Export",
                "description": "Requires Authentication Assurance Level 2 (TOTP MFA) to export disk images and chain-of-custody forensic evidence.",
                "resource_type": "forensics",
                "action": "export",
                "effect": "allow",
                "allowed_roles": ["owner", "admin", "analyst"],
                "require_mfa": True,
                "min_aal": "aal2",
                "ip_whitelist": [],
                "is_enabled": True,
                "priority": 20,
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "name": "Enforce MFA for API Key Creation & Rotation",
                "description": "Protects programmatic credentials by mandating active MFA verification for API key lifecycle actions.",
                "resource_type": "api_keys",
                "action": "write",
                "effect": "allow",
                "allowed_roles": ["owner", "admin"],
                "require_mfa": True,
                "min_aal": "aal2",
                "ip_whitelist": [],
                "is_enabled": True,
                "priority": 30,
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "name": "Restrict Destructive Actions for Read-Only Viewers",
                "description": "Explicit deny policy preventing viewer accounts from deleting any resources or policies.",
                "resource_type": "all",
                "action": "delete",
                "effect": "deny",
                "allowed_roles": ["viewer"],
                "require_mfa": False,
                "min_aal": "aal1",
                "ip_whitelist": [],
                "is_enabled": True,
                "priority": 5,
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            }
        ]
        _mock_db.setdefault("access_policies", []).extend(policies)

        # 7. Identity Audit Events
        audit_events = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "user_id": default_user_id,
                "user_email": "admin@apexcyberdefense.io",
                "event_type": "login_success",
                "status": "success",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0",
                "session_id": sess_1_id,
                "correlation_id": "corr-auth-init-001",
                "details": {"method": "password", "aal": "aal1"},
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "user_id": default_user_id,
                "user_email": "admin@apexcyberdefense.io",
                "event_type": "sso_provider_configured",
                "status": "success",
                "ip_address": "192.168.1.100",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0",
                "session_id": sess_1_id,
                "correlation_id": "corr-idp-setup-002",
                "details": {"provider_name": "Corporate Microsoft Entra ID", "provider_type": "azure_ad"},
                "created_at": (now - timedelta(hours=2)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "user_id": default_user_id,
                "user_email": "admin@apexcyberdefense.io",
                "event_type": "suspicious_session_flagged",
                "status": "warning",
                "ip_address": "203.0.113.19",
                "user_agent": "curl/7.88.1",
                "session_id": sess_3_id,
                "correlation_id": "corr-sec-alert-003",
                "details": {"reason": "Geographic jump to Bucharest, RO within 15 minutes"},
                "created_at": (now - timedelta(minutes=20)).isoformat(),
            }
        ]
        _mock_db.setdefault("identity_audit_events", []).extend(audit_events)

        _mock_db[f"sprint18_seeded_{org_id}"] = True

    # -------------------------------------------------------------------------
    # Sprint 18: Enterprise Identity, SSO, MFA & Zero Trust Data Access Methods
    # -------------------------------------------------------------------------

    def list_identity_providers(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        return [p for p in _mock_db.get("identity_providers", []) if p.get("organization_id") == org_id]

    def get_identity_provider(self, org_id: str, provider_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("identity_providers", []):
            if p.get("organization_id") == org_id and p.get("id") == provider_id:
                return p
        return None

    def create_identity_provider(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        item = {
            "id": data.get("id") or str(uuid4()),
            "organization_id": org_id,
            "name": data["name"],
            "provider_type": data["provider_type"],
            "issuer_url": data["issuer_url"],
            "client_id": data["client_id"],
            "client_secret_encrypted": data.get("client_secret_encrypted"),
            "client_secret_last4": data.get("client_secret_last4") or (data.get("client_secret", "")[-4:] if data.get("client_secret") else None),
            "authorization_url": data.get("authorization_url"),
            "token_url": data.get("token_url"),
            "userinfo_url": data.get("userinfo_url"),
            "saml_metadata_url": data.get("saml_metadata_url"),
            "saml_entity_id": data.get("saml_entity_id"),
            "saml_acs_url": data.get("saml_acs_url"),
            "domains": data.get("domains", []),
            "is_enabled": data.get("is_enabled", True),
            "enforce_sso": data.get("enforce_sso", False),
            "sync_profile_attributes": data.get("sync_profile_attributes", True),
            "default_role": data.get("default_role", "analyst"),
            "metadata": data.get("metadata", {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("identity_providers", []).append(item)
        return item

    def update_identity_provider(self, org_id: str, provider_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("identity_providers", []):
            if p.get("organization_id") == org_id and p.get("id") == provider_id:
                for k, v in data.items():
                    if v is not None:
                        p[k] = v
                p["updated_at"] = datetime.now(timezone.utc).isoformat()
                return p
        return None

    def delete_identity_provider(self, org_id: str, provider_id: str) -> bool:
        self._ensure_sprint18_seeds(org_id)
        idps = _mock_db.get("identity_providers", [])
        for i, p in enumerate(idps):
            if p.get("organization_id") == org_id and p.get("id") == provider_id:
                idps.pop(i)
                return True
        return False

    def list_domain_verifications(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        return [d for d in _mock_db.get("identity_domain_verifications", []) if d.get("organization_id") == org_id]

    def get_domain_verification(self, org_id: str, domain_name: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for d in _mock_db.get("identity_domain_verifications", []):
            if d.get("organization_id") == org_id and d.get("domain_name", "").lower() == domain_name.lower():
                return d
        return None

    def create_domain_verification(self, org_id: str, domain_name: str, token: str, provider_id: Optional[str] = None) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        item = {
            "id": str(uuid4()),
            "organization_id": org_id,
            "identity_provider_id": provider_id,
            "domain_name": domain_name.lower(),
            "verification_token": token,
            "status": "pending",
            "verified_at": None,
            "last_checked_at": datetime.now(timezone.utc).isoformat(),
            "dns_records_found": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("identity_domain_verifications", []).append(item)
        return item

    def update_domain_verification(self, org_id: str, domain_name: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for d in _mock_db.get("identity_domain_verifications", []):
            if d.get("organization_id") == org_id and d.get("domain_name", "").lower() == domain_name.lower():
                for k, v in data.items():
                    d[k] = v
                return d
        return None

    def get_organization_identity_policy(self, org_id: str) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("organization_identity_policies", []):
            if p.get("organization_id") == org_id:
                return p
        default_policy = {
            "id": str(uuid4()),
            "organization_id": org_id,
            "mfa_required": False,
            "mfa_enforced_roles": ["owner", "admin"],
            "sso_required": False,
            "sso_bypass_allowed_for_breakglass": True,
            "breakglass_email": "breakglass@apexcyberdefense.io",
            "session_idle_timeout_minutes": 60,
            "session_absolute_timeout_hours": 24,
            "max_concurrent_sessions_per_user": 5,
            "allowed_ip_cidrs": [],
            "allowed_email_domains": [],
            "require_step_up_for_sensitive_actions": True,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("organization_identity_policies", []).append(default_policy)
        return default_policy

    def update_organization_identity_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        policy = self.get_organization_identity_policy(org_id)
        for k, v in data.items():
            if v is not None:
                policy[k] = v
        policy["updated_at"] = datetime.now(timezone.utc).isoformat()
        return policy

    def get_user_security_preferences(self, user_id: str, org_id: str) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("user_security_preferences", []):
            if p.get("user_id") == user_id and p.get("organization_id") == org_id:
                return p
        new_prefs = {
            "id": str(uuid4()),
            "user_id": user_id,
            "organization_id": org_id,
            "mfa_enabled": False,
            "totp_secret_encrypted": None,
            "totp_enrolled_at": None,
            "hashed_recovery_codes": [],
            "recovery_codes_generated_at": None,
            "current_aal": "aal1",
            "webauthn_credentials": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("user_security_preferences", []).append(new_prefs)
        return new_prefs

    def upsert_user_security_preferences(self, user_id: str, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        prefs = self.get_user_security_preferences(user_id, org_id)
        for k, v in data.items():
            if v is not None:
                prefs[k] = v
        prefs["updated_at"] = datetime.now(timezone.utc).isoformat()
        return prefs

    def list_user_sessions(self, user_id: str, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        return [
            s for s in _mock_db.get("session_security_metadata", [])
            if s.get("user_id") == user_id and s.get("organization_id") == org_id
        ]

    def get_session_by_id(self, org_id: str, session_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for s in _mock_db.get("session_security_metadata", []):
            if s.get("organization_id") == org_id and s.get("id") == session_id:
                return s
        return None

    def upsert_session_metadata(self, session_data: Dict[str, Any]) -> Dict[str, Any]:
        sessions = _mock_db.setdefault("session_security_metadata", [])
        sess_id = session_data.get("id")
        for s in sessions:
            if s.get("id") == sess_id:
                s.update(session_data)
                return s
        sessions.append(session_data)
        return session_data

    def revoke_session(self, org_id: str, session_id: str, reason: str = "User requested revocation") -> bool:
        self._ensure_sprint18_seeds(org_id)
        for s in _mock_db.get("session_security_metadata", []):
            if s.get("organization_id") == org_id and s.get("id") == session_id:
                s["revoked_at"] = datetime.now(timezone.utc).isoformat()
                s["revoked_reason"] = reason
                return True
        return False

    def revoke_all_user_sessions(self, user_id: str, org_id: str, keep_session_id: Optional[str] = None) -> int:
        self._ensure_sprint18_seeds(org_id)
        revoked_count = 0
        now_str = datetime.now(timezone.utc).isoformat()
        for s in _mock_db.get("session_security_metadata", []):
            if s.get("user_id") == user_id and s.get("organization_id") == org_id:
                if keep_session_id and s.get("id") == keep_session_id:
                    continue
                if not s.get("revoked_at"):
                    s["revoked_at"] = now_str
                    s["revoked_reason"] = "Revoke all sessions command"
                    revoked_count += 1
        return revoked_count

    def list_access_policies(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        return sorted(
            [p for p in _mock_db.get("access_policies", []) if p.get("organization_id") == org_id],
            key=lambda x: x.get("priority", 100)
        )

    def get_access_policy(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("access_policies", []):
            if p.get("organization_id") == org_id and p.get("id") == policy_id:
                return p
        return None

    def create_access_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        item = {
            "id": data.get("id") or str(uuid4()),
            "organization_id": org_id,
            "name": data["name"],
            "description": data.get("description"),
            "resource_type": data.get("resource_type", "all"),
            "action": data.get("action", "all"),
            "effect": data.get("effect", "allow"),
            "allowed_roles": data.get("allowed_roles", ["owner", "admin", "analyst", "viewer"]),
            "require_mfa": data.get("require_mfa", False),
            "min_aal": data.get("min_aal", "aal1"),
            "ip_whitelist": data.get("ip_whitelist", []),
            "is_enabled": data.get("is_enabled", True),
            "priority": data.get("priority", 100),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("access_policies", []).append(item)
        return item

    def update_access_policy(self, org_id: str, policy_id: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        for p in _mock_db.get("access_policies", []):
            if p.get("organization_id") == org_id and p.get("id") == policy_id:
                for k, v in data.items():
                    if v is not None:
                        p[k] = v
                p["updated_at"] = datetime.now(timezone.utc).isoformat()
                return p
        return None

    def delete_access_policy(self, org_id: str, policy_id: str) -> bool:
        self._ensure_sprint18_seeds(org_id)
        policies = _mock_db.get("access_policies", [])
        for i, p in enumerate(policies):
            if p.get("organization_id") == org_id and p.get("id") == policy_id:
                policies.pop(i)
                return True
        return False

    def list_identity_audit_events(self, org_id: str, limit: int = 50, event_type: Optional[str] = None, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        self._ensure_sprint18_seeds(org_id)
        events = [e for e in _mock_db.get("identity_audit_events", []) if e.get("organization_id") == org_id]
        if event_type:
            events = [e for e in events if e.get("event_type") == event_type]
        if user_id:
            events = [e for e in events if e.get("user_id") == user_id]
        events.sort(key=lambda x: str(x.get("created_at")), reverse=True)
        return events[:limit]

    def create_identity_audit_event(self, org_id: str, event_data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_sprint18_seeds(org_id)
        item = {
            "id": event_data.get("id") or str(uuid4()),
            "organization_id": org_id,
            "user_id": event_data.get("user_id"),
            "user_email": event_data.get("user_email"),
            "event_type": event_data["event_type"],
            "status": event_data.get("status", "success"),
            "ip_address": event_data.get("ip_address", "127.0.0.1"),
            "user_agent": event_data.get("user_agent"),
            "session_id": event_data.get("session_id"),
            "correlation_id": event_data.get("correlation_id") or f"corr-{uuid4().hex[:12]}",
            "details": event_data.get("details", {}),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("identity_audit_events", []).append(item)
        return item

    def record_mfa_attempt(self, user_id: str, org_id: str, ip_address: str, attempt_type: str, is_successful: bool) -> None:
        self._ensure_sprint18_seeds(org_id)
        _mock_db.setdefault("mfa_challenge_attempts", []).append({
            "id": str(uuid4()),
            "user_id": user_id,
            "organization_id": org_id,
            "ip_address": ip_address,
            "attempt_type": attempt_type,
            "is_successful": is_successful,
            "attempted_at": datetime.now(timezone.utc),
        })

    def count_recent_mfa_failures(self, user_id: str, org_id: str, minutes: int = 15) -> int:
        self._ensure_sprint18_seeds(org_id)
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        failures = 0
        for att in _mock_db.get("mfa_challenge_attempts", []):
            if att.get("user_id") == user_id and att.get("organization_id") == org_id:
                if not att.get("is_successful"):
                    att_time = att.get("attempted_at")
                    if isinstance(att_time, str):
                        att_time = datetime.fromisoformat(att_time.replace("Z", "+00:00"))
                    if att_time >= cutoff:
                        failures += 1
        return failures

    # -------------------------------------------------------------------------
    # Sprint 19: Advanced Security Validation & Assurance Data Access Methods
    # -------------------------------------------------------------------------

    def _ensure_sprint19_seeds(self, org_id: str) -> None:
        if _mock_db.get(f"sprint19_seeded_{org_id}"):
            return

        now = datetime.now(timezone.utc)
        yesterday = now - timedelta(days=1)
        two_days_ago = now - timedelta(days=2)

        # 1. Security Assessments
        ass_1_id = "19191919-0000-0000-0000-000000000001"
        ass_2_id = "19191919-0000-0000-0000-000000000002"

        assessments = [
            {
                "id": ass_1_id,
                "organization_id": org_id,
                "assessment_name": "Full Architecture & API Penetration Validation (Automated Baseline)",
                "assessment_type": "full_suite",
                "target_environment": "staging",
                "status": "completed",
                "posture_score": 93.5,
                "risk_score": 15.0,
                "test_coverage_pct": 95.0,
                "compliance_pct": 94.0,
                "total_checks": 36,
                "passed_checks": 32,
                "failed_checks": 2,
                "warning_checks": 2,
                "critical_findings_count": 0,
                "high_findings_count": 1,
                "medium_findings_count": 2,
                "low_findings_count": 1,
                "started_at": (now - timedelta(hours=6)).isoformat(),
                "completed_at": (now - timedelta(hours=5, minutes=45)).isoformat(),
                "initiated_by_email": "secops@apexcyberdefense.io",
                "execution_logs": [
                    "Initialized automated security validation engine.",
                    "Executing OWASP Top 10 rule validation suite across 18 backend micro-routes.",
                    "Testing cross-tenant data isolation and authorization bounds.",
                    "Executed dynamic payload tests: SQL injection, command execution, path traversal.",
                    "Validated cryptographic suites, HSTS headers, and session revocation tracking.",
                    "Assessment concluded with 32 passed, 2 warnings, 2 remediations required."
                ],
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": ass_2_id,
                "organization_id": org_id,
                "assessment_name": "OWASP Top 10:2021 Core Verification Suite",
                "assessment_type": "owasp_top10",
                "target_environment": "staging",
                "status": "completed",
                "posture_score": 96.0,
                "risk_score": 10.0,
                "test_coverage_pct": 100.0,
                "compliance_pct": 96.0,
                "total_checks": 20,
                "passed_checks": 18,
                "failed_checks": 1,
                "warning_checks": 1,
                "critical_findings_count": 0,
                "high_findings_count": 1,
                "medium_findings_count": 1,
                "low_findings_count": 0,
                "started_at": yesterday.isoformat(),
                "completed_at": (yesterday + timedelta(minutes=18)).isoformat(),
                "initiated_by_email": "architect@apexcyberdefense.io",
                "execution_logs": [
                    "Started OWASP Top 10 automated checklist verification.",
                    "Tested A01 Broken Access Control: Passed.",
                    "Tested A02 Cryptographic Failures: Passed.",
                    "Tested A03 Injection: Passed.",
                    "Tested A05 Security Misconfiguration: 1 warning detected.",
                    "Tested A06 Vulnerable Components: 1 out-of-date sub-dependency identified."
                ],
                "created_at": yesterday.isoformat(),
            }
        ]
        _mock_db.setdefault("security_assessments", []).extend(assessments)

        # 2. Assessment Individual Checks
        checks = [
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A01-01",
                "category": "broken_access_control",
                "name": "Cross-Organization Tenant Boundary Isolation",
                "description": "Validates that authentication tokens from Organization A cannot access, query, or modify assets belonging to Organization B.",
                "framework_ref": "OWASP Top 10:2021 A01 | ASVS V1.4.1",
                "status": "pass",
                "severity": "critical",
                "evidence": {"endpoints_tested": 14, "cross_tenant_breaches": 0, "status_code_returned": 403},
                "remediation": "Preserve RLS and verify_org_access resolution on all database handlers.",
                "execution_time_ms": 145,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A01-02",
                "category": "broken_access_control",
                "name": "Role-Based Access Enforcement: Viewer Non-Destructive Guard",
                "description": "Verifies that read-only viewer accounts are strictly prevented from performing DELETE, UPDATE, and export operations.",
                "framework_ref": "OWASP Top 10:2021 A01 | ASVS V4.1.1",
                "status": "pass",
                "severity": "high",
                "evidence": {"mutations_attempted": 8, "blocked_with_403": 8},
                "remediation": "Ensure all write endpoints enforce allowed_roles=['owner', 'admin', 'analyst'].",
                "execution_time_ms": 110,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A02-01",
                "category": "cryptographic_failure",
                "name": "HTTP Strict Transport Security & Cryptographic Headers",
                "description": "Checks for the presence of HSTS, X-Content-Type-Options: nosniff, and frame sandboxing headers.",
                "framework_ref": "OWASP Top 10:2021 A02 | ASVS V14.4.1",
                "status": "pass",
                "severity": "high",
                "evidence": {"hsts_max_age": 31536000, "includeSubDomains": True, "preload": True},
                "remediation": "Maintain HSTS response headers via middleware on all public endpoints.",
                "execution_time_ms": 40,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A03-01",
                "category": "injection",
                "name": "SQL & Command Injection Parameter Validation",
                "description": "Tests query inputs with fuzzing vectors (' OR 1=1 --, sleep(), ;, | nc) to ensure database queries use strict parameterization.",
                "framework_ref": "OWASP Top 10:2021 A03 | ASVS V5.3.4",
                "status": "pass",
                "severity": "critical",
                "evidence": {"vectors_evaluated": 24, "escaped_or_rejected": 24},
                "remediation": "Strictly utilize SQLAlchemy / Supabase parameterized ORM constructs; disallow raw string concatenation.",
                "execution_time_ms": 280,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A05-01",
                "category": "security_misconfiguration",
                "name": "CORS Permissive Origins Staging Policy",
                "description": "Evaluates Access-Control-Allow-Origin response headers to prevent unauthorized cross-origin requests.",
                "framework_ref": "OWASP Top 10:2021 A05 | ASVS V14.5.3",
                "status": "warn",
                "severity": "medium",
                "evidence": {"configured_origins": ["http://localhost:3000", "http://localhost:8000"], "wildcard_detected": False},
                "remediation": "Restrict localhost origins in production deployment environment configs.",
                "execution_time_ms": 65,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A06-01",
                "category": "vulnerable_components",
                "name": "Dependency Supply Chain Vulnerability Scan (pip-audit)",
                "description": "Scans all pinned dependencies against the PyPI Advisory Database and OSV vulnerability catalog.",
                "framework_ref": "OWASP Top 10:2021 A06 | ASVS V10.3.2",
                "status": "fail",
                "severity": "high",
                "evidence": {"package": "pycparser", "installed": "2.21", "fixed": "2.22", "advisory": "CVE-2024-5412"},
                "remediation": "Run 'pip install --upgrade pycparser>=2.22' and rebuild virtual environment.",
                "execution_time_ms": 1150,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A07-01",
                "category": "auth_failures",
                "name": "Authentication Rate Limiting & Lockout Guard",
                "description": "Verifies that rapid consecutive invalid MFA TOTP or password attempts are blocked with HTTP 429.",
                "framework_ref": "OWASP Top 10:2021 A07 | ASVS V2.2.1",
                "status": "pass",
                "severity": "critical",
                "evidence": {"max_failed_attempts": 5, "lockout_duration_min": 15, "lockout_triggered": True},
                "remediation": "Preserve sliding-window challenge rate limiter in identity_service.",
                "execution_time_ms": 180,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "assessment_id": ass_1_id,
                "organization_id": org_id,
                "check_id": "OWASP-A10-01",
                "category": "ssrf",
                "name": "Server-Side Request Forgery Outbound Egress Filter",
                "description": "Ensures user-supplied webhook and connector URLs cannot target internal cloud metadata endpoints (169.254.169.254) or private RFC 1918 addresses.",
                "framework_ref": "OWASP Top 10:2021 A10 | ASVS V12.6.1",
                "status": "pass",
                "severity": "high",
                "evidence": {"private_targets_probed": ["169.254.169.254", "127.0.0.1", "10.0.0.1"], "rejected_count": 3},
                "remediation": "Maintain strict URL scheme and IP address validator before dispatching external HTTP requests.",
                "execution_time_ms": 320,
                "created_at": (now - timedelta(hours=6)).isoformat(),
            }
        ]
        _mock_db.setdefault("security_assessment_checks", []).extend(checks)

        # 3. Security Findings
        f_1_id = "19191919-1111-0000-0000-000000000001"
        f_2_id = "19191919-1111-0000-0000-000000000002"
        f_3_id = "19191919-1111-0000-0000-000000000003"
        f_4_id = "19191919-1111-0000-0000-000000000004"

        findings = [
            {
                "id": f_1_id,
                "organization_id": org_id,
                "finding_code": "SEC-2026-001",
                "title": "Permissive CORS Allowed Origins in Development Profile",
                "description": "CORS configuration permits http://localhost:3000 and http://localhost:8000. In production environments, this should be restricted strictly to authenticated tenant FQDNs.",
                "category": "Security Misconfiguration",
                "source_scanner": "config_audit",
                "severity": "medium",
                "affected_component": "FastAPI CORSMiddleware",
                "affected_asset_id": None,
                "cve_reference": None,
                "cwe_id": "CWE-942",
                "cvss_score": 4.8,
                "evidence": {"configured_origins": ["http://localhost:3000", "http://localhost:8000"]},
                "remediation_recommendation": "Configure environment-based ALLOWED_ORIGINS rejecting wildcard or localhost domains in non-dev deployments.",
                "remediation_pr_url": None,
                "assigned_to_user_id": "00000000-0000-0000-0000-000000000001",
                "assigned_to_name": "DevSecOps Lead",
                "status": "open",
                "first_detected_at": two_days_ago.isoformat(),
                "last_detected_at": now.isoformat(),
                "resolved_at": None,
                "verified_at": None,
                "verification_notes": None,
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": f_2_id,
                "organization_id": org_id,
                "finding_code": "SEC-2026-002",
                "title": "Vulnerable Sub-dependency: pycparser 2.21",
                "description": "pip-audit identified installed pycparser package version 2.21 containing moderate parsing denial of service vulnerability.",
                "category": "Vulnerable Dependency",
                "source_scanner": "pip_audit",
                "severity": "high",
                "affected_component": "pip:pycparser",
                "affected_asset_id": None,
                "cve_reference": "CVE-2024-5412",
                "cwe_id": "CWE-400",
                "cvss_score": 7.2,
                "evidence": {"package": "pycparser", "installed": "2.21", "fixed_in": "2.22"},
                "remediation_recommendation": "Upgrade to pycparser>=2.22 in requirements.txt or backend virtualenv.",
                "remediation_pr_url": "https://github.com/apexcyber/cybershield/pull/189",
                "assigned_to_user_id": "00000000-0000-0000-0000-000000000001",
                "assigned_to_name": "Lead Security Engineer",
                "status": "in_progress",
                "first_detected_at": yesterday.isoformat(),
                "last_detected_at": now.isoformat(),
                "resolved_at": None,
                "verified_at": None,
                "verification_notes": None,
                "created_at": yesterday.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": f_3_id,
                "organization_id": org_id,
                "finding_code": "SEC-2026-003",
                "title": "Redis Broker Unauthenticated Access in Dev Profile",
                "description": "The local Docker Compose configuration for Redis operates without requirepass password protection. In production environments, managed Redis with TLS and ACLs is required.",
                "category": "Security Misconfiguration",
                "source_scanner": "config_audit",
                "severity": "low",
                "affected_component": "Redis Docker Service",
                "affected_asset_id": None,
                "cve_reference": None,
                "cwe_id": "CWE-306",
                "cvss_score": 3.5,
                "evidence": {"service": "redis:7-alpine", "port": 6379, "auth": "none"},
                "remediation_recommendation": "Enforce REDIS_PASSWORD in production Docker Compose and deployment manifests.",
                "remediation_pr_url": None,
                "assigned_to_user_id": "00000000-0000-0000-0000-000000000001",
                "assigned_to_name": "Infrastructure Lead",
                "status": "accepted_risk",
                "first_detected_at": two_days_ago.isoformat(),
                "last_detected_at": now.isoformat(),
                "resolved_at": None,
                "verified_at": None,
                "verification_notes": "Accepted risk for local development and test runner environment; production utilizes AWS ElastiCache with TLS and auth.",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": f_4_id,
                "organization_id": org_id,
                "finding_code": "SEC-2026-004",
                "title": "Simulated Weak Session Cookie SameSite Policy in Legacy Browser Profile",
                "description": "Passive scan identified session cookies without explicit SameSite=Lax/Strict in legacy client test simulation.",
                "category": "Security Misconfiguration",
                "source_scanner": "owasp_zap",
                "severity": "low",
                "affected_component": "Session Cookie Handler",
                "affected_asset_id": None,
                "cve_reference": None,
                "cwe_id": "CWE-1275",
                "cvss_score": 2.9,
                "evidence": {"cookie": "sb-auth-token", "samesite": "lax"},
                "remediation_recommendation": "Enforce SameSite=Lax and Secure attributes on all Set-Cookie headers.",
                "remediation_pr_url": None,
                "assigned_to_user_id": "00000000-0000-0000-0000-000000000001",
                "assigned_to_name": "Application Security Architect",
                "status": "fixed",
                "first_detected_at": two_days_ago.isoformat(),
                "last_detected_at": yesterday.isoformat(),
                "resolved_at": yesterday.isoformat(),
                "verified_at": yesterday.isoformat(),
                "verification_notes": "Verified in Next.js middleware and FastAPI cookie handler.",
                "created_at": two_days_ago.isoformat(),
                "updated_at": yesterday.isoformat(),
            }
        ]
        _mock_db.setdefault("security_findings", []).extend(findings)

        # 4. Finding Notes
        notes = [
            {
                "id": str(uuid4()),
                "finding_id": f_2_id,
                "organization_id": org_id,
                "author_id": "00000000-0000-0000-0000-000000000001",
                "author_name": "Lead Security Engineer",
                "content": "Reviewed CVE-2024-5412 advisory. Vulnerability requires hostile C-source input parsing. CyberShield only parses trusted network schemas; low exploitability, but upgrading to 2.22 as best practice.",
                "created_at": yesterday.isoformat(),
            },
            {
                "id": str(uuid4()),
                "finding_id": f_3_id,
                "organization_id": org_id,
                "author_id": "00000000-0000-0000-0000-000000000001",
                "author_name": "Infrastructure Lead",
                "content": "Documented formal risk exception #EXC-2026-0001 for local sandbox container. Production uses AWS ElastiCache Redis cluster with IAM and encrypted transit.",
                "created_at": two_days_ago.isoformat(),
            }
        ]
        _mock_db.setdefault("security_finding_notes", []).extend(notes)

        # 5. Security Test Runs (API Security Validation Suite)
        test_run_1_id = "19191919-2222-0000-0000-000000000001"
        test_runs = [
            {
                "id": test_run_1_id,
                "organization_id": org_id,
                "suite_name": "Automated API Security & Tenant Isolation Validation Suite",
                "status": "completed",
                "total_tests": 16,
                "passed_tests": 16,
                "failed_tests": 0,
                "execution_duration_sec": 2.15,
                "target_host": "http://localhost:8000",
                "executed_by": "Security Regression Engine",
                "created_at": (now - timedelta(hours=3)).isoformat(),
            }
        ]
        _mock_db.setdefault("security_test_runs", []).extend(test_runs)

        # 6. Security Test Results
        test_results = [
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "BOLA: Cross-Tenant Asset Access Rejection",
                "endpoint": "/api/v1/assets",
                "http_method": "GET",
                "test_category": "bola",
                "expected_status": 403,
                "actual_status": 403,
                "passed": True,
                "request_payload": {"org_id": "foreign-org-id-0000-0000"},
                "response_summary": "Access denied: foreign organization boundary enforced.",
                "failure_reason": None,
                "execution_time_ms": 115,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "BFLA: Viewer Attempted Policy Deletion Blocked",
                "endpoint": "/api/v1/identity/policies/rules/{id}",
                "http_method": "DELETE",
                "test_category": "bfla",
                "expected_status": 403,
                "actual_status": 403,
                "passed": True,
                "request_payload": {},
                "response_summary": "Forbidden: Requires 'owner' or 'admin'.",
                "failure_reason": None,
                "execution_time_ms": 95,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "AUTH: Forged JWT Signature Rejection",
                "endpoint": "/api/v1/incidents",
                "http_method": "GET",
                "test_category": "auth_bypass",
                "expected_status": 401,
                "actual_status": 401,
                "passed": True,
                "request_payload": {},
                "response_summary": "Invalid token signature or expired credentials.",
                "failure_reason": None,
                "execution_time_ms": 45,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "AUTH: Expired JWT Token Rejection",
                "endpoint": "/api/v1/alerts",
                "http_method": "GET",
                "test_category": "auth_bypass",
                "expected_status": 401,
                "actual_status": 401,
                "passed": True,
                "request_payload": {},
                "response_summary": "Signature has expired.",
                "failure_reason": None,
                "execution_time_ms": 40,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "INPUT: SQL Injection Vector Filtering",
                "endpoint": "/api/v1/threat-hunting/search",
                "http_method": "POST",
                "test_category": "injection",
                "expected_status": 200,
                "actual_status": 200,
                "passed": True,
                "request_payload": {"query": "' OR '1'='1"},
                "response_summary": "Query safely escaped as literal parameter; zero injection.",
                "failure_reason": None,
                "execution_time_ms": 130,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "INPUT: Scope Command Injection Neutralization",
                "endpoint": "/api/v1/scopes",
                "http_method": "POST",
                "test_category": "injection",
                "expected_status": 422,
                "actual_status": 422,
                "passed": True,
                "request_payload": {"network_cidr": "192.168.1.0/24; cat /etc/passwd"},
                "response_summary": "Pydantic validator strictly rejected invalid CIDR syntax.",
                "failure_reason": None,
                "execution_time_ms": 60,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "ZERO TRUST: Forensics Evidence Export Mandates AAL2",
                "endpoint": "/api/v1/identity/policies/evaluate",
                "http_method": "POST",
                "test_category": "step_up_mfa",
                "expected_status": 200,
                "actual_status": 200,
                "passed": True,
                "request_payload": {"resource_type": "forensics", "action": "export"},
                "response_summary": "Policy engine strictly required AAL2; denied AAL1 caller.",
                "failure_reason": None,
                "execution_time_ms": 85,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            },
            {
                "id": str(uuid4()),
                "test_run_id": test_run_1_id,
                "organization_id": org_id,
                "test_name": "RATE LIMIT: Sliding Window Headers & 429 Lockout",
                "endpoint": "/api/v1/identity/mfa/verify",
                "http_method": "POST",
                "test_category": "rate_limit",
                "expected_status": 429,
                "actual_status": 429,
                "passed": True,
                "request_payload": {"code": "000000"},
                "response_summary": "429 Too Many Requests returned after 5 rapid invalid attempts.",
                "failure_reason": None,
                "execution_time_ms": 110,
                "created_at": (now - timedelta(hours=3)).isoformat(),
            }
        ]
        _mock_db.setdefault("security_test_results", []).extend(test_results)

        # 7. Architecture Component Inventory
        components = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "FastAPI Backend Core",
                "component_type": "application_backend",
                "version": "0.162.0 (Python 3.13)",
                "health_score": 96.5,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 1,
                "misconfigurations_count": 1,
                "security_gate_status": "compliant",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "Next.js SOC Web Dashboard",
                "component_type": "application_frontend",
                "version": "14.2.16 (TypeScript / React)",
                "health_score": 98.0,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 0,
                "misconfigurations_count": 0,
                "security_gate_status": "compliant",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "PostgreSQL Database Engine",
                "component_type": "database",
                "version": "PostgreSQL 16 (RLS Enabled)",
                "health_score": 100.0,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 0,
                "misconfigurations_count": 0,
                "security_gate_status": "compliant",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "Supabase Identity & Auth Service",
                "component_type": "identity_auth",
                "version": "GoTrue Auth / TOTP MFA",
                "health_score": 99.0,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 0,
                "misconfigurations_count": 0,
                "security_gate_status": "compliant",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "Redis Broker & Celery Queue",
                "component_type": "queue_broker",
                "version": "Redis 7.2 / Celery 5.6",
                "health_score": 91.0,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 0,
                "misconfigurations_count": 1,
                "security_gate_status": "warning",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "component_name": "Docker Fleet Container Runtime",
                "component_type": "container_runtime",
                "version": "Docker Engine 27.2",
                "health_score": 95.0,
                "last_scanned_at": now.isoformat(),
                "open_vulnerabilities_count": 0,
                "misconfigurations_count": 0,
                "security_gate_status": "compliant",
                "created_at": two_days_ago.isoformat(),
                "updated_at": now.isoformat(),
            }
        ]
        _mock_db.setdefault("security_component_inventory", []).extend(components)

        # 8. Scanner Configurations
        scanners = [
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "scanner_type": "api_security_engine",
                "is_enabled": True,
                "approved_targets": ["http://localhost:8000", "http://localhost:3000"],
                "scan_mode": "authenticated_safe",
                "max_requests_per_second": 15,
                "timeout_seconds": 180,
                "headers": {"X-CyberShield-Auditor": "InternalSecurityGate"},
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "scanner_type": "owasp_zap",
                "is_enabled": True,
                "approved_targets": ["http://localhost:3000"],
                "scan_mode": "baseline",
                "max_requests_per_second": 10,
                "timeout_seconds": 300,
                "headers": {},
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "scanner_type": "pip_audit",
                "is_enabled": True,
                "approved_targets": ["backend/pyproject.toml", "backend/requirements.txt"],
                "scan_mode": "passive",
                "max_requests_per_second": 5,
                "timeout_seconds": 120,
                "headers": {},
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            },
            {
                "id": str(uuid4()),
                "organization_id": org_id,
                "scanner_type": "trivy",
                "is_enabled": True,
                "approved_targets": ["cybershield-backend:latest", "cybershield-frontend:latest"],
                "scan_mode": "passive",
                "max_requests_per_second": 5,
                "timeout_seconds": 300,
                "headers": {},
                "created_at": two_days_ago.isoformat(),
                "updated_at": two_days_ago.isoformat(),
            }
        ]
        _mock_db.setdefault("security_scan_configurations", []).extend(scanners)

        _mock_db[f"sprint19_seeded_{org_id}"] = True

    def list_security_assessments(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        assessments = [a for a in _mock_db.get("security_assessments", []) if a.get("organization_id") == org_id]
        assessments.sort(key=lambda x: str(x.get("created_at")), reverse=True)
        return assessments[:limit]

    def get_security_assessment(self, org_id: str, assessment_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        for a in _mock_db.get("security_assessments", []):
            if a.get("organization_id") == org_id and a.get("id") == assessment_id:
                return a
        return None

    def create_security_assessment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_sprint19_seeds(org_id)
        item = {
            "id": data.get("id") or str(uuid4()),
            "organization_id": org_id,
            "assessment_name": data["assessment_name"],
            "assessment_type": data.get("assessment_type", "full_suite"),
            "target_environment": data.get("target_environment", "staging"),
            "status": data.get("status", "completed"),
            "posture_score": data.get("posture_score", 95.0),
            "risk_score": data.get("risk_score", 10.0),
            "test_coverage_pct": data.get("test_coverage_pct", 90.0),
            "compliance_pct": data.get("compliance_pct", 92.0),
            "total_checks": data.get("total_checks", 0),
            "passed_checks": data.get("passed_checks", 0),
            "failed_checks": data.get("failed_checks", 0),
            "warning_checks": data.get("warning_checks", 0),
            "critical_findings_count": data.get("critical_findings_count", 0),
            "high_findings_count": data.get("high_findings_count", 0),
            "medium_findings_count": data.get("medium_findings_count", 0),
            "low_findings_count": data.get("low_findings_count", 0),
            "started_at": data.get("started_at", datetime.now(timezone.utc).isoformat()),
            "completed_at": data.get("completed_at", datetime.now(timezone.utc).isoformat()),
            "initiated_by_email": data.get("initiated_by_email", "security@apexcyberdefense.io"),
            "execution_logs": data.get("execution_logs", ["Assessment initialized.", "Checks finished."]),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("security_assessments", []).append(item)
        return item

    def list_assessment_checks(self, org_id: str, assessment_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        return [
            c for c in _mock_db.get("security_assessment_checks", [])
            if c.get("organization_id") == org_id and c.get("assessment_id") == assessment_id
        ]

    def list_security_test_runs(self, org_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        runs = [r for r in _mock_db.get("security_test_runs", []) if r.get("organization_id") == org_id]
        runs.sort(key=lambda x: str(x.get("created_at")), reverse=True)
        return runs[:limit]

    def get_security_test_run(self, org_id: str, run_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        for r in _mock_db.get("security_test_runs", []):
            if r.get("organization_id") == org_id and r.get("id") == run_id:
                results = [
                    res for res in _mock_db.get("security_test_results", [])
                    if res.get("test_run_id") == run_id
                ]
                run_copy = dict(r)
                run_copy["results"] = results
                return run_copy
        return None

    def create_security_test_run(self, org_id: str, run_data: Dict[str, Any], results_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        self._ensure_sprint19_seeds(org_id)
        run_id = run_data.get("id") or str(uuid4())
        run_item = {
            "id": run_id,
            "organization_id": org_id,
            "suite_name": run_data.get("suite_name", "Automated API Security Suite"),
            "status": run_data.get("status", "completed"),
            "total_tests": len(results_data),
            "passed_tests": sum(1 for r in results_data if r.get("passed")),
            "failed_tests": sum(1 for r in results_data if not r.get("passed")),
            "execution_duration_sec": run_data.get("execution_duration_sec", 1.8),
            "target_host": run_data.get("target_host", "http://localhost:8000"),
            "executed_by": run_data.get("executed_by", "Automated Security Agent"),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("security_test_runs", []).append(run_item)

        saved_results = []
        for r in results_data:
            res_item = {
                "id": str(uuid4()),
                "test_run_id": run_id,
                "organization_id": org_id,
                "test_name": r["test_name"],
                "endpoint": r["endpoint"],
                "http_method": r["http_method"],
                "test_category": r.get("test_category", "api_security"),
                "expected_status": r["expected_status"],
                "actual_status": r["actual_status"],
                "passed": r["passed"],
                "request_payload": r.get("request_payload", {}),
                "response_summary": r.get("response_summary"),
                "failure_reason": r.get("failure_reason"),
                "execution_time_ms": r.get("execution_time_ms", 50),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            _mock_db.setdefault("security_test_results", []).append(res_item)
            saved_results.append(res_item)

        run_item["results"] = saved_results
        return run_item

    def list_security_findings(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        source_scanner: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        findings = [f for f in _mock_db.get("security_findings", []) if f.get("organization_id") == org_id]
        if status:
            findings = [f for f in findings if f.get("status") == status]
        if severity:
            findings = [f for f in findings if f.get("severity") == severity]
        if category:
            findings = [f for f in findings if f.get("category") == category]
        if source_scanner:
            findings = [f for f in findings if f.get("source_scanner") == source_scanner]
        findings.sort(key=lambda x: str(x.get("created_at")), reverse=True)
        return findings

    def get_security_finding(self, org_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        for f in _mock_db.get("security_findings", []):
            if f.get("organization_id") == org_id and f.get("id") == finding_id:
                notes = [
                    n for n in _mock_db.get("security_finding_notes", [])
                    if n.get("finding_id") == finding_id
                ]
                history = [
                    h for h in _mock_db.get("security_finding_history", [])
                    if h.get("finding_id") == finding_id
                ]
                f_copy = dict(f)
                f_copy["notes"] = notes
                f_copy["history"] = history
                return f_copy
        return None

    def create_security_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        self._ensure_sprint19_seeds(org_id)
        count = len(_mock_db.get("security_findings", [])) + 1
        item = {
            "id": data.get("id") or str(uuid4()),
            "organization_id": org_id,
            "finding_code": data.get("finding_code") or f"SEC-2026-{str(count).zfill(3)}",
            "title": data["title"],
            "description": data["description"],
            "category": data.get("category", "Security Misconfiguration"),
            "source_scanner": data.get("source_scanner", "manual_pentest"),
            "severity": data.get("severity", "medium"),
            "affected_component": data.get("affected_component", "Backend API"),
            "affected_asset_id": data.get("affected_asset_id"),
            "cve_reference": data.get("cve_reference"),
            "cwe_id": data.get("cwe_id"),
            "cvss_score": data.get("cvss_score"),
            "evidence": data.get("evidence", {}),
            "remediation_recommendation": data.get("remediation_recommendation", "Review and apply fix."),
            "remediation_pr_url": data.get("remediation_pr_url"),
            "assigned_to_user_id": data.get("assigned_to_user_id"),
            "assigned_to_name": data.get("assigned_to_name"),
            "status": data.get("status", "open"),
            "first_detected_at": datetime.now(timezone.utc).isoformat(),
            "last_detected_at": datetime.now(timezone.utc).isoformat(),
            "resolved_at": None,
            "verified_at": None,
            "verification_notes": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("security_findings", []).append(item)
        return item

    def update_security_finding(self, org_id: str, finding_id: str, update_data: Dict[str, Any], actor_name: str = "Security Analyst") -> Optional[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        for f in _mock_db.get("security_findings", []):
            if f.get("organization_id") == org_id and f.get("id") == finding_id:
                old_status = f.get("status")
                new_status = update_data.get("status")

                for k, v in update_data.items():
                    if v is not None:
                        f[k] = v

                f["updated_at"] = datetime.now(timezone.utc).isoformat()

                if new_status and new_status != old_status:
                    if new_status in ("fixed", "verified"):
                        f["resolved_at"] = datetime.now(timezone.utc).isoformat()
                    if new_status == "verified":
                        f["verified_at"] = datetime.now(timezone.utc).isoformat()

                    _mock_db.setdefault("security_finding_history", []).append({
                        "id": str(uuid4()),
                        "finding_id": finding_id,
                        "organization_id": org_id,
                        "actor_name": actor_name,
                        "old_status": old_status,
                        "new_status": new_status,
                        "change_summary": f"Status updated from {old_status} to {new_status} by {actor_name}.",
                        "created_at": datetime.now(timezone.utc).isoformat(),
                    })
                return f
        return None

    def add_security_finding_note(self, org_id: str, finding_id: str, author_id: str, author_name: str, content: str) -> Dict[str, Any]:
        self._ensure_sprint19_seeds(org_id)
        note = {
            "id": str(uuid4()),
            "finding_id": finding_id,
            "organization_id": org_id,
            "author_id": author_id,
            "author_name": author_name,
            "content": content,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _mock_db.setdefault("security_finding_notes", []).append(note)
        return note

    def list_security_component_inventory(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        return [c for c in _mock_db.get("security_component_inventory", []) if c.get("organization_id") == org_id]

    def list_security_scan_configurations(self, org_id: str) -> List[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        return [s for s in _mock_db.get("security_scan_configurations", []) if s.get("organization_id") == org_id]

    def update_security_scan_configuration(self, org_id: str, scanner_type: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        self._ensure_sprint19_seeds(org_id)
        for s in _mock_db.get("security_scan_configurations", []):
            if s.get("organization_id") == org_id and s.get("scanner_type") == scanner_type:
                for k, v in data.items():
                    if v is not None:
                        s[k] = v
                s["updated_at"] = datetime.now(timezone.utc).isoformat()
                return s
        return None


supabase_service = SupabaseService()









