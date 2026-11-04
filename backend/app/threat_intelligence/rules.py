from typing import Any, Dict, List

DEFAULT_DETECTION_RULES: List[Dict[str, Any]] = [
    {
        "id": "10000000-0000-0000-0000-000000000001",
        "rule_name": "Repeated Authentication Failure Anomaly (Brute-Force Detection)",
        "description": "Detects multiple failed login or credential validation attempts within a short time window.",
        "severity": "High",
        "rule_type": "auth_failure_threshold",
        "is_enabled": True,
        "threshold": 5,
        "time_window_seconds": 300,
        "event_conditions": {
            "event_type": "auth_failure",
            "group_by": "source_ip",
        },
    },
    {
        "id": "10000000-0000-0000-0000-000000000002",
        "rule_name": "Known Threat Indicator Correlation Match",
        "description": "Detects network connection or telemetry matching active Threat Intelligence IOCs (malicious IP, domain, URL, or hash).",
        "severity": "Critical",
        "rule_type": "threat_intel_match",
        "is_enabled": True,
        "threshold": 1,
        "time_window_seconds": 60,
        "event_conditions": {
            "check_fields": ["source_ip", "destination_ip", "hostname"],
        },
    },
    {
        "id": "10000000-0000-0000-0000-000000000003",
        "rule_name": "Vulnerability Risk & CISA KEV Exposure Correlation",
        "description": "Correlates critical unmitigated vulnerability discoveries listed in CISA KEV on network assets.",
        "severity": "High",
        "rule_type": "vuln_risk_correlation",
        "is_enabled": True,
        "threshold": 1,
        "time_window_seconds": 3600,
        "event_conditions": {
            "min_cvss": 7.0,
            "require_kev": True,
        },
    },
    {
        "id": "10000000-0000-0000-0000-000000000004",
        "rule_name": "Asset Telemetry Volume Spike Anomaly",
        "description": "Identifies statistically abnormal bursts of security events from a single host indicating scanning or denial of service.",
        "severity": "Medium",
        "rule_type": "asset_anomaly",
        "is_enabled": True,
        "threshold": 20,
        "time_window_seconds": 60,
        "event_conditions": {
            "group_by": "asset_id",
        },
    },
    {
        "id": "10000000-0000-0000-0000-000000000005",
        "rule_name": "Repeated Suspicious Network Activity",
        "description": "Triggers when suspicious port sweeps or non-baseline discovery signals recur from a single source.",
        "severity": "High",
        "rule_type": "repeated_suspicious_events",
        "is_enabled": True,
        "threshold": 3,
        "time_window_seconds": 600,
        "event_conditions": {
            "event_type": "suspicious_traffic",
        },
    },
]
