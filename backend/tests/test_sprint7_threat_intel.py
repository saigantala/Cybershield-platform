import asyncio
import pytest
from uuid import uuid4

from app.threat_intelligence.correlation import correlation_engine
from app.threat_intelligence.feed_manager import feed_manager
from app.threat_intelligence.indicators import IndicatorValidator
from app.threat_intelligence.models import SecurityEventCreate, ThreatIndicatorCreate
from app.threat_intelligence.reputation import reputation_service
from app.services.supabase_service import SupabaseService


# ------------------------------------------------------------------------------
# 1. IOC Validation & Normalization
# ------------------------------------------------------------------------------
def test_ioc_validation_ipv4_ipv6():
    # Valid IPv4 & IPv6
    assert IndicatorValidator.validate_and_normalize("ipv4", "192.0.2.1") == "192.0.2.1"
    assert IndicatorValidator.validate_and_normalize("ipv6", "2001:db8::1") == "2001:db8::1"

    # Invalid IPs
    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("ipv4", "999.999.999.999")
    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("ipv6", "not-an-ipv6-address")


def test_ioc_validation_domains():
    assert IndicatorValidator.validate_and_normalize("domain", "EVIL-C2.CORP.COM") == "evil-c2.corp.com"
    assert IndicatorValidator.validate_and_normalize("domain", "phishing.xyz:8080/") == "phishing.xyz"

    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("domain", "invalid_domain")


def test_ioc_validation_urls():
    url = "https://malicious.example.com/gate.php?id=1"
    assert IndicatorValidator.validate_and_normalize("url", url) == url

    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("url", "ftp://invalid-scheme.com")
    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("url", "not-a-url")


def test_ioc_validation_hashes():
    # MD5 (32 hex)
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    assert IndicatorValidator.validate_and_normalize("md5", md5.upper()) == md5

    # SHA1 (40 hex)
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    assert IndicatorValidator.validate_and_normalize("sha1", sha1.upper()) == sha1

    # SHA256 (64 hex)
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert IndicatorValidator.validate_and_normalize("sha256", sha256.upper()) == sha256

    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("md5", "short-hash")
    with pytest.raises(ValueError):
        IndicatorValidator.validate_and_normalize("sha256", "not-hex-chars-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")


# ------------------------------------------------------------------------------
# 2. Duplicate IOC Prevention & Storage
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_duplicate_ioc_prevention():
    db = SupabaseService()
    org_id = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"

    payload1 = ThreatIndicatorCreate(
        indicator_type="ipv4",
        indicator_value="198.51.100.99",
        source="Manual Ingestion",
        threat_category="c2",
        confidence=80,
    )
    first = await db.create_threat_indicator(org_id, payload1)

    # Ingest same IP with updated confidence
    payload2 = ThreatIndicatorCreate(
        indicator_type="ipv4",
        indicator_value="198.51.100.99",
        source="Second Ingestion",
        confidence=95,
    )
    second = await db.create_threat_indicator(org_id, payload2)

    # Must be same record updated, not duplicate
    assert first["id"] == second["id"]
    assert second["confidence"] == 95


# ------------------------------------------------------------------------------
# 3. Threat Feed Parsing & Provider Timeout
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_threat_feed_sync():
    res = await feed_manager.sync_feed("cisa_kev")
    assert res["status"] == "success"
    assert res["indicators_ingested"] >= 0

    res_urlhaus = await feed_manager.sync_feed("urlhaus")
    assert res_urlhaus["status"] == "success"
    assert res_urlhaus["indicators_ingested"] >= 1


@pytest.mark.asyncio
async def test_feed_timeout_handling():
    with pytest.raises(asyncio.TimeoutError):
        await feed_manager.sync_feed("urlhaus", options={"simulate_timeout": True})


# ------------------------------------------------------------------------------
# 4. Security Event Validation & Ingestion
# ------------------------------------------------------------------------------
def test_event_ingestion_api(client, owner_token):
    payload = {
        "source": "network_discovery",
        "event_type": "port_discovered",
        "severity": "Low",
        "source_ip": "192.168.10.1",
        "event_description": "Observed port 80 open on gateway router.",
        "metadata": {"port": 80},
    }
    response = client.post(
        "/api/v1/security-events",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 201
    data = response.json()
    assert data["event"]["event_type"] == "port_discovered"
    assert data["event"]["source_ip"] == "192.168.10.1"


# ------------------------------------------------------------------------------
# 5. Correlation Engine: Brute Force Anomaly Detection
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_correlation_auth_failure_threshold():
    db = SupabaseService()
    org_id = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"

    attacker_ip = "198.51.100.77"
    rule = {
        "id": "test-rule-brute-force",
        "rule_name": "Brute Force Threshold",
        "severity": "High",
        "rule_type": "auth_failure_threshold",
        "is_enabled": True,
        "threshold": 3,
        "time_window_seconds": 300,
    }

    # Simulate 2 historical failures
    recent_events = [
        {
            "id": str(uuid4()),
            "organization_id": org_id,
            "source": "auth",
            "event_type": "auth_failure",
            "source_ip": attacker_ip,
            "event_timestamp": "2026-10-31T12:00:00Z",
        },
        {
            "id": str(uuid4()),
            "organization_id": org_id,
            "source": "auth",
            "event_type": "auth_failure",
            "source_ip": attacker_ip,
            "event_timestamp": "2026-10-31T12:01:00Z",
        },
    ]

    # 3rd failure event triggers the threshold of 3
    new_event = {
        "id": str(uuid4()),
        "organization_id": org_id,
        "source": "auth",
        "event_type": "auth_failure",
        "source_ip": attacker_ip,
        "event_timestamp": "2026-10-31T12:02:00Z",
    }

    alerts = correlation_engine.evaluate(
        new_event=new_event,
        recent_events=recent_events,
        rules=[rule],
        indicators=[],
        existing_alerts=[],
    )
    assert len(alerts) == 1
    assert "Repeated Authentication Failures" in alerts[0]["title"]
    assert alerts[0]["severity"] == "High"


# ------------------------------------------------------------------------------
# 6. Correlation Engine: Threat Indicator Match
# ------------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_correlation_threat_indicator_match():
    org_id = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"
    malicious_ip = "198.51.100.42"

    rule = {
        "id": "rule-threat-match",
        "rule_name": "Threat Intel Match",
        "severity": "Critical",
        "rule_type": "threat_intel_match",
        "is_enabled": True,
    }

    indicators = [
        {
            "id": "ind-c2-01",
            "indicator_type": "ipv4",
            "indicator_value": malicious_ip,
            "source": "abuse.ch URLhaus",
            "threat_category": "c2",
            "confidence": 95,
            "severity": "Critical",
            "description": "Known Cobalt Strike C2 server",
        }
    ]

    event = {
        "id": str(uuid4()),
        "organization_id": org_id,
        "source": "network_discovery",
        "event_type": "outbound_connection",
        "destination_ip": malicious_ip,
        "event_timestamp": "2026-10-31T12:00:00Z",
    }

    alerts = correlation_engine.evaluate(
        new_event=event,
        recent_events=[],
        rules=[rule],
        indicators=indicators,
        existing_alerts=[],
    )
    assert len(alerts) == 1
    assert "Threat Indicator Match" in alerts[0]["title"]
    assert alerts[0]["indicator_id"] == "ind-c2-01"
    assert alerts[0]["severity"] == "Critical"


# ------------------------------------------------------------------------------
# 7. Alert Management: Status Transitions & Assignment
# ------------------------------------------------------------------------------
def test_alert_lifecycle_and_assignment(client, owner_token):
    alert_id = "14000000-0000-0000-0000-000000000001"

    # 1. Update status to Investigating
    patch_res = client.patch(
        f"/api/v1/alerts/{alert_id}",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"status": "Investigating"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Investigating"

    # 2. Assign to analyst
    analyst_id = "00000000-0000-0000-0000-000000000001"
    assign_res = client.post(
        f"/api/v1/alerts/{alert_id}/assign",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"assigned_to": analyst_id},
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["assigned_to"] == analyst_id

    # 3. Append investigation note
    note_res = client.post(
        f"/api/v1/alerts/{alert_id}/notes",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"note": "Confirmed egress packet to C2 listener. Isolating host interface."},
    )
    assert note_res.status_code == 201
    assert "Isolating host interface" in note_res.json()["note"]

    # 4. Link incident
    incident_id = str(uuid4())
    link_res = client.post(
        f"/api/v1/alerts/{alert_id}/link-incident",
        headers={"Authorization": f"Bearer {owner_token}"},
        json={"incident_id": incident_id},
    )
    assert link_res.status_code == 200
    assert link_res.json()["linked_incident_id"] == incident_id
    assert link_res.json()["status"] == "Escalated"


# ------------------------------------------------------------------------------
# 8. Detection Rules Toggle (Enable / Disable)
# ------------------------------------------------------------------------------
def test_detection_rule_toggle(client, owner_token):
    rule_id = "10000000-0000-0000-0000-000000000001"

    # Disable
    dis_res = client.post(
        f"/api/v1/detection-rules/{rule_id}/disable",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert dis_res.status_code == 200
    assert dis_res.json()["is_enabled"] is False

    # Enable
    en_res = client.post(
        f"/api/v1/detection-rules/{rule_id}/enable",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert en_res.status_code == 200
    assert en_res.json()["is_enabled"] is True


# ------------------------------------------------------------------------------
# 9. Role Permissions & Organization Isolation
# ------------------------------------------------------------------------------
def test_viewer_cannot_modify_intel_or_rules(client, viewer_token):
    # Viewer cannot register indicator
    ind_res = client.post(
        "/api/v1/threat-intelligence/indicators",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"indicator_type": "ipv4", "indicator_value": "198.51.100.1"},
    )
    assert ind_res.status_code == 403

    # Viewer cannot create detection rule
    rule_res = client.post(
        "/api/v1/detection-rules",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={
            "rule_name": "Unauthorized Rule",
            "rule_type": "threat_intel_match",
            "severity": "High",
        },
    )
    assert rule_res.status_code == 403


def test_unauthorized_user_blocked_from_threat_intel(client, unauthorized_user_token):
    res = client.get(
        "/api/v1/threat-intelligence/overview",
        headers={"Authorization": f"Bearer {unauthorized_user_token}"},
    )
    assert res.status_code == 403
