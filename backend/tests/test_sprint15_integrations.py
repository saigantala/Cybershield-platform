import time
import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.integrations_service import SSRFProtectionGuard, WebhookHMACSigner

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


def test_ssrf_protection_guard():
    # 1. Reject localhost / 127.0.0.1
    with pytest.raises(ValueError, match="SSRF Protection"):
        SSRFProtectionGuard.validate_url("http://127.0.0.1:8080/admin")

    with pytest.raises(ValueError, match="SSRF Protection"):
        SSRFProtectionGuard.validate_url("http://localhost:3000/internal")

    # 2. Reject cloud metadata 169.254.169.254
    with pytest.raises(ValueError, match="SSRF Protection"):
        SSRFProtectionGuard.validate_url("http://169.254.169.254/latest/meta-data/")

    # 3. Reject private RFC 1918 subnets
    with pytest.raises(ValueError, match="SSRF Protection"):
        SSRFProtectionGuard.validate_url("https://10.200.1.5/hec")

    with pytest.raises(ValueError, match="SSRF Protection"):
        SSRFProtectionGuard.validate_url("https://192.168.1.100:9200")

    # 4. Allow legitimate public endpoints
    SSRFProtectionGuard.validate_url("https://hooks.slack.com/services/T00/B00/X00")
    SSRFProtectionGuard.validate_url("https://splunk-hec.corp.acme-security.com:8088/services/collector")


def test_webhook_hmac_signing_and_verification():
    secret = "whsec_test_secret_key_1234567890"
    payload = b'{"event":"alert.created","alert_id":"ALT-2026-001"}'
    now = int(time.time())

    # Generate valid signature
    sig = WebhookHMACSigner.sign_payload(secret, now, payload)
    assert sig.startswith("v1=")

    # Verify valid signature
    assert WebhookHMACSigner.verify_signature(secret, now, payload, sig) is True

    # Tampered payload rejected
    assert WebhookHMACSigner.verify_signature(secret, now, b'{"tampered":true}', sig) is False

    # Stale/replayed timestamp rejected (>300s skew)
    stale_time = now - 600
    stale_sig = WebhookHMACSigner.sign_payload(secret, stale_time, payload)
    assert WebhookHMACSigner.verify_signature(secret, stale_time, payload, stale_sig, tolerance_seconds=300) is False


def test_list_integrations(owner_headers):
    res = client.get(f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    integrations = res.json()
    assert len(integrations) >= 6
    names = [i["name"] for i in integrations]
    assert "Splunk Enterprise SIEM" in names
    assert "Slack Incident Operations" in names
    assert "CISA Known Exploited Vulnerabilities" in names
    # Verify raw secret is never returned
    for item in integrations:
        assert "encrypted_secret" not in item
        assert "secret_key" not in item


def test_create_and_update_integration(owner_headers):
    # 1. Create integration with credential
    payload = {
        "name": "Elastic Security SIEM",
        "slug": "elastic_security",
        "category": "siem",
        "provider": "Elastic",
        "description": "ECS security event shipper to Elasticsearch cluster",
        "config": {"endpoint_url": "https://elastic-cloud.external.io:9243", "index": "cybershield-ecs"},
        "secret_key": "apiKey_99482819102938472910",
    }
    create_res = client.post(
        f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["name"] == payload["name"]
    assert created["connection_status"] == "Connected"
    assert created["secret_configured"] is True
    assert created["secret_masked"] is not None
    int_id = created["id"]

    # 2. Update config
    patch_res = client.patch(
        f"/api/v1/integrations/{int_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"description": "Updated ECS forwarder description", "is_enabled": False},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["description"] == "Updated ECS forwarder description"
    assert patch_res.json()["is_enabled"] is False


def test_create_integration_rejects_ssrf(owner_headers):
    payload = {
        "name": "Malicious SSRF Probe",
        "slug": "ssrf_probe",
        "category": "siem",
        "provider": "Splunk",
        "config": {"endpoint_url": "http://169.254.169.254/latest/meta-data/"},
    }
    res = client.post(
        f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert res.status_code == 400
    assert "SSRF Protection" in res.json()["detail"]


def test_test_connection_and_sync(owner_headers):
    items = client.get(f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    splunk = next(i for i in items if i["slug"] == "splunk")

    # 1. Test probe
    test_res = client.post(
        f"/api/v1/integrations/{splunk['id']}/test?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"test_event_type": "connectivity_probe"},
    )
    assert test_res.status_code == 200
    test_data = test_res.json()
    assert test_data["success"] is True
    assert test_data["status"] == "Connected"
    assert test_data["latency_ms"] > 0

    # 2. Sync run
    sync_res = client.post(
        f"/api/v1/integrations/{splunk['id']}/sync?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"sync_type": "manual"},
    )
    assert sync_res.status_code == 200
    sync_data = sync_res.json()
    assert sync_data["status"] == "Success"
    assert sync_data["items_synced"] > 0


def test_webhook_crud_and_secret_rotation(owner_headers):
    # 1. Create Webhook
    wh_payload = {
        "name": "PagerDuty Escalation Webhook",
        "url": "https://events.pagerduty.com/v2/enqueue",
        "description": "Pushes critical incident triggers to on-call schedules",
        "events": ["alert.created", "incident.created"],
        "retry_limit": 3,
        "timeout_seconds": 10,
    }
    create_res = client.post(
        f"/api/v1/integrations/webhooks?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=wh_payload,
    )
    assert create_res.status_code == 201
    wh = create_res.json()
    assert wh["name"] == wh_payload["name"]
    assert wh["secret_preview"].startswith("whsec_")
    wh_id = wh["id"]

    # 2. Rotate Secret
    rot_res = client.post(
        f"/api/v1/integrations/webhooks/{wh_id}/rotate-secret?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert rot_res.status_code == 200
    rot_data = rot_res.json()
    assert rot_data["new_secret"].startswith("whsec_")
    assert rot_data["webhook_id"] == wh_id


def test_webhook_deliveries_and_replay(owner_headers):
    hooks = client.get(f"/api/v1/integrations/webhooks?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    hook = next(h for h in hooks if h.get("id") == "a0000001-0000-0000-0000-000000000001" or "Corporate SIEM" in h.get("name", ""))
    hook_id = hook["id"]

    # 1. List deliveries
    list_res = client.get(
        f"/api/v1/integrations/webhooks/{hook_id}/deliveries?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert list_res.status_code == 200
    deliveries = list_res.json()
    assert len(deliveries) >= 1
    del_id = deliveries[0]["id"]

    # 2. Replay delivery
    replay_res = client.post(
        f"/api/v1/integrations/webhooks/{hook_id}/deliveries/{del_id}/replay?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert replay_res.status_code == 200
    assert replay_res.json()["success"] is True
    assert replay_res.json()["new_status"] == "Delivered"


def test_integration_logs_and_health_summary(owner_headers):
    # 1. Logs
    logs_res = client.get(f"/api/v1/integrations/logs?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert logs_res.status_code == 200
    logs = logs_res.json()
    assert len(logs) >= 3
    assert logs[0]["status"] == "Delivered"
    assert "payload_summary" in logs[0]

    # 2. Health
    health_res = client.get(f"/api/v1/integrations/health?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert health_res.status_code == 200
    health = health_res.json()
    assert "total_integrations_count" in health
    assert "connected_count" in health
    assert "healthy_percent" in health
    assert "provider_health" in health
    assert len(health["provider_health"]) > 0


def test_delete_integration(owner_headers):
    # Create temp integration to delete
    payload = {
        "name": "Temp Disconnectable Integration",
        "slug": "temp_disc",
        "category": "communication",
        "provider": "Slack",
        "config": {"channel": "#temp"},
    }
    create_res = client.post(
        f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    int_id = create_res.json()["id"]

    del_res = client.delete(
        f"/api/v1/integrations/{int_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert del_res.status_code == 204

    # Verify 404
    get_res = client.get(
        f"/api/v1/integrations/{int_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert get_res.status_code == 404


def test_viewer_rbac_restrictions(viewer_headers):
    # Viewer cannot create integrations
    res = client.post(
        f"/api/v1/integrations?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={"name": "Viewer-Unauthorized", "slug": "bad", "category": "siem", "provider": "Splunk"},
    )
    assert res.status_code == 403

    # Viewer cannot rotate webhook secret
    hooks = client.get(f"/api/v1/integrations/webhooks?org_id={DEFAULT_ORG_ID}", headers=viewer_headers).json()
    hook_id = hooks[0]["id"]
    rot_res = client.post(
        f"/api/v1/integrations/webhooks/{hook_id}/rotate-secret?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
    )
    assert rot_res.status_code == 403
