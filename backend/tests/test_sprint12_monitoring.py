import pytest
from starlette.testclient import TestClient

from app.main import app

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


def test_monitoring_status_endpoint(owner_headers):
    response = client.get(f"/api/v1/monitoring/status?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["worker_status"] in ("running", "idle", "degraded")
    assert "active_agents_count" in data
    assert "network_health_status" in data
    assert data["network_health_status"] in ("Healthy", "Degraded", "Critical")
    assert "current_traffic_bps" in data
    assert "active_anomalies_count" in data


def test_agent_registration_and_one_time_key(owner_headers):
    payload = {
        "hostname": "k8s-node-worker-09.internal",
        "ip_address": "192.168.10.199",
        "mac_address": "AA:BB:CC:DD:EE:FF",
        "os_type": "Linux Alpine 3.19",
        "agent_name": "K8s-Telemetry-Probe",
        "agent_version": "1.3.0",
        "config": {"reporting_interval_seconds": 15},
    }
    response = client.post(
        f"/api/v1/monitoring/agents/register?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert response.status_code == 201
    agent = response.json()
    assert agent["hostname"] == "k8s-node-worker-09.internal"
    assert agent["status"] == "Active"
    assert agent["api_key"] is not None
    assert agent["api_key"].startswith("cs_mon_")

    # Verify agent list does NOT expose the raw secret key
    list_res = client.get(f"/api/v1/monitoring/agents?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    agents = list_res.json()
    target = next((a for a in agents if a["id"] == agent["id"]), None)
    assert target is not None
    assert target["api_key"] is None
    assert target["api_key_prefix"] is not None


def test_telemetry_ingestion_with_agent_key_auth(owner_headers):
    # 1. Register an agent to get a valid key
    reg_res = client.post(
        f"/api/v1/monitoring/agents/register?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "hostname": "telemetry-agent-test.internal",
            "ip_address": "192.168.10.240",
            "os_type": "Linux Ubuntu 24.04",
        },
    )
    assert reg_res.status_code == 201
    agent = reg_res.json()
    agent_id = agent["id"]
    api_key = agent["api_key"]

    # 2. Submit telemetry using X-Agent-Key header
    telemetry_payload = {
        "agent_id": agent_id,
        "network_flows": [
            {
                "interface": "eth0",
                "source_ip": "192.168.10.240",
                "destination_ip": "1.1.1.1",
                "protocol": "DNS",
                "source_port": 51234,
                "destination_port": 53,
                "packet_count": 10,
                "byte_count": 840,
                "direction": "Outbound",
            },
            {
                "interface": "eth0",
                "source_ip": "10.0.1.5",
                "destination_ip": "192.168.10.240",
                "protocol": "HTTPS",
                "source_port": 443,
                "destination_port": 59123,
                "packet_count": 55,
                "byte_count": 48200,
                "direction": "Inbound",
            },
        ],
        "host_metrics": {
            "cpu_utilization_pct": 42.0,
            "memory_utilization_pct": 65.5,
            "disk_utilization_pct": 38.0,
            "network_interface_status": "Up",
        },
    }

    ingest_res = client.post(
        "/api/v1/monitoring/telemetry",
        headers={"X-Agent-Key": api_key},
        json=telemetry_payload,
    )
    assert ingest_res.status_code == 200
    res_data = ingest_res.json()
    assert res_data["status"] == "success"
    assert res_data["flows_ingested"] == 2
    assert res_data["host_health_state"] == "Healthy"


def test_telemetry_ingestion_unauthorized_rejection():
    # Submit telemetry with a bogus agent key
    telemetry_payload = {
        "agent_id": "00000000-0000-0000-0000-000000000099",
        "network_flows": [],
    }
    response = client.post(
        "/api/v1/monitoring/telemetry",
        headers={"X-Agent-Key": "cs_mon_invalid_secret_key_12345"},
        json=telemetry_payload,
    )
    assert response.status_code == 401
    assert "Invalid or revoked" in response.json()["detail"]


def test_device_health_states_and_no_fake_metrics(owner_headers):
    response = client.get(f"/api/v1/monitoring/device-health?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert response.status_code == 200
    devices = response.json()
    assert len(devices) > 0

    monitored = [d for d in devices if d["is_agent_monitored"]]
    unmonitored = [d for d in devices if not d["is_agent_monitored"]]

    assert len(monitored) >= 1
    # Monitored devices have real metrics
    assert monitored[0]["cpu_pct"] is not None
    assert monitored[0]["memory_pct"] is not None
    assert monitored[0]["agent_status"] == "Active"

    # Unmonitored devices do NOT have faked CPU/memory metrics
    if unmonitored:
        assert unmonitored[0]["cpu_pct"] is None
        assert unmonitored[0]["memory_pct"] is None
        assert unmonitored[0]["agent_status"] == "Not Installed"
        assert unmonitored[0]["health_state"] == "Unknown"


def test_network_traffic_analytics_and_protocols(owner_headers):
    # Traffic summary
    traf_res = client.get(f"/api/v1/network/traffic?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert traf_res.status_code == 200
    traf_data = traf_res.json()
    assert traf_data["total_bytes"] > 0
    assert traf_data["total_packets"] > 0
    assert len(traf_data["top_talkers"]) > 0
    assert len(traf_data["top_destination_ports"]) > 0
    assert len(traf_data["traffic_trend"]) > 0

    # Protocols endpoint
    proto_res = client.get(f"/api/v1/network/protocols?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert proto_res.status_code == 200
    protos = proto_res.json()
    assert any(p["protocol"] in ("HTTPS", "TCP", "DNS") for p in protos)

    # Top talkers endpoint
    talkers_res = client.get(f"/api/v1/network/top-talkers?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert talkers_res.status_code == 200
    assert len(talkers_res.json()) > 0


def test_rule_based_anomaly_detection_trigger(owner_headers):
    # Register an agent
    reg = client.post(
        f"/api/v1/monitoring/agents/register?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"hostname": "anomaly-test-box.internal", "ip_address": "192.168.10.88", "os_type": "Linux"},
    ).json()

    # Submit a flow to suspicious Metasploit port 4444
    client.post(
        "/api/v1/monitoring/telemetry",
        headers={"X-Agent-Key": reg["api_key"]},
        json={
            "agent_id": reg["id"],
            "network_flows": [
                {
                    "interface": "eth0",
                    "source_ip": "198.51.100.99",
                    "destination_ip": "192.168.10.88",
                    "protocol": "TCP",
                    "source_port": 50123,
                    "destination_port": 4444,
                    "packet_count": 8,
                    "byte_count": 1024,
                    "direction": "Inbound",
                }
            ],
        },
    )

    # Verify anomaly created
    anom_res = client.get(f"/api/v1/network/anomalies?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert anom_res.status_code == 200
    anomalies = anom_res.json()
    assert len(anomalies) > 0
    high_port_anom = next((a for a in anomalies if a["event_category"] == "unexpected_port"), None)
    assert high_port_anom is not None
    assert high_port_anom["severity"] in ("Critical", "High")
    assert high_port_anom["confidence"] >= 80
    assert "recommended_investigation" in high_port_anom


def test_monitoring_rules_crud_and_rbac(owner_headers, viewer_headers):
    # List rules as viewer (allowed read-only)
    list_res = client.get(f"/api/v1/monitoring/rules?org_id={DEFAULT_ORG_ID}", headers=viewer_headers)
    assert list_res.status_code == 200
    rules = list_res.json()
    assert len(rules) >= 3

    # Viewer cannot create rules (403 Forbidden)
    create_fail = client.post(
        f"/api/v1/monitoring/rules?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={
            "rule_name": "Viewer Unauthorized Rule",
            "rule_type": "traffic_spike",
            "threshold": 1000000,
        },
    )
    assert create_fail.status_code == 403

    # Owner can create rules
    create_ok = client.post(
        f"/api/v1/monitoring/rules?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "rule_name": "Custom SSH Brute Force Ingress",
            "rule_type": "unexpected_port",
            "threshold": 5,
            "severity": "Medium",
            "time_window_seconds": 60,
        },
    )
    assert create_ok.status_code == 201
    new_rule = create_ok.json()
    assert new_rule["rule_name"] == "Custom SSH Brute Force Ingress"

    # Owner can update rules
    patch_ok = client.patch(
        f"/api/v1/monitoring/rules/{new_rule['id']}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"threshold": 10, "is_enabled": False},
    )
    assert patch_ok.status_code == 200
    assert patch_ok.json()["threshold"] == 10
    assert patch_ok.json()["is_enabled"] is False
