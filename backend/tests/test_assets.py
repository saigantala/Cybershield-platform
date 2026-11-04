def test_list_assets(client, owner_token):
    response = client.get(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["total"] >= 1
    assert data["page"] == 1


def test_asset_validation_invalid_ip(client, owner_token):
    payload = {
        "name": "TEST-INVALID-IP",
        "ip_address": "999.1.1.1",
        "device_type": "Server",
        "risk_level": "Low",
        "status": "Active",
    }
    response = client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 422
    err_json = response.json()
    assert "validation_errors" in err_json


def test_asset_validation_invalid_mac(client, owner_token):
    payload = {
        "name": "TEST-INVALID-MAC",
        "ip_address": "192.168.1.50",
        "mac_address": "invalid-mac-string",
        "device_type": "Laptop",
        "risk_level": "Low",
        "status": "Active",
    }
    response = client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 422


def test_create_asset_as_owner(client, owner_token):
    payload = {
        "name": "TEST-SERVER-APEX-01",
        "ip_address": "10.0.50.15",
        "mac_address": "00:11:22:33:44:55",
        "hostname": "test-srv.nexus.internal",
        "device_type": "Server",
        "operating_system": "Debian 12 Bookworm",
        "manufacturer": "Supermicro",
        "risk_level": "Medium",
        "status": "Active",
        "description": "Integration test endpoint",
    }
    response = client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 201
    created = response.json()
    assert created["name"] == payload["name"]
    assert created["ip_address"] == payload["ip_address"]
    assert created["device_type"] == payload["device_type"]


def test_create_asset_blocked_for_viewer(client, viewer_token):
    payload = {
        "name": "VIEWER-SHOULD-FAIL",
        "ip_address": "10.0.99.99",
        "device_type": "Server",
        "risk_level": "Low",
        "status": "Active",
    }
    response = client.post(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json=payload,
    )
    assert response.status_code == 403
    assert "Access denied" in response.json()["detail"]


def test_update_asset(client, owner_token):
    # Fetch existing asset
    list_res = client.get(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    asset_id = list_res.json()["items"][0]["id"]

    update_payload = {"risk_level": "High", "description": "Elevated during triage"}
    response = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=update_payload,
    )
    assert response.status_code == 200
    assert response.json()["risk_level"] == "High"


def test_unauthorized_user_blocked(client, unauthorized_user_token):
    response = client.get(
        "/api/v1/assets",
        headers={"Authorization": f"Bearer {unauthorized_user_token}"},
    )
    assert response.status_code == 403
