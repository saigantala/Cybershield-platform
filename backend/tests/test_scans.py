def test_create_scan_job(client, owner_token):
    payload = {
        "title": "Subnet Discovery Sweep",
        "type": "network_discovery",
        "profile": "fast_discovery",
        "target_scope": "192.168.10.0/24",
    }
    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    assert response.status_code == 202
    data = response.json()
    assert data["title"] == payload["title"]
    assert data["status"] in ["queued", "completed"]
    assert "id" in data


def test_create_scan_blocked_for_viewer(client, viewer_token):
    payload = {
        "title": "Viewer Unauthorized Scan",
        "type": "network_discovery",
        "profile": "fast_discovery",
        "target_scope": "10.0.0.0/24",
    }
    response = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json=payload,
    )
    assert response.status_code == 403


def test_get_and_cancel_scan(client, owner_token):
    # 1. Create
    payload = {
        "title": "Scan To Cancel",
        "type": "vulnerability_assessment",
        "profile": "comprehensive_audit",
        "target_scope": "192.168.10.0/24",
    }
    create_res = client.post(
        "/api/v1/scans",
        headers={"Authorization": f"Bearer {owner_token}"},
        json=payload,
    )
    scan_id = create_res.json()["id"]

    # 2. Get
    get_res = client.get(
        f"/api/v1/scans/{scan_id}",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert get_res.status_code == 200
    assert get_res.json()["id"] == scan_id

    # 3. Cancel
    cancel_res = client.post(
        f"/api/v1/scans/{scan_id}/cancel",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"
