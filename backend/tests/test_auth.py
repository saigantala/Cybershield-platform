def test_auth_missing_token(client):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    assert "Authorization header required" in response.json()["detail"]


def test_auth_invalid_token(client):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.token.payload"},
    )
    assert response.status_code == 401


def test_auth_expired_token(client, expired_token):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert response.status_code == 401
    assert "expired" in response.json()["detail"].lower()


def test_auth_valid_token(client, owner_token):
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {owner_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "owner@cybershield.internal"
    assert data["id"] == "00000000-0000-0000-0000-000000000001"
    assert "organizations" in data
