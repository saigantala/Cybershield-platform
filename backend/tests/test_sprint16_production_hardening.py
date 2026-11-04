import pytest
from starlette.testclient import TestClient

from app.main import app
from app.core.config import Settings
from app.core.middleware import SensitiveDataRedactor

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


def test_security_response_headers():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    headers = res.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in headers.get("Content-Security-Policy", "")
    assert "camera=()" in headers.get("Permissions-Policy", "")


def test_request_correlation_id_generation():
    res = client.get("/api/v1/health")
    assert res.status_code == 200

    corr_id = res.headers.get("X-Correlation-ID")
    req_id = res.headers.get("X-Request-ID")
    assert corr_id is not None
    assert req_id is not None
    assert corr_id.startswith("req_")
    assert "X-Response-Time-Ms" in res.headers


def test_custom_correlation_id_propagation():
    custom_trace = "trace-corp-soc-998877"
    res = client.get("/api/v1/health", headers={"X-Correlation-ID": custom_trace})
    assert res.status_code == 200
    assert res.headers.get("X-Correlation-ID") == custom_trace
    assert res.headers.get("X-Request-ID") == custom_trace


def test_sensitive_data_redactor():
    payload = {
        "user_id": "usr-1234",
        "username": "soc_analyst",
        "password": "SuperSecretPassword123!",
        "api_key": "sec_live_998877665544",
        "config": {
            "token": "tok_xyz999",
            "hec_token": "hec_123456",
            "endpoint": "https://splunk.corp.net",
        },
        "nested_list": [
            {"secret": "sensitive_value_1", "name": "hook1"},
            {"public_info": "safe_value"},
        ],
    }

    sanitized = SensitiveDataRedactor.redact_dict(payload)

    assert sanitized["user_id"] == "usr-1234"
    assert sanitized["username"] == "soc_analyst"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["config"]["token"] == "[REDACTED]"
    assert sanitized["config"]["hec_token"] == "[REDACTED]"
    assert sanitized["config"]["endpoint"] == "https://splunk.corp.net"
    assert sanitized["nested_list"][0]["secret"] == "[REDACTED]"
    assert sanitized["nested_list"][1]["public_info"] == "safe_value"


def test_production_configuration_validation():
    # 1. Dev settings should produce 0 critical errors
    dev_settings = Settings(ENVIRONMENT="development", DEBUG=True)
    dev_issues = dev_settings.validate_production_configuration()
    assert len(dev_issues) == 0

    # 2. Prod settings with placeholders must trigger critical warnings
    prod_bad_settings = Settings(
        ENVIRONMENT="production",
        DEBUG=True,
        SECRET_KEY="cybershield-dev-secret-key-change-in-production-min-32-chars",
        SUPABASE_URL="https://your-project.supabase.co",
        SUPABASE_ANON_KEY="your-anon-key",
    )
    prod_issues = prod_bad_settings.validate_production_configuration()
    assert any("DEBUG=True" in i for i in prod_issues)
    assert any("SECRET_KEY" in i for i in prod_issues)
    assert any("SUPABASE_URL" in i for i in prod_issues)


def test_system_health_endpoint():
    res = client.get("/api/v1/system-health")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] in ("Healthy", "Degraded")
    assert "version" in data
    assert "subsystems" in data
    assert len(data["subsystems"]) >= 5

    subsystem_names = [s["name"] for s in data["subsystems"]]
    assert "PostgreSQL Database" in subsystem_names
    assert "Redis In-Memory Broker" in subsystem_names
    assert "Celery Asynchronous Workers" in subsystem_names

    # Check resource metrics
    assert "resources" in data
    res_metrics = data["resources"]
    assert "cpu_percent" in res_metrics
    assert "memory_percent" in res_metrics
    assert "process_uptime_seconds" in res_metrics


def test_production_readiness_checklist(owner_headers):
    res = client.get("/api/v1/system-health/production-readiness", headers=owner_headers)
    assert res.status_code == 200
    data = res.json()

    assert "readiness_score" in data
    assert data["total_checks"] == 12
    assert "checklist" in data

    statuses = {c["status"] for c in data["checklist"]}
    assert "Passed" in statuses

    # Verify key audited domains
    titles = [c["title"] for c in data["checklist"]]
    assert any("Entropy" in t for t in titles)
    assert any("Row Level Security" in t for t in titles)
    assert any("SSRF Protection" in t for t in titles)
    assert any("HTTP Security" in t for t in titles)
    assert any("Rate Limiting" in t for t in titles)


def test_system_health_ping():
    res = client.post("/api/v1/system-health/ping")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "pong"
    assert "latency_ms" in data
    assert data["latency_ms"] >= 0


def test_rate_limiter_headers():
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    # Health endpoint is exempt from rate limit counters, root endpoint or API endpoint will have them
    api_res = client.get("/api/v1/system-health/ping")
    assert api_res.status_code == 200
    assert "X-RateLimit-Limit" in api_res.headers
    assert "X-RateLimit-Remaining" in api_res.headers


def test_request_size_limiter_exceeded():
    # Attempting to declare Content-Length larger than 25MB (26214400 bytes)
    oversized = 30000000
    res = client.post(
        "/api/v1/system-health/ping",
        headers={"Content-Length": str(oversized)},
    )
    assert res.status_code == 413
    assert "Payload Too Large" in res.json()["error"]
