import pytest
from starlette.testclient import TestClient

from app.main import app
from app.services.ai_threat_service import FeatureExtractor, MLThreatDetectionEngine

client = TestClient(app)

DEFAULT_ORG_ID = "e4a29a43-089c-4f70-a889-cb4c5b36dc32"


@pytest.fixture
def owner_headers(owner_token):
    return {"Authorization": f"Bearer {owner_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


def test_feature_extraction_and_missing_data_imputation():
    # 1. Complete telemetry
    telemetry = {
        "connections_count": 500,
        "bytes_transferred": 1048576,
        "unique_dst_ips": 15,
        "unique_dst_ports": 8,
        "failed_connections": 3,
        "protocol_entropy": 1.4,
        "comm_frequency_hz": 4.5,
        "failed_auth_count": 0,
    }
    vec = FeatureExtractor.extract_vector(telemetry)
    assert len(vec) == 8
    assert vec[0] == 500.0
    assert vec[1] == 1048576.0

    # 2. Missing data imputation
    sparse_telemetry = {"connections_count": None, "bytes_transferred": None}
    vec_sparse = FeatureExtractor.extract_vector(sparse_telemetry)
    assert len(vec_sparse) == 8
    assert vec_sparse[0] == 0.0
    assert vec_sparse[1] == 0.0
    assert all(not (x != x) for x in vec_sparse)  # No NaNs


def test_ml_isolation_forest_anomaly_detection():
    engine = MLThreatDetectionEngine()

    # Normal baseline vector
    normal_vec = [120.0, 450000.0, 12.0, 5.0, 2.0, 1.2, 2.0, 0.0]
    is_anom, anom_score, conf = engine.predict_anomaly(normal_vec)
    assert isinstance(is_anom, bool)
    assert 0.0 <= anom_score <= 1.0
    assert 0.0 <= conf <= 1.0

    # Massive exfiltration spike outlier
    outlier_vec = [15000.0, 500000000.0, 450.0, 250.0, 80.0, 3.8, 45.0, 12.0]
    outlier_anom, outlier_score, outlier_conf = engine.predict_anomaly(outlier_vec)
    assert outlier_anom is True
    assert outlier_score > 0.60
    assert outlier_conf >= 0.70


def test_list_models_and_versions(owner_headers):
    res = client.get(f"/api/v1/ai-detection/models?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    models = res.json()
    assert len(models) >= 3
    types = [m["model_type"] for m in models]
    assert "isolation_forest" in types
    assert "statistical_baseline" in types
    assert "rule_engine" in types

    # Check model versions
    first_model = models[0]
    v_res = client.get(
        f"/api/v1/ai-detection/models/{first_model['id']}/versions?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert v_res.status_code == 200
    versions = v_res.json()
    assert len(versions) >= 1
    assert "precision" in versions[0]["evaluation_metrics"]


def test_register_new_model(owner_headers):
    payload = {
        "model_name": "K8s-Pod-Egress-Autoencoder",
        "model_type": "deep_autoencoder",
        "description": "Reconstruction error anomaly detector for Kubernetes ingress/egress",
        "version": "1.0.0",
        "hyperparameters": {"latent_dim": 4, "learning_rate": 0.001},
        "is_production_ready": False,  # Correctly labeled as experimental/evaluation
    }
    res = client.post(
        f"/api/v1/ai-detection/models?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=payload,
    )
    assert res.status_code == 201
    created = res.json()
    assert created["model_name"] == payload["model_name"]
    assert created["is_production_ready"] is False
    assert "evaluation_metrics" in created


def test_list_and_manage_detection_rules(owner_headers):
    # 1. List rules
    list_res = client.get(f"/api/v1/ai-detection/rules?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert list_res.status_code == 200
    rules = list_res.json()
    assert len(rules) >= 4

    # 2. Create rule
    new_rule = {
        "rule_name": "Zero-Day Lateral Movement SMB Spike",
        "rule_type": "behavioral_deviation",
        "description": "Flags internal SMB share access spikes exceeding threshold",
        "severity": "Critical",
        "data_sources": ["network_monitoring"],
        "threshold_config": {"smb_requests_per_min": 100},
        "evaluation_interval_seconds": 120,
        "is_enabled": True,
    }
    create_res = client.post(
        f"/api/v1/ai-detection/rules?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=new_rule,
    )
    assert create_res.status_code == 201
    rule_id = create_res.json()["id"]

    # 3. Update rule
    patch_res = client.patch(
        f"/api/v1/ai-detection/rules/{rule_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={"severity": "High", "is_enabled": False},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["severity"] == "High"
    assert patch_res.json()["is_enabled"] is False


def test_analyze_security_telemetry_inference(owner_headers):
    req_payload = {
        "asset_id": "00000000-0000-0000-0000-000000000001",
        "telemetry_window_minutes": 15,
        "synthetic_telemetry": {
            "connections_count": 1200.0,
            "bytes_transferred": 25000000.0,  # 25MB burst
            "unique_dst_ips": 65.0,
            "unique_dst_ports": 22.0,
            "failed_connections": 34.0,
            "protocol_entropy": 2.85,
            "comm_frequency_hz": 18.0,
            "failed_auth_count": 0.0,
        },
    }
    res = client.post(
        f"/api/v1/ai-detection/analyze?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=req_payload,
    )
    assert res.status_code == 201
    detection = res.json()
    assert detection["detection_category"] == "suspicious_outbound"
    assert detection["severity"] in ("Critical", "High")
    assert detection["confidence_score"] > 0.70
    assert detection["anomaly_score"] > 0.60
    assert "features_analyzed" in detection["supporting_evidence"]
    assert "recommended_investigation" in detection


def test_list_and_get_detection_results(owner_headers):
    res = client.get(f"/api/v1/ai-detection/results?org_id={DEFAULT_ORG_ID}", headers=owner_headers)
    assert res.status_code == 200
    results = res.json()
    assert len(results) >= 4

    first_det = results[0]
    detail_res = client.get(
        f"/api/v1/ai-detection/results/{first_det['id']}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == first_det["id"]


def test_investigation_workflow_and_analyst_feedback(owner_headers):
    # Fetch first detection
    results = client.get(f"/api/v1/ai-detection/results?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    target_det_id = results[0]["id"]

    # 1. Open investigation
    inv_payload = {
        "detection_id": target_det_id,
        "analyst_notes": "Triage started. Reviewing NetFlow pcap.",
        "status": "Reviewing",
    }
    inv_res = client.post(
        f"/api/v1/ai-detection/investigations?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=inv_payload,
    )
    assert inv_res.status_code == 201
    inv_id = inv_res.json()["id"]

    # 2. Update investigation to Confirmed Suspicious
    patch_res = client.patch(
        f"/api/v1/ai-detection/investigations/{inv_id}?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json={
            "status": "Confirmed Suspicious",
            "analyst_notes": "Confirmed reverse shell socket connection.",
            "findings_summary": "Malicious payload executed via exploited web server.",
        },
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "Confirmed Suspicious"
    assert patch_res.json()["confirmed_at"] is not None

    # 3. Submit analyst feedback
    fb_payload = {
        "detection_id": target_det_id,
        "verdict": "true_positive",
        "notes": "Verified C2 beaconing pattern accurately flagged by Isolation Forest.",
    }
    fb_res = client.post(
        f"/api/v1/ai-detection/feedback?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=fb_payload,
    )
    assert fb_res.status_code == 201
    assert fb_res.json()["verdict"] == "true_positive"


def test_risk_predictions_and_threat_analytics(owner_headers):
    # 1. Predictive Risk
    risk_res = client.get(
        f"/api/v1/ai-detection/risk-predictions?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert risk_res.status_code == 200
    predictions = risk_res.json()
    assert len(predictions) >= 3
    assert "risk_score" in predictions[0]
    assert predictions[0]["risk_level"] in ("Critical", "High", "Medium", "Low")
    assert "contributing_factors" in predictions[0]

    # 2. AI Threat Analytics
    analytics_res = client.get(
        f"/api/v1/ai-detection/analytics?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
    )
    assert analytics_res.status_code == 200
    data = analytics_res.json()
    assert "total_detections_count" in data
    assert "false_positive_rate_percent" in data
    assert "model_health_overview" in data
    assert len(data["daily_anomaly_volume"]) > 0


def test_ai_threat_investigation_assistant(owner_headers):
    # Query assistant regarding flagged evidence
    results = client.get(f"/api/v1/ai-detection/results?org_id={DEFAULT_ORG_ID}", headers=owner_headers).json()
    det_id = results[0]["id"]

    query_payload = {
        "query": "Why was this event flagged and what evidence supports this alert?",
        "detection_id": det_id,
    }
    chat_res = client.post(
        f"/api/v1/ai-detection/investigation-assistant/chat?org_id={DEFAULT_ORG_ID}",
        headers=owner_headers,
        json=query_payload,
    )
    assert chat_res.status_code == 200
    resp = chat_res.json()
    assert "Isolation Forest" in resp["answer"] or "Detection Evidence" in resp["answer"]
    assert len(resp["evidence_citations"]) >= 1
    assert len(resp["recommended_next_steps"]) >= 1
    assert "confidence_and_uncertainty" in resp


def test_viewer_rbac_restrictions(viewer_headers):
    # Viewer cannot register models
    res = client.post(
        f"/api/v1/ai-detection/models?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={"model_name": "Unauthorized-Model", "model_type": "deep_cnn"},
    )
    assert res.status_code == 403

    # Viewer cannot create rules
    rule_res = client.post(
        f"/api/v1/ai-detection/rules?org_id={DEFAULT_ORG_ID}",
        headers=viewer_headers,
        json={"rule_name": "Unauthorized-Rule", "rule_type": "statistical_threshold"},
    )
    assert rule_res.status_code == 403
