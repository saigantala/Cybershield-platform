from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field, HttpUrl

IntegrationCategory = Literal[
    "siem",
    "communication",
    "threat_intelligence",
    "cloud_security",
    "webhooks",
    "auth_sso",
    "monitoring",
]

ConnectionStatus = Literal[
    "Connected",
    "Disconnected",
    "Pending_Configuration",
    "Error",
    "Disabled",
]

IntegrationHealthStatus = Literal["Healthy", "Degraded", "Critical", "Unknown"]

WebhookEventType = Literal[
    "alert.created",
    "incident.created",
    "incident.updated",
    "vulnerability.detected",
    "asset.discovered",
    "compliance.updated",
    "soar.execution_completed",
    "soar.execution_failed",
    "report.generated",
]

# ------------------------------------------------------------------------------
# 1. INTEGRATIONS CATALOG & CONFIG
# ------------------------------------------------------------------------------
class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: str = Field(..., min_length=2, max_length=64)
    category: IntegrationCategory
    provider: str = Field(..., min_length=2, max_length=64)
    description: Optional[str] = None
    config: Dict[str, Any] = {}
    secret_key: Optional[str] = Field(None, description="Optional raw credential token stored server-side only")

class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    secret_key: Optional[str] = None
    is_enabled: Optional[bool] = None
    connection_status: Optional[ConnectionStatus] = None

class IntegrationResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    slug: str
    category: IntegrationCategory
    provider: str
    description: Optional[str] = None
    connection_status: ConnectionStatus
    is_enabled: bool
    health_status: IntegrationHealthStatus
    config: Dict[str, Any]
    secret_configured: bool = False
    secret_masked: Optional[str] = None
    last_synced_at: Optional[str] = None
    error_message: Optional[str] = None
    created_at: str
    updated_at: str

class IntegrationTestRequest(BaseModel):
    custom_endpoint: Optional[str] = None
    test_event_type: Optional[str] = "ping"

class IntegrationTestResponse(BaseModel):
    success: bool
    status: ConnectionStatus
    latency_ms: int
    message: str
    tested_at: str

class IntegrationSyncRequest(BaseModel):
    sync_type: Literal["manual", "scheduled", "real_time"] = "manual"
    dry_run: bool = False

class IntegrationSyncResponse(BaseModel):
    integration_id: str
    status: Literal["Success", "Failed", "Partial"]
    items_synced: int
    duration_ms: int
    synced_at: str
    error_message: Optional[str] = None

# ------------------------------------------------------------------------------
# 2. LOGS & HEALTH METRICS
# ------------------------------------------------------------------------------
class IntegrationDeliveryLogResponse(BaseModel):
    id: str
    integration_id: str
    integration_name: str
    event_type: str
    status: Literal["Delivered", "Failed", "Retrying"]
    http_status_code: Optional[int] = None
    attempt_count: int
    payload_summary: Dict[str, Any]
    error_summary: Optional[str] = None
    duration_ms: int
    delivered_at: str

class IntegrationHealthSummaryResponse(BaseModel):
    total_integrations_count: int
    connected_count: int
    disconnected_count: int
    error_count: int
    healthy_percent: float
    successful_deliveries_24h: int
    failed_deliveries_24h: int
    average_latency_ms: int
    last_sync_timestamp: Optional[str] = None
    category_distribution: Dict[str, int]
    provider_health: List[Dict[str, Any]]

# ------------------------------------------------------------------------------
# 3. WEBHOOKS & DELIVERIES
# ------------------------------------------------------------------------------
class WebhookEndpointCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    url: str = Field(..., min_length=10, max_length=512)
    description: Optional[str] = None
    events: List[WebhookEventType] = ["alert.created", "incident.created"]
    retry_limit: int = Field(3, ge=1, le=10)
    timeout_seconds: int = Field(10, ge=2, le=30)
    is_active: bool = True

class WebhookEndpointUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    events: Optional[List[WebhookEventType]] = None
    retry_limit: Optional[int] = None
    timeout_seconds: Optional[int] = None
    is_active: Optional[bool] = None

class WebhookEndpointResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    url: str
    description: Optional[str] = None
    secret_preview: str  # e.g. "whsec_...9x4b"
    is_active: bool
    events: List[str]
    retry_limit: int
    timeout_seconds: int
    failure_count: int
    last_triggered_at: Optional[str] = None
    created_at: str
    updated_at: str

class WebhookSecretRotateResponse(BaseModel):
    webhook_id: str
    new_secret: str  # Revealed only once upon rotation
    rotated_at: str

class WebhookDeliveryAttemptResponse(BaseModel):
    id: str
    webhook_id: str
    event_type: str
    idempotency_key: str
    payload: Dict[str, Any]
    status: Literal["Delivered", "Failed", "Pending_Retry"]
    http_status_code: Optional[int] = None
    attempt_number: int
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    duration_ms: int
    created_at: str

class WebhookReplayResponse(BaseModel):
    delivery_id: str
    success: bool
    new_status: str
    http_status_code: Optional[int] = None
    message: str
