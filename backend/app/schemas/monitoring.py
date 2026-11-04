from typing import Optional, List, Dict, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime

class AgentRegisterRequest(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str = Field(..., pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    mac_address: Optional[str] = Field(None, pattern=r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    os_type: str = Field(..., min_length=1, max_length=64)
    agent_name: Optional[str] = None
    agent_version: str = Field("1.0.0", max_length=32)
    asset_id: Optional[str] = None
    config: Optional[Dict[str, Any]] = None

class AgentResponse(BaseModel):
    id: str
    organization_id: str
    agent_name: str
    hostname: str
    ip_address: str
    mac_address: Optional[str] = None
    os_type: str
    agent_version: str
    status: Literal["Active", "Offline", "Suspended", "Revoked"]
    last_heartbeat_at: Optional[str] = None
    registered_at: str
    config: Dict[str, Any] = {}
    api_key: Optional[str] = None
    api_key_prefix: Optional[str] = None

class TelemetryItem(BaseModel):
    interface: str = "eth0"
    source_ip: str
    destination_ip: str
    protocol: Literal["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SSH", "TLS", "OTHER"] = "TCP"
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_count: int = 1
    byte_count: int = 64
    direction: Literal["Inbound", "Outbound", "Internal"] = "Inbound"
    captured_at: Optional[str] = None

class DeviceMetricsItem(BaseModel):
    cpu_utilization_pct: float = Field(..., ge=0.0, le=100.0)
    memory_utilization_pct: float = Field(..., ge=0.0, le=100.0)
    disk_utilization_pct: float = Field(..., ge=0.0, le=100.0)
    network_interface_status: str = "Up"

class IngestTelemetryPayload(BaseModel):
    agent_id: str
    network_flows: List[TelemetryItem] = []
    host_metrics: Optional[DeviceMetricsItem] = None
    timestamp: Optional[str] = None

class MonitoringStatusResponse(BaseModel):
    worker_status: Literal["running", "idle", "degraded"]
    active_agents_count: int
    total_monitored_assets: int
    network_health_status: Literal["Healthy", "Degraded", "Critical"]
    current_traffic_bps: float
    active_anomalies_count: int
    open_alerts_count: int
    active_incidents_count: int
    last_telemetry_received_at: Optional[str] = None
    connection_mode: str = "hybrid_realtime_polling"

class ProtocolBreakdown(BaseModel):
    protocol: str
    percentage: float
    byte_count: int
    packet_count: int

class TopTalkerItem(BaseModel):
    ip_address: str
    hostname: Optional[str] = None
    total_bytes: int
    packet_count: int
    direction: str

class TopPortItem(BaseModel):
    port: int
    service: str
    count: int
    bytes: int

class TrafficAnalyticsResponse(BaseModel):
    total_packets: int
    total_bytes: int
    upload_bytes: int
    download_bytes: int
    current_throughput_kbps: float
    traffic_trend: List[Dict[str, Any]]
    top_destination_ports: List[TopPortItem]
    top_talkers: List[TopTalkerItem]
    protocol_breakdown: List[ProtocolBreakdown]

class DeviceHealthSummary(BaseModel):
    asset_id: str
    asset_name: str
    ip_address: str
    agent_id: Optional[str] = None
    agent_status: Literal["Active", "Offline", "Not Installed"] = "Not Installed"
    health_state: Literal["Healthy", "Warning", "Critical", "Offline", "Unknown"] = "Unknown"
    cpu_pct: Optional[float] = None
    memory_pct: Optional[float] = None
    disk_pct: Optional[float] = None
    interface_status: str = "Up"
    last_seen: Optional[str] = None
    is_agent_monitored: bool = False

class NetworkAnomalyResponse(BaseModel):
    id: str
    detected_at: str
    source_asset: str
    event_category: str
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"]
    rule_name: str
    evidence: Dict[str, Any]
    confidence: int
    recommended_investigation: str
    status: Literal["Open", "Investigating", "Resolved", "Dismissed"]
    asset_id: Optional[str] = None

class MonitoringRuleCreate(BaseModel):
    rule_name: str = Field(..., min_length=2, max_length=128)
    rule_type: Literal[
        "traffic_spike",
        "unexpected_port",
        "connection_failure_burst",
        "volume_anomaly",
        "new_device",
        "suspicious_outbound",
        "ioc_traffic_match",
    ]
    description: Optional[str] = None
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"] = "Medium"
    threshold: float = 100.0
    time_window_seconds: int = 300
    parameters: Dict[str, Any] = {}

class MonitoringRuleUpdate(BaseModel):
    rule_name: Optional[str] = None
    threshold: Optional[float] = None
    severity: Optional[Literal["Critical", "High", "Medium", "Low", "Informational"]] = None
    time_window_seconds: Optional[int] = None
    is_enabled: Optional[bool] = None
    parameters: Optional[Dict[str, Any]] = None

class MonitoringRuleResponse(BaseModel):
    id: str
    organization_id: str
    rule_name: str
    rule_type: str
    description: Optional[str] = None
    severity: str
    threshold: float
    time_window_seconds: int
    is_enabled: bool
    parameters: Dict[str, Any] = {}
    last_triggered_at: Optional[str] = None
    created_at: str
    updated_at: str

class MonitoringEventItem(BaseModel):
    id: str
    timestamp: str
    event_type: str
    severity: str
    title: str
    details: Dict[str, Any]
    agent_id: Optional[str] = None
    asset_id: Optional[str] = None
