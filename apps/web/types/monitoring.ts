export type AgentStatus = 'Active' | 'Offline' | 'Suspended' | 'Revoked';
export type DeviceHealthState = 'Healthy' | 'Warning' | 'Critical' | 'Offline' | 'Unknown';
export type AnomalySeverity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
export type AnomalyStatus = 'Open' | 'Investigating' | 'Resolved' | 'Dismissed';

export interface MonitoringStatus {
  worker_status: 'running' | 'idle' | 'degraded';
  active_agents_count: number;
  total_monitored_assets: number;
  network_health_status: 'Healthy' | 'Degraded' | 'Critical';
  current_traffic_bps: number;
  active_anomalies_count: number;
  open_alerts_count: number;
  active_incidents_count: number;
  last_telemetry_received_at?: string;
  connection_mode: string;
}

export interface MonitoringAgent {
  id: string;
  organization_id: string;
  agent_name: string;
  hostname: string;
  ip_address: string;
  mac_address?: string;
  os_type: string;
  agent_version: string;
  status: AgentStatus;
  last_heartbeat_at?: string;
  registered_at: string;
  config: Record<string, any>;
  api_key?: string; // Only populated on registration
  api_key_prefix?: string;
}

export interface TelemetryFlow {
  id?: string;
  interface: string;
  source_ip: string;
  destination_ip: string;
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS' | 'SSH' | 'TLS' | 'OTHER';
  source_port?: number;
  destination_port?: number;
  packet_count: number;
  byte_count: number;
  direction: 'Inbound' | 'Outbound' | 'Internal';
  captured_at?: string;
}

export interface DeviceMetrics {
  cpu_utilization_pct: number;
  memory_utilization_pct: number;
  disk_utilization_pct: number;
  network_interface_status: string;
}

export interface DeviceHealth {
  asset_id: string;
  asset_name: string;
  ip_address: string;
  agent_id?: string;
  agent_status: 'Active' | 'Offline' | 'Not Installed';
  health_state: DeviceHealthState;
  cpu_pct?: number;
  memory_pct?: number;
  disk_pct?: number;
  interface_status: string;
  last_seen?: string;
  is_agent_monitored: boolean;
}

export interface ProtocolBreakdown {
  protocol: string;
  percentage: number;
  byte_count: number;
  packet_count: number;
}

export interface TopTalker {
  ip_address: string;
  hostname?: string;
  total_bytes: number;
  packet_count: number;
  direction: string;
}

export interface TopPort {
  port: number;
  service: string;
  count: number;
  bytes: number;
}

export interface TrafficAnalytics {
  total_packets: number;
  total_bytes: number;
  upload_bytes: number;
  download_bytes: number;
  current_throughput_kbps: number;
  traffic_trend: Array<{
    time: string;
    upload_kbps: number;
    download_kbps: number;
    packet_count: number;
  }>;
  top_destination_ports: TopPort[];
  top_talkers: TopTalker[];
  protocol_breakdown: ProtocolBreakdown[];
}

export interface NetworkAnomaly {
  id: string;
  detected_at: string;
  source_asset: string;
  event_category: string;
  severity: AnomalySeverity;
  rule_name: string;
  evidence: Record<string, any>;
  confidence: number;
  recommended_investigation: string;
  status: AnomalyStatus;
  asset_id?: string;
}

export interface MonitoringRule {
  id: string;
  organization_id: string;
  rule_name: string;
  rule_type: string;
  description?: string;
  severity: AnomalySeverity;
  threshold: number;
  time_window_seconds: number;
  is_enabled: boolean;
  parameters: Record<string, any>;
  last_triggered_at?: string;
  created_at: string;
  updated_at: string;
}

export interface MonitoringEvent {
  id: string;
  timestamp: string;
  event_type: string;
  severity: string;
  title: string;
  details: Record<string, any>;
  agent_id?: string;
  asset_id?: string;
}
