export type IntegrationCategory =
  | 'siem'
  | 'security_tools'
  | 'communication'
  | 'threat_intelligence'
  | 'cloud_security'
  | 'webhooks'
  | 'authentication'
  | 'monitoring';

export type ConnectionStatus =
  | 'Connected'
  | 'Disconnected'
  | 'Pending_Configuration'
  | 'Error'
  | 'Testing';

export type IntegrationHealthStatus =
  | 'Healthy'
  | 'Degraded'
  | 'Unhealthy'
  | 'Unknown';

export type WebhookEventType =
  | 'alert.created'
  | 'incident.created'
  | 'incident.updated'
  | 'vulnerability.detected'
  | 'asset.discovered'
  | 'compliance.updated'
  | 'soar.execution_completed'
  | 'soar.execution_failed'
  | 'report.generated';

export type WebhookDeliveryStatus =
  | 'Pending'
  | 'Delivered'
  | 'Failed'
  | 'Retrying'
  | 'Dead_Letter';

export interface Integration {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  category: IntegrationCategory;
  provider: string;
  description?: string | null;
  connection_status: ConnectionStatus;
  is_enabled: boolean;
  health_status: IntegrationHealthStatus;
  config: Record<string, any>;
  secret_configured: boolean;
  secret_masked?: string | null;
  last_synced_at?: string | null;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface IntegrationCreate {
  name: string;
  slug: string;
  category: IntegrationCategory;
  provider: string;
  description?: string;
  config?: Record<string, any>;
  secret_key?: string;
  is_enabled?: boolean;
}

export interface IntegrationUpdate {
  name?: string;
  description?: string;
  is_enabled?: boolean;
  config?: Record<string, any>;
  secret_key?: string;
}

export interface IntegrationTestRequest {
  custom_endpoint?: string;
  test_event_type?: string;
}

export interface IntegrationTestResponse {
  success: boolean;
  latency_ms: number;
  status: ConnectionStatus;
  message: string;
  raw_response?: Record<string, any> | null;
  tested_at: string;
}

export interface IntegrationSyncRequest {
  sync_type?: 'incremental' | 'full' | 'manual';
  dry_run?: boolean;
}

export interface IntegrationSyncResponse {
  integration_id: string;
  sync_type: string;
  status: 'Success' | 'Partial' | 'Failed';
  items_synced: number;
  duration_ms: number;
  error_message?: string | null;
  synced_at: string;
}

export interface IntegrationDeliveryLog {
  id: string;
  integration_id: string;
  event_type: string;
  status: 'Delivered' | 'Failed' | 'Retrying';
  http_status_code?: number | null;
  duration_ms: number;
  payload_summary?: string | null;
  error_message?: string | null;
  created_at: string;
}

export interface ProviderHealthMetric {
  provider: string;
  status: IntegrationHealthStatus;
  latency_ms: number;
  success_rate_24h: number;
  total_deliveries_24h: number;
  last_delivery_at?: string | null;
}

export interface IntegrationHealthSummary {
  total_integrations_count: number;
  connected_count: number;
  healthy_percent: number;
  active_webhooks_count: number;
  failed_deliveries_24h: number;
  provider_health: ProviderHealthMetric[];
}

export interface WebhookEndpoint {
  id: string;
  organization_id: string;
  name: string;
  url: string;
  description?: string | null;
  secret_preview: string;
  is_active: boolean;
  events: WebhookEventType[];
  retry_limit: number;
  timeout_seconds: number;
  failure_count: number;
  last_triggered_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface WebhookEndpointCreate {
  name: string;
  url: string;
  description?: string;
  events: WebhookEventType[];
  retry_limit?: number;
  timeout_seconds?: number;
  is_active?: boolean;
}

export interface WebhookEndpointUpdate {
  name?: string;
  url?: string;
  description?: string;
  events?: WebhookEventType[];
  retry_limit?: number;
  timeout_seconds?: number;
  is_active?: boolean;
}

export interface WebhookSecretRotateResponse {
  webhook_id: string;
  new_secret: string;
  rotated_at: string;
}

export interface WebhookDeliveryAttempt {
  id: string;
  webhook_id: string;
  idempotency_key: string;
  payload: Record<string, any>;
  status: WebhookDeliveryStatus;
  http_status_code?: number | null;
  attempt_number: number;
  response_body?: string | null;
  error_message?: string | null;
  duration_ms: number;
  created_at: string;
}

export interface WebhookReplayResponse {
  delivery_id: string;
  success: boolean;
  http_status_code?: number | null;
  new_status: WebhookDeliveryStatus;
  duration_ms: number;
  replayed_at: string;
}
