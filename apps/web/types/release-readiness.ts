export type ReleaseCheckStatus = "passed" | "failed" | "warning" | "not_tested" | "requires_configuration";
export type ReleaseGateStatus = "ready_for_release" | "release_blocked" | "conditionally_ready";

export interface ReleaseCheckItem {
  check_id: string;
  category: string;
  name: string;
  description: string;
  status: ReleaseCheckStatus;
  evidence_or_details: string;
  remediation_or_action?: string;
  tested_at: string;
}

export interface SecurityEngineStatus {
  engine_name: string;
  engine_type: string;
  classification:
    | "configured"
    | "connected_and_verified"
    | "disconnected"
    | "configuration_required"
    | "mock_demo"
    | "error";
  details: string;
  version_or_provider?: string;
  execution_mode: string;
}

export interface EnterpriseReleaseOverview {
  release_version: string;
  evaluated_at: string;
  gate_status: ReleaseGateStatus;
  readiness_score: number;
  total_checks: number;
  passed_checks: number;
  failed_checks: number;
  warning_checks: number;
  config_required_checks: number;
  checks_by_category: Record<string, ReleaseCheckItem[]>;
  security_engines: SecurityEngineStatus[];
  system_metrics: {
    total_automated_tests: number;
    test_pass_rate_pct: number;
    frontend_tsc_errors: number;
    total_routes_mounted: number;
    total_database_migrations: number;
    rls_coverage_pct: number;
  };
  active_environment: string;
  summary_verdict: string;
}
