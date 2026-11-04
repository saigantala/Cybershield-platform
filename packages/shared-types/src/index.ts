export type UserRole = 'owner' | 'admin' | 'analyst' | 'viewer';

export interface UserProfile {
  id: string;
  email: string;
  fullName: string;
  avatarUrl?: string;
  role: UserRole;
  organizationId: string;
  createdAt: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: 'enterprise' | 'professional' | 'standard';
  createdAt: string;
  updatedAt: string;
  logoUrl?: string;
  verifiedDomain?: string;
}

export type ScopeTargetType = 'cidr' | 'ip_range' | 'single_ip' | 'hostname';
export type ScopeStatus = 'pending_approval' | 'approved' | 'rejected' | 'revoked';

export interface ScanScope {
  id: string;
  organizationId: string;
  target: string;
  type: ScopeTargetType;
  description: string;
  status: ScopeStatus;
  approvedBy?: string;
  approvedAt?: string;
  createdAt: string;
}

export type DeviceCategory = 
  | 'Server'
  | 'Router'
  | 'Switch'
  | 'Laptop'
  | 'Desktop'
  | 'Mobile'
  | 'IoT device'
  | 'Printer'
  | 'Camera'
  | 'Unknown device';

export type DeviceStatus = 'online' | 'offline' | 'unresponsive';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'safe';

export interface Asset {
  id: string;
  organizationId: string;
  name: string;
  ipAddress: string;
  macAddress?: string;
  hostname?: string;
  category: DeviceCategory;
  classificationConfidence: number; // 0 - 100 percentage
  classificationEvidence: string;
  os?: string;
  status: DeviceStatus;
  riskLevel: RiskLevel;
  riskScore: number; // 0 - 100
  lastSeen: string;
  firstSeen: string;
  tags: string[];
  openPortsCount: number;
  vulnerabilityCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  segment?: string;
}

export interface AssetService {
  id: string;
  assetId: string;
  port: number;
  protocol: 'tcp' | 'udp';
  name: string;
  version?: string;
  state: 'open' | 'filtered' | 'closed';
  banner?: string;
  isBaselineApproved: boolean;
}

export type ScanType = 'network_discovery' | 'vulnerability_assessment' | 'web_baseline';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScanProfile = 'fast_discovery' | 'comprehensive_audit' | 'web_baseline_safe' | 'full_compliance';

export interface Scan {
  id: string;
  organizationId: string;
  title: string;
  type: ScanType;
  profile: ScanProfile;
  targetScope: string;
  status: ScanStatus;
  progress: number; // 0 to 100
  startedAt?: string;
  completedAt?: string;
  durationSeconds?: number;
  hostsDiscovered: number;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  initiatedBy: string;
  logs: string[];
}

export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type FindingStatus = 'open' | 'in_progress' | 'mitigated' | 'false_positive' | 'accepted_risk';

export interface Finding {
  id: string;
  organizationId: string;
  cveId?: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  cvssScore: number;
  assetId: string;
  assetName: string;
  assetIp: string;
  port?: number;
  service?: string;
  remediation: string;
  evidence: string;
  cisaKev: boolean;
  exploitAvailable: boolean;
  status: FindingStatus;
  discoveredAt: string;
  updatedAt: string;
}

export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed';

export interface Incident {
  id: string;
  organizationId: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assignedTo?: string;
  assignedToName?: string;
  affectedAssets: string[];
  evidenceNotes: string;
  resolutionNotes?: string;
  createdAt: string;
  updatedAt: string;
}

export interface SecurityNotification {
  id: string;
  organizationId: string;
  title: string;
  message: string;
  severity: 'critical' | 'warning' | 'info' | 'success';
  read: boolean;
  createdAt: string;
  link?: string;
}

export interface AuditLog {
  id: string;
  organizationId: string;
  userEmail: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  details: string;
  ipAddress: string;
  timestamp: string;
}

export interface SecurityReport {
  id: string;
  organizationId: string;
  title: string;
  type: 'executive_summary' | 'technical_vulnerability' | 'compliance_assessment' | 'network_inventory';
  scope: string;
  generatedAt: string;
  generatedBy: string;
  assetCount: number;
  findingsCount: number;
  riskScore: number;
  fileSize: string;
}

export interface SecurityPostureMetrics {
  totalAssets: number;
  onlineDevices: number;
  offlineDevices: number;
  totalVulnerabilities: number;
  criticalFindings: number;
  highRiskAssets: number;
  activeScansCount: number;
  securityPostureScore: number; // 0 - 100
  scoreDelta: number; // e.g. +3% or -5%
  cisaKevCount: number;
}
