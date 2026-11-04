-- CyberShield Development Seed Data

INSERT INTO organizations (id, name, slug, plan, verified_domain)
VALUES 
  ('00000000-0000-0000-0000-000000000001', 'Nexus Defense Group', 'nexus-defense', 'enterprise', 'nexusdefense.internal'),
  ('00000000-0000-0000-0000-000000000002', 'Aegis FinTech Labs', 'aegis-fintech', 'professional', 'aegisfintech.io')
ON CONFLICT (id) DO NOTHING;

INSERT INTO profiles (id, email, full_name)
VALUES
  ('11111111-1111-1111-1111-111111111111', 'sec-lead@nexusdefense.internal', 'Elena Rostova'),
  ('22222222-2222-2222-2222-222222222222', 'marcus.vance@nexusdefense.internal', 'Marcus Vance')
ON CONFLICT (id) DO NOTHING;

INSERT INTO organization_members (organization_id, user_id, role)
VALUES
  ('00000000-0000-0000-0000-000000000001', '11111111-1111-1111-1111-111111111111', 'owner'),
  ('00000000-0000-0000-0000-000000000001', '22222222-2222-2222-2222-222222222222', 'admin')
ON CONFLICT (organization_id, user_id) DO NOTHING;

INSERT INTO scan_scopes (id, organization_id, target, type, description, status)
VALUES
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '00000000-0000-0000-0000-000000000001', '192.168.10.0/24', 'cidr', 'Core Datacenter Subnet', 'approved'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '00000000-0000-0000-0000-000000000001', '10.50.0.0/22', 'cidr', 'Corporate Workstations Subnet', 'approved'),
  ('cccccccc-cccc-cccc-cccc-cccccccccccc', '00000000-0000-0000-0000-000000000001', '172.16.80.0/24', 'cidr', 'Facility IoT Subnet', 'approved')
ON CONFLICT (id) DO NOTHING;

INSERT INTO assets (id, organization_id, name, ip_address, mac_address, hostname, category, classification_confidence, classification_evidence, os, status, risk_level, risk_score)
VALUES
  ('33333333-3333-3333-3333-333333333333', '00000000-0000-0000-0000-000000000001', 'PRD-K8S-GATEWAY-01', '192.168.10.1', '00:1A:2B:3C:4D:5E', 'gw-core.prod.nexus.internal', 'Router', 96, 'Cisco IOS-XE banner fingerprint, CDP protocol match', 'Cisco IOS-XE 17.9', 'online', 'critical', 89),
  ('44444444-4444-4444-4444-444444444444', '00000000-0000-0000-0000-000000000001', 'DB-POSTGRES-CLUSTER-01', '192.168.10.45', '52:54:00:8F:90:A1', 'pg-primary.prod.nexus.internal', 'Server', 92, 'Ubuntu Linux kernel 6.5, OpenSSH 8.9p1 banner, PostgreSQL 16', 'Ubuntu 22.04 LTS', 'online', 'high', 74)
ON CONFLICT (id) DO NOTHING;

INSERT INTO findings (id, organization_id, cve_id, title, description, severity, cvss_score, asset_id, remediation, evidence, cisa_kev, exploit_available, status)
VALUES
  ('55555555-5555-5555-5555-555555555555', '00000000-0000-0000-0000-000000000001', 'CVE-2024-6387', 'regreSSHion: Remote Code Execution in OpenSSH Server', 'Signal handler race condition allows unauthenticated RCE as root on glibc Linux.', 'critical', 9.8, '44444444-4444-4444-4444-444444444444', 'Upgrade openssh-server to 8.9p1-3ubuntu0.10 or set LoginGraceTime 0.', 'Banner confirmed OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 vulnerable to glibc race condition.', true, true, 'open')
ON CONFLICT (id) DO NOTHING;
