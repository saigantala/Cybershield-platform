# CyberShield – Sprint 18 Deliverables
## Enterprise Identity, SSO, MFA & Zero Trust Security Architecture

### Overview
Sprint 18 implements an enterprise-grade Identity & Access Management (IAM), Multi-Factor Authentication (MFA), Single Sign-On (SSO), secure session management, and Zero Trust access policy architecture for CyberShield.

---

### Key Deliverables

#### 1. Database Schema (`supabase/migrations/20261102_sprint18_enterprise_identity_sso_mfa.sql`)
Defined 10 tables with Row Level Security (RLS) tenant isolation:
- `identity_providers`: OIDC / SAML2 / Entra / Okta / Google Workspace configuration with masked secret metadata.
- `identity_domain_verifications`: Domain verification challenges with TXT tokens.
- `organization_identity_policies`: Organization-wide governance toggles (MFA required, SSO required, idle timeout, max concurrent sessions, allowed CIDRs).
- `user_security_preferences`: User MFA enrollment status, Base32 encrypted secret, hashed backup recovery codes, AAL level.
- `session_security_metadata`: Active session tracking with device type, browser, OS, IP address, approx location, suspicious flags, revocation timestamps.
- `access_policies`: Zero Trust microsegmentation rules (resource, action, effect, allowed roles, min_aal, IP whitelist).
- `access_policy_assignments`: Role and user bindings to access policies.
- `identity_audit_events`: Immutable forensic audit log of all identity and authentication events.
- `mfa_factors`: Enrolled factor registry.
- `mfa_challenge_attempts`: Rate-limiting and brute-force tracking table.

#### 2. Backend Services & Schemas
- `backend/app/schemas/identity.py`: Comprehensive Pydantic models for MFA setup, verification, recovery codes, rotation, step-up tokens, SSO providers, domain challenges, session management, Zero Trust policies, and identity audit logs.
- `backend/app/services/identity_service.py`:
  - **RFC 6238 TOTP Engine**: Standard 160-bit Base32 secret generation, `otpauth://` URI, inline scalable SVG QR code, time-drift tolerance (+/- 30s), brute-force rate limiter (5 failed attempts per 15 mins triggers 429 lockout).
  - **Recovery Codes Vault**: Generates 10 `CS-XXXX-XXXX` codes, persists only SHA-256 hashes, enforces single-use invalidation (burn on use), and supports TOTP-verified rotation.
  - **Step-Up Authentication**: Generates HMAC-SHA256 signed 5-minute tokens for sensitive operations.
  - **SSO Provider Engine**: OIDC / SAML2 setup with masked secrets (`••••••••••••`), domain verification via DNS TXT tokens, authorization code flow initiation with cryptographically secure state & nonce.
  - **Active Session Manager**: Device parsing, suspicious IP/location jump detection, individual and bulk revocation, concurrent session enforcement.
  - **Zero Trust Engine**: Fail-closed continuous authorization evaluating network CIDRs, organization MFA mandates, prioritized microsegmentation rules, and role hierarchies.
  - **Last-Owner Protection**: Prevents deleting the last owner or removing the only active SSO provider.

#### 3. FastAPI Endpoints (`backend/app/api/routes/identity.py`)
Mounted under `/api/v1/identity`:
- `GET /identity/overview`: Account security posture score, MFA status, session count, recommendations.
- `POST /identity/mfa/setup`: Generates Base32 secret, otpauth URI, and QR code SVG.
- `POST /identity/mfa/verify`: Verifies TOTP or recovery code, elevates session to AAL2, issues initial recovery codes.
- `POST /identity/mfa/rotate-recovery`: Rotates 10 recovery codes when verified by valid TOTP.
- `POST /identity/mfa/disable`: Disables MFA if permitted by organization policy.
- `POST /identity/mfa/step-up`: Generates 5-minute step-up authorization token for sensitive actions.
- `GET /identity/sso/providers`: Lists configured IdPs with masked secrets.
- `POST /identity/sso/providers`: Configures new SSO IdP (owner/admin only).
- `PUT /identity/sso/providers/{id}`: Updates SSO IdP configuration (owner/admin only).
- `DELETE /identity/sso/providers/{id}`: Deletes SSO IdP with lockout protection (owner/admin only).
- `POST /identity/sso/providers/{id}/test`: Validates IdP discovery and endpoints.
- `GET /identity/sso/domains`: Lists domain verification challenges.
- `POST /identity/sso/domains`: Initiates domain verification challenge with TXT token.
- `POST /identity/sso/domains/{domain}/verify`: Verifies DNS TXT record.
- `POST /identity/sso/login/initiate`: Public OIDC flow initiation.
- `POST /identity/sso/login/callback`: Exchanges auth code for session.
- `GET /identity/sessions`: Lists active sessions with device/location info.
- `POST /identity/sessions/revoke`: Revokes specific session.
- `POST /identity/sessions/revoke-all`: Revokes all other sessions.
- `GET /identity/policies/org`: Retrieves organization identity policy.
- `PUT /identity/policies/org`: Updates organization identity policy (owner/admin only).
- `GET /identity/policies/rules`: Lists Zero Trust access rules.
- `POST /identity/policies/rules`: Deploys new access rule (owner/admin only).
- `PUT /identity/policies/rules/{id}`: Updates access rule (owner/admin only).
- `DELETE /identity/policies/rules/{id}`: Deletes access rule (owner/admin only).
- `POST /identity/policies/evaluate`: Evaluates continuous authorization in real-time.
- `GET /identity/audit`: Queries immutable identity audit log.

#### 4. Frontend User Interface (Premium SOC Dark Glassmorphism)
- `/settings/security`: Account Hardening Posture Overview, 0-100 Security Score gauge, MFA/SSO/Sessions status cards, actionable recommendations list, and navigation tabs.
- `/settings/mfa`: TOTP setup wizard with SVG QR code, Base32 key with one-click copy, verification input, 10 backup recovery codes vault with copy and download, rotation form, and step-up auth sandbox.
- `/settings/sso`: Configured IdP cards (Microsoft Entra ID, Okta, Google Workspace), "Configure New IdP" modal, connection tester with feedback banner, and domain TXT record verification manager.
- `/settings/sessions`: Device sessions tracker with icons (desktop, mobile, tablet), browser, OS, IP address, approximate location, suspicious login anomaly alerts, individual session revocation, and "Revoke All Other Sessions" emergency button.
- `/identity/access-policies`: Organization governance toggles, microsegmentation ABAC rules table, deploy rule modal, and interactive Zero Trust Policy Simulator.
- `/identity/audit`: Immutable forensic audit ledger with status badges, event filters, real-time search, and strict credential redaction.
- `apps/web/components/layout/Sidebar.tsx`: Added navigation links for Security & MFA, Identity & Zero Trust, and Identity Audit.

---

### Verification & Testing
- **Sprint 18 Backend Tests**: 14 tests passing (`pytest tests/test_sprint18_identity_mfa_sso.py`).
- **Full Backend Regression Suite**: **183 passed in 6.89s** across Sprints 1–18 with 0 failures.
- **Frontend TypeScript Compilation**: Clean exit code 0 (`npx tsc --noEmit`) with 0 errors.
