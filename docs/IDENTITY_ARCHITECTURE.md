# CyberShield Enterprise Identity & Zero Trust Architecture

## Executive Overview
CyberShield Sprint 18 implements an enterprise-grade Identity and Access Management (IAM), Multi-Factor Authentication (MFA), Single Sign-On (SSO), secure session management, and Zero Trust access control architecture. Designed to protect multi-tenant security operations centers against advanced credential compromise, session hijacking, and unauthorized lateral movement, CyberShield enforces continuous server-side authorization and strict Authentication Assurance Levels (AAL).

---

## 1. Authentication Architecture & Token Verification

### 1.1 Supabase Auth & JWT Verification Model
- **Primary Token Authority**: Supabase Auth issues cryptographically signed JSON Web Tokens (JWT) using HS256 (symmetric) or RS256/ES256 (asymmetric JWKS).
- **Claims Verification**: FastAPI backend verifies the signature, `aud`, `iss`, `sub`, `exp`, and extracts identity attributes (`email`, `user_metadata`).
- **Tenant Context Resolution**: All protected endpoints resolve the caller's authorized tenant organization membership from `organization_members` with associated role (`owner`, `admin`, `analyst`, `viewer`).

### 1.2 Authentication Assurance Levels (AAL)
CyberShield adheres to NIST SP 800-63B Authentication Assurance Levels:
- **`aal1` (Single-Factor Assurance)**: Primary credential verified (email/password or standard SSO without step-up MFA).
- **`aal2` (Multi-Factor Assurance)**: Primary credential augmented with verified second factor (TOTP authenticator app or single-use recovery code).
- **Continuous Elevation**: Sessions elevated to `aal2` can execute high-risk operations (e.g. digital forensics evidence export, API key rotation, SSO provider reconfiguration). Requests to sensitive endpoints with `aal1` are rejected with HTTP 403 / 422 requiring step-up.

---

## 2. Multi-Factor Authentication (MFA) Implementation

### 2.1 RFC 6238 Time-Based One-Time Passwords (TOTP)
- **Algorithm**: Standard HMAC-SHA1 with 30-second step window and 6-digit output.
- **Key Generation**: Cryptographically secure 160-bit Base32 secret generated via `os.urandom(20)`.
- **Enrollment URI**: Formatted compliant with `otpauth://totp/CyberShield%20SOC:{email}?secret={secret}&issuer=CyberShield%20SOC&algorithm=SHA1&digits=6&period=30`.
- **Inline QR Code Generation**: Scalable SVG representation rendered dynamically with finder patterns and module grids derived from the SHA-256 hash of the enrollment URI.
- **Time Drift Tolerance**: Verification window allows +/- 30 seconds (1 step before and after current time) to accommodate client clock skew.
- **Brute-Force & Rate-Limiting Protection**: Failed verification attempts are tracked in `mfa_challenge_attempts`. Five consecutive failed attempts within 15 minutes trigger an automated HTTP 429 lockout for that account.

### 2.2 Backup Recovery Codes Vault
- **Code Format**: 10 high-entropy codes generated in `CS-XXXX-XXXX` format.
- **Secure Storage**: Plaintext codes are presented to the user **once** during enrollment. The database stores only SHA-256 hashes:
  ```json
  [
    { "hash": "3a7b...", "used_at": null, "created_at": "2026-11-02T10:00:00Z" }
  ]
  ```
- **Single-Use Invalidation (Burn on Use)**: When a recovery code is submitted, its SHA-256 hash is checked against unburned entries (`used_at is None`). Upon match, `used_at` is timestamped, preventing reuse.
- **Cryptographic Rotation**: Users can rotate their entire recovery code vault at any time by supplying a valid TOTP code.

### 2.3 Step-Up Authentication Workflow
For high-risk operations:
1. User provides current 6-digit TOTP verification code.
2. Backend verifies code and generates a HMAC-SHA256 signed step-up authorization token with 5-minute validity:
   ```
   stepup_{b64(user_id:org_id:action:expires_at)}.{hmac_sha256}
   ```
3. Target sensitive API validates signature and expiration before committing changes.

---

## 3. Enterprise Single Sign-On (SSO) Engine

### 3.1 Supported Identity Providers (IdP)
- **Microsoft Entra ID (Azure AD)**: OIDC 1.0 authorization code flow with tenant-specific discovery endpoints.
- **Okta Workforce Identity**: Multi-domain authorization with custom auth servers.
- **Google Workspace**: Google Identity OIDC integration with domain constraints.
- **Generic OIDC 1.0 & SAML 2.0**: Standard metadata endpoints, ACS URLs, and X.509 certificate validation.

### 3.2 Domain Verification & DNS Challenge
To prevent account takeover and unauthorized SSO takeover:
1. Administrator inputs corporate domain (e.g. `apexcyberdefense.io`).
2. CyberShield generates a deterministic cryptographic verification token:
   ```
   cybershield-verify={sha256(domain + org_id)[:24]}
   ```
3. Enterprise DNS administrator publishes this token as a `TXT` record at the domain apex.
4. CyberShield queries DNS to confirm presence before activating SSO domain routing.

### 3.3 Credential Masking & Security
- `client_secret` is encrypted or stored in vault.
- API responses strictly mask client secrets as `••••••••••••`, exposing only the last 4 characters (`client_secret_last4`) for administrative verification.
- **Lockout Prevention**: System prohibits deleting the sole active SSO provider or locking out the last organization owner.

---

## 4. Active Session Security & Device Management

### 4.1 Continuous Session Tracking
The backend records enriched session metadata in `session_security_metadata`:
- Device category (`desktop`, `mobile`, `tablet`, `api_client`).
- Browser family and Operating System version parsed from User-Agent.
- IP address and approximate geographical location.
- Authentication Assurance Level (`aal1` vs `aal2`).
- Session expiration and last active timestamp.

### 4.2 Anomaly & Impossible Travel Detection
Sessions flagged as suspicious under conditions:
- **Impossible Travel**: Geographical coordinate jump between consecutive requests exceeding physical transport capabilities (< 15 mins between different continents).
- **High-Risk Network Fingerprints**: Headless browsers, unrecognized proxy ASNs, or IP changes during active workflows.

### 4.3 Granular & Bulk Revocation
- **Individual Session Termination**: Instantly revokes session tokens, preventing further API access.
- **Revoke All Other Sessions**: Emergency killswitch invalidating all sessions across all devices except the current active session.
- **Concurrent Session Limits**: Organization policy automatically enforces `max_concurrent_sessions_per_user`, revoking the oldest inactive session when exceeded.

---

## 5. Zero Trust Access Policies (Fail-Closed ABAC)

### 5.1 Continuous Server-Side Authorization
Client-side checks are never trusted. Every API invocation evaluates context dynamically:
1. **Network Boundary Evaluation**: Verifies caller's IP against organization allowed CIDRs (`allowed_ip_cidrs`).
2. **Organization MFA Mandate**: If `mfa_required` is enabled or user's role is in `mfa_enforced_roles`, rejects any session below `aal2`.
3. **Microsegmentation Rules**: Matches target `resource_type` and `action` against prioritized rules:
   - Explicit `deny` policies take immediate precedence.
   - Requires `min_aal == "aal2"` for high-risk operations (e.g. Forensics evidence export, API key regeneration).
   - Validates resource-specific IP whitelists.
4. **RBAC Fallback (Fail-Closed)**:
   - `owner`: Full organizational governance and transfer.
   - `admin`: Full administrative operational capability.
   - `analyst`: Read, write, execute on security assets, alerts, incidents, SOAR, threat hunting, and forensics.
   - `viewer`: Strictly read-only; write, delete, execute, and export operations are denied.

---

## 6. Immutable Identity Audit Trail
All authentication and authorization events are recorded in `identity_audit_events`:
- **Event Types**: `login_success`, `login_failure`, `logout`, `mfa_enrolled`, `mfa_disabled`, `mfa_challenge_success`, `mfa_challenge_failure`, `mfa_recovery_code_used`, `mfa_recovery_codes_rotated`, `step_up_success`, `step_up_failure`, `sso_provider_configured`, `sso_domain_verified`, `session_revoked`, `all_sessions_revoked`, `zero_trust_access_denied`.
- **Zero Exposure**: Plaintext passwords, TOTP secret keys, and unhashed recovery codes are strictly filtered before persistence.
- **Correlation ID**: Cryptographic trace ID linking frontend requests to backend audit records.
