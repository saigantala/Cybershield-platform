# CyberShield DevSecOps & Security Operations Guide

---

## 1. DevSecOps Philosophy & Toolchain
CyberShield integrates security into every phase of the software development and deployment lifecycle, shifting security checks left to detect vulnerabilities, secrets, and configuration drift before merging.

| Phase | Automated Tooling | Target Objective |
| :--- | :--- | :--- |
| **Pre-Commit** | Gitleaks / Local Linter | Prevents accidental commits of API keys or JWT tokens |
| **CI Build** | TypeScript (`tsc`), Flake8 | Strict static typing and code hygiene enforcement |
| **CI Security** | CodeQL SAST | Detects injection, SSRF, XSS, and authorization bypasses |
| **Dependency** | Dependabot & Trivy | Flags outdated and vulnerable npm / pip packages (CVEs) |
| **Container** | Multi-Stage Non-Root Docker | Drops root privileges, limits attack surface |
| **Runtime** | Adaptive Rate Limiter & CSP | Real-time defense against DoS, brute force, and XSS |

---

## 2. Secrets Management & Zero-Commit Policy
1. **Never Commit Secrets**:
   - `.env`, `.env.local`, `.env.production` are strictly ignored in `.gitignore`.
   - Continuous scanning via Gitleaks in GitHub Actions blocks any PR introducing entropy matching private keys or certificates.
2. **Environment Variable Separation**:
   - Client variables prefixed with `NEXT_PUBLIC_` MUST ONLY contain public-safe keys (e.g. Supabase URL and Anon Key).
   - Private keys (`SUPABASE_SERVICE_ROLE_KEY`, `SECRET_KEY`, `REDIS_PASSWORD`) are strictly backend-only.
3. **Log Scrubbing**:
   - [`SensitiveDataRedactor`](file:///C:/Users/YETHENDRA%20SAI/.gemini/antigravity/scratch/CyberShield/backend/app/core/middleware.py) sanitizes all log outputs, redacting tokens, passwords, and authorization headers.

---

## 3. Secret Rotation Playbook

### A. Application `SECRET_KEY` Rotation
1. Generate new 256-bit secret:
   ```bash
   openssl rand -hex 32
   ```
2. Update environment variable in hosting provider (Vercel / AWS ECS / Cloud Run).
3. Trigger rolling deployment. Existing session tokens expire cleanly upon rotation.

### B. Supabase JWT Secret Rotation
1. Navigate to Supabase Dashboard -> Project Settings -> API.
2. Select **Generate New JWT Secret**.
3. Copy secret to `SUPABASE_JWT_SECRET` in backend production variables.
4. Restart API containers to load new HMAC signing parameters.

### C. Webhook Signing Secret Rotation
1. Open CyberShield SOC Dashboard -> Integrations -> Webhooks (`/integrations/webhooks`).
2. Click **Rotate Key** on the target endpoint.
3. Copy one-time plaintext secret and update the consuming subscriber (e.g. PagerDuty, Jira, SIEM bridge).

---

## 4. Container Hardening Checklist
- [x] Multi-stage build minimizes final image layers.
- [x] Non-root user `appuser:appgroup` (UID/GID 1001) in backend; `nextjs:nodejs` (UID/GID 1001) in frontend.
- [x] Dropped all Linux capabilities (`cap_drop: ALL`).
- [x] Bound only required capabilities (`cap_add: NET_BIND_SERVICE`).
- [x] Restricted `no-new-privileges: true` flag set in Docker Compose.
- [x] Resource quotas (CPU and memory limits) defined to prevent noisy neighbor starvation.
- [x] Native health probes on `/api/v1/health` with automatic restart on failure.
