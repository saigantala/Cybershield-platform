# CyberShield – Enterprise Security Architecture
**Document ID:** SEC-ARCH-2026-FINAL  
**Standard Compliance:** Zero Trust Architecture (NIST SP 800-207), OWASP Top 10:2021, OWASP ASVS 4.0  

---

## 1. Zero Trust Principles & Core Identity Controls

CyberShield implements continuous verification across all operational layers:
1. **Never Trust, Always Verify**: Every HTTP request validates HMAC-SHA256 JWT signatures and organization membership.
2. **Explicit Verification of Access Assurance**:
   - Single-Factor (`aal1`): Permitted for read-only and operational SOC triage.
   - Multi-Factor (`aal2`): Mandatory for sensitive actions (forensic exports, IdP updates, role promotions).
3. **Least Privilege & Role-Based Access Control**:
   - `OWNER`: Full organization governance, ownership transfer, billing.
   - `ADMIN`: User management, scanner configuration, integration management.
   - `ANALYST`: Incident investigation, playbook execution, threat hunting.
   - `VIEWER`: Strictly read-only access; all mutations return HTTP 403 Forbidden.
4. **Last-Owner Protection**: The system strictly prevents demotion or removal of an organization's sole owner.

---

## 2. Multi-Layer Defense-in-Depth

```
Layer 1: Edge & Network Guardrails (Cloudflare WAF, Strict TLS 1.3, Rate Limiting)
  └── Layer 2: API Gateway Defenses (CSP, X-Content-Type nosniff, DENY clickjacking)
        └── Layer 3: Application Authorization (Zero Trust AAL2, ABAC evaluation)
              └── Layer 4: Data Layer Isolation (PostgreSQL Row Level Security on all tables)
                    └── Layer 5: Operational Auditing (Immutable Append-Only Audit Log)
```

---

## 3. Cryptographic Standards

- **JWT Tokens**: HMAC-SHA256 with 60-minute expiration.
- **MFA Secret**: 160-bit Base32 secret with RFC 6238 TOTP algorithm and +/- 30s drift tolerance.
- **Recovery Codes**: SHA-256 hashed single-use vault codes (`CS-XXXX-XXXX`).
- **Forensic Chain of Custody**: Cryptographic SHA-256 hash chaining over all custody events.
- **Digital Evidence**: Immediate SHA-256 calculation on ingestion; bit-stream preservation.
- **Webhooks**: Outbound HMAC-SHA256 payload signatures (`CyberShield-Signature`) with replay skew protection (<300s).
