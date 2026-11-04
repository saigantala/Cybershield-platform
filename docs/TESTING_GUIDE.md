# CyberShield – Automated Testing & Quality Assurance Guide

## 1. Testing Strategy & Philosophy

CyberShield employs a rigorous test pyramid ensuring that all 20 sprints operate harmoniously without regression:
- **Unit Tests**: Pure cryptographic routines (TOTP RFC 6238, hash chaining, posture formulas).
- **Integration Tests**: FastAPI TestClient requests exercising middleware, dependencies, and DB abstractions.
- **Security Probes**: Automated OWASP verification (BOLA, BFLA, SQLi fuzzing, command injection, token tampering).
- **Regression Suite**: 215 tests executed across 21 test files in under 15 seconds.

---

## 2. Running Test Suites

### Complete Backend Regression Suite (215 Tests)
```bash
cd backend
.venv\Scripts\pytest -q
```
Expected output:
```
215 passed, 549 warnings in ~14s
```

### Specific Sprint Test Suites
```bash
# Sprint 19 Security Validation Suite (18 tests)
pytest tests/test_sprint19_security_validation.py -v

# Sprint 20 Enterprise Release & Workflow Suite (14 tests)
pytest tests/test_sprint20_enterprise_release.py -v

# Sprint 18 Identity & MFA Suite (14 tests)
pytest tests/test_sprint18_identity_mfa_sso.py -v
```

### Frontend Type Safety Verification
```bash
cd apps/web
npx tsc --noEmit
```
Expected output:
```
Exit code 0 (0 compilation errors).
```
