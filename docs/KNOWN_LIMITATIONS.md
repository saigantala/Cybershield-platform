# CyberShield – Known Limitations & Operating Boundaries
**Release:** v1.0.0-enterprise  
**Audit Standard:** Honest Disclosure & Operational Safety  

---

## 1. External Security Engine Configurations

1. **Nmap Binary Dependency**:
   - In environments where the native `nmap` binary or raw socket privileges (`CAP_NET_RAW` / Npcap) are unavailable, CyberShield automatically utilizes simulated network scan results to preserve stability.
2. **OpenVAS / Greenbone GVM**:
   - Full vulnerability scanning requires an external, reachable GVM daemon instance. A simulated connector is active for staging and development.
3. **OWASP ZAP Dynamic Scanning**:
   - Internal API security probes and fuzzing are natively executed by CyberShield; deep recursive web crawling requires an external OWASP ZAP container.
4. **AlienVault OTX Intelligence**:
   - Live threat pulse ingestion requires a customer-provided `ALIENVAULT_OTX_API_KEY`.
5. **AI Assistant External LLM**:
   - When `CYBERSHIELD_AI_API_KEY` is not provided, the AI Assistant defaults to deterministic, non-hallucinatory grounded retrieval logic without calling external cloud APIs.

---

## 2. Hardening Boundaries

1. **RFC 1918 Scope Restriction**:
   - Network discovery scanners strictly block public internet IP ranges (e.g. `8.8.8.8`) to prevent unauthorized scanning.
2. **Evidence Storage Limit**:
   - Forensic evidence uploads are bounded to a maximum of 25MB per file with immediate SHA-256 integrity hashing.
3. **Rate Limiting**:
   - In-memory rate limiting operates per IP address (120 requests/minute general, 15 requests/minute for authentication).
