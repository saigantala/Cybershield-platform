# CyberShield – Architecture Documentation

## 1. System Overview

CyberShield is an enterprise multi-tenant cybersecurity platform delivering automated network discovery, vulnerability assessment, threat intelligence correlation, and Security Operations Center (SOC) incident response workflows.

```mermaid
graph TD
    User["Security Operations / Analyst"] -->|HTTPS / WAF| WebApp["Next.js 14 SOC Web App (Vercel / Cloudflare)"]
    MobileUser["Mobile On-Call Analyst"] -->|HTTPS| MobileApp["Expo React Native Mobile App"]

    WebApp -->|Supabase JWT / REST| FastAPIGateway["FastAPI Central Backend Gateway (/api/v1)"]
    MobileApp -->|Supabase JWT / REST| FastAPIGateway

    FastAPIGateway -->|RLS / Tenant ID| SupabaseDB[("Supabase PostgreSQL (Multi-Tenant RLS)")]
    FastAPIGateway -->|Enqueue Task| RedisQueue[("Redis Broker")]

    RedisQueue --> ScannerWorker1["Celery Worker (Isolated Container)"]
    RedisQueue --> ScannerWorker2["Celery Worker (Isolated Container)"]

    ScannerWorker1 -->|Host Enumeration| NmapEngine["Nmap Discovery Module"]
    ScannerWorker1 -->|Vulnerability Sweep| OpenVASEngine["Greenbone / OpenVAS"]
    ScannerWorker2 -->|Baseline Web Audit| ZAPEngine["OWASP ZAP Baseline"]
    ScannerWorker2 -->|CVE Correlation| CISAKEV["CISA KEV & NVD Intelligence"]

    ScannerWorker1 -.->|Append Results| SupabaseDB
    ScannerWorker2 -.->|Alert Events| Notifications["Resend Email & Expo Push"]
```

## 2. Multi-Tenant Isolation & Safety Model

1. **Row Level Security (RLS)**: Every tenant resource (`assets`, `scans`, `findings`, `incidents`, `audit_logs`) belongs to an `organization_id`. Database queries strictly evaluate the authenticated user's organization membership through Supabase RLS.
2. **Strict Scope Authorization**: Scanning engines strictly decline execution against any IP or hostname that does not match an active, tenant-approved `scan_scopes` record.
3. **No Exploitation**: The scanner is non-destructive. It does not perform brute force, shell uploads, persistent implants, or DDoS attacks.
4. **Isolated Celery Workers**: Scanners execute in unprivileged Docker containers isolated from public API ingress.
