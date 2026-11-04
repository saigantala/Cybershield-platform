# CyberShield – Backup, Disaster Recovery & Business Continuity Guide
**Target Recovery Objectives:** RPO < 1 Hour, RTO < 30 Minutes  

---

## 1. Automated Database Backups (Supabase)

- **Continuous WAL Archiving**: Point-In-Time-Recovery (PITR) enabled with up to 30 days retention.
- **Daily Physical Snapshot**: Executed every 24 hours at 00:00 UTC with automated offsite replication.
- **Evidence Storage Replication**: Multi-region bucket replication enabled for forensic evidence objects.

---

## 2. Manual Backup Procedures

### PostgreSQL Logical Export
```bash
pg_dump -h db.your-project.supabase.co -U postgres -d postgres -F c -b -v -f "cybershield_backup_$(date +%Y%m%d_%H%M%S).dump"
```

### Redis Snapshot
```bash
redis-cli -u $REDIS_URL BGSAVE
```

---

## 3. Disaster Recovery Scenario: Complete Region Failure

1. **Activate Secondary Standby Cluster**:
   - Promote Supabase read-replica or restore snapshot into alternate region.
2. **Deploy Application Containers**:
   - Deploy backend and Celery workers pointing to secondary database endpoint.
3. **DNS Traffic Shift**:
   - Update Cloudflare DNS origin pool to direct traffic to new region VIP.
4. **Verification**:
   - Validate `/api/v1/health` and verify user sessions and evidence chain integrity.
