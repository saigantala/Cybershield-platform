from app.workers.tasks import health_check_task, cleanup_demo_task, process_demo_scan
from app.services.scanner_base import NmapScanner, OpenVASScanner, OwaspZapScanner


def test_health_check_task():
    res = health_check_task()
    assert res["status"] == "healthy"
    assert res["worker"] == "celery_worker"
    assert "timestamp" in res


def test_cleanup_demo_task():
    res = cleanup_demo_task()
    assert res["status"] == "success"
    assert res["artifacts_purged"] == 0


def test_scanner_scope_validation():
    scanner = NmapScanner()
    approved = ["192.168.10.0/24", "10.0.0.0/16"]

    # In scope subnet
    assert scanner.validate_scope("192.168.10.50/32", approved) is True
    assert scanner.validate_scope("10.0.1.0/24", approved) is True

    # Out of scope third-party network
    assert scanner.validate_scope("8.8.8.8", approved) is False
    assert scanner.validate_scope("172.16.0.0/12", approved) is False


def test_scanner_interfaces():
    nmap = NmapScanner()
    openvas = OpenVASScanner()
    zap = OwaspZapScanner()

    assert "Nmap" in nmap.name
    assert "OpenVAS" in openvas.name
    assert "ZAP" in zap.name
