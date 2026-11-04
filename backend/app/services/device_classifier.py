import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel


class ClassificationResult(BaseModel):
    device_type: str
    confidence: int  # 0 to 100 percentage
    evidence: List[str]


# Common MAC OUI prefixes mapped to likely vendors
OUI_VENDORS = {
    "00:1A:2B": "Cisco Systems",
    "00:0C:29": "VMware Virtual Platform",
    "52:54:00": "QEMU/KVM Virtual",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "24:0A:C4": "Espressif Systems (ESP32 IoT)",
    "30:AE:A4": "Espressif Systems (ESP32 IoT)",
    "00:03:93": "Apple Inc.",
    "AC:DE:48": "Apple Inc.",
    "F0:18:98": "Apple Inc.",
    "00:14:22": "Dell Inc.",
    "54:48:10": "Dell Inc.",
    "00:25:B3": "Hewlett Packard Enterprise",
    "3C:D9:2B": "HP Inc. (Printer / System)",
    "00:1E:67": "Intel Corporate",
    "70:81:05": "Fortinet Edge Security",
}


class DeviceClassifier:
    """
    Evidence-based network device classification engine.
    Analyzes MAC OUIs, service banners, open ports, and hostname patterns.
    Never claims certainty without sufficient corroborating telemetry.
    """

    @classmethod
    def classify(
        cls,
        ip_address: str,
        mac_address: Optional[str] = None,
        hostname: Optional[str] = None,
        open_ports: Optional[List[int]] = None,
        service_banners: Optional[List[Dict[str, Any]]] = None,
        os_hint: Optional[str] = None,
    ) -> ClassificationResult:
        ports = set(open_ports or [])
        banners = service_banners or []
        evidence: List[str] = []
        scores: Dict[str, int] = {
            "Router": 0,
            "Server": 0,
            "Laptop": 0,
            "Desktop": 0,
            "IoT": 0,
            "Printer": 0,
            "Mobile": 0,
        }

        # 1. Inspect MAC Vendor
        if mac_address:
            clean_mac = mac_address.upper().replace("-", ":")
            prefix = clean_mac[:8]
            vendor = OUI_VENDORS.get(prefix)
            if vendor:
                evidence.append(f"MAC OUI matched vendor: {vendor}")
                if "Cisco" in vendor or "Fortinet" in vendor:
                    scores["Router"] += 35
                elif "Raspberry" in vendor or "Espressif" in vendor:
                    scores["IoT"] += 40
                elif "HP Inc. (Printer" in vendor:
                    scores["Printer"] += 45
                elif "Dell" in vendor or "Supermicro" in vendor or "VMware" in vendor or "QEMU" in vendor:
                    scores["Server"] += 30
                elif "Apple" in vendor:
                    scores["Laptop"] += 20
                    scores["Mobile"] += 15

        # 2. Inspect Hostname Patterns
        if hostname:
            h = hostname.lower()
            if any(k in h for k in ["rtr", "router", "switch", "sw-", "gw-", "firewall", "fw-"]):
                scores["Router"] += 40
                evidence.append(f"Hostname matches network infrastructure pattern: '{hostname}'")
            elif any(k in h for k in ["prn", "printer", "mfp", "jetdirect"]):
                scores["Printer"] += 45
                evidence.append(f"Hostname matches printer naming convention: '{hostname}'")
            elif any(k in h for k in ["srv", "k8s", "db-", "pg-", "prod-", "api-", "redis", "nginx", "node"]):
                scores["Server"] += 40
                evidence.append(f"Hostname matches server / cluster naming convention: '{hostname}'")
            elif any(k in h for k in ["mbp", "macbook", "laptop", "thinkpad", "surface", "notebook"]):
                scores["Laptop"] += 40
                evidence.append(f"Hostname matches portable workstation naming: '{hostname}'")
            elif any(k in h for k in ["desktop", "workstation", "pc-", "win11-"]):
                scores["Desktop"] += 35
                evidence.append(f"Hostname matches desktop computer naming: '{hostname}'")
            elif any(k in h for k in ["cam", "sensor", "iot", "esp32", "thermostat"]):
                scores["IoT"] += 45
                evidence.append(f"Hostname matches embedded IoT naming: '{hostname}'")
            elif any(k in h for k in ["iphone", "android", "pixel", "galaxy", "ipad"]):
                scores["Mobile"] += 50
                evidence.append(f"Hostname matches mobile handset naming: '{hostname}'")

        # 3. Inspect Open Ports
        if ports:
            # Printer ports
            if 9100 in ports or 515 in ports or 631 in ports:
                scores["Printer"] += 40
                evidence.append(f"Standard printing ports open: {ports.intersection({9100, 515, 631})}")

            # Router / Management ports
            if 161 in ports or 830 in ports:
                scores["Router"] += 30
                evidence.append(f"Network management port active (SNMP/NETCONF: {ports.intersection({161, 830})})")

            # IoT Ports (MQTT, CoAP)
            if 1883 in ports or 8883 in ports or 5683 in ports:
                scores["IoT"] += 45
                evidence.append(f"IoT telemetry messaging port active (MQTT: {ports.intersection({1883, 8883, 5683})})")

            # Server / Enterprise services
            if 22 in ports and (80 in ports or 443 in ports or 5432 in ports or 3306 in ports or 6379 in ports):
                scores["Server"] += 35
                evidence.append(f"Multi-tier enterprise server port bundle: {sorted(list(ports))}")

            # RDP / SMB Workstation
            if 3389 in ports and 445 in ports:
                scores["Desktop"] += 25
                scores["Server"] += 15
                evidence.append("Windows remote access & SMB ports active (3389, 445)")

        # 4. Inspect Service Banners
        for banner in banners:
            name = str(banner.get("name", "")).lower()
            product = str(banner.get("product", "")).lower()
            version = str(banner.get("version", "")).lower()
            combined = f"{name} {product} {version}"

            if any(s in combined for s in ["cisco", "fortios", "junos", "pfsense", "openwrt"]):
                scores["Router"] += 40
                evidence.append(f"Router / Firewall banner detected: '{product or name}'")
            elif any(s in combined for s in ["jetdirect", "cups", "canon", "epson"]):
                scores["Printer"] += 45
                evidence.append(f"Print spooler banner detected: '{product or name}'")
            elif any(s in combined for s in ["openssh", "nginx", "apache", "postgresql", "envoy", "mariadb"]):
                scores["Server"] += 25
                evidence.append(f"Server service banner detected: '{product or name}'")

        # 5. OS Hint Evaluation
        if os_hint:
            os_lower = os_hint.lower()
            if any(o in os_lower for o in ["cisco", "fortigate", "routeros"]):
                scores["Router"] += 40
                evidence.append(f"OS detection indicates network appliance: {os_hint}")
            elif any(o in os_lower for o in ["ubuntu", "debian", "red hat", "centos", "freebsd", "windows server"]):
                scores["Server"] += 25
                evidence.append(f"OS detection indicates enterprise server platform: {os_hint}")

        # 6. Determine Winning Classification
        best_category = max(scores, key=scores.get)
        highest_score = scores[best_category]

        # Minimum confidence threshold (30%)
        if highest_score < 30:
            return ClassificationResult(
                device_type="Unknown",
                confidence=0,
                evidence=evidence or ["Insufficient telemetry to determine device class."],
            )

        confidence = min(95, highest_score)
        return ClassificationResult(
            device_type=best_category,
            confidence=confidence,
            evidence=evidence,
        )
