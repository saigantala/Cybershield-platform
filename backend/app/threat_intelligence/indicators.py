import ipaddress
import re
from typing import Tuple
from urllib.parse import urlparse

from app.threat_intelligence.models import IOCType

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


class IndicatorValidator:
    """
    Validates, standardizes, and sanitizes Indicators of Compromise (IOCs).
    Rejects malformed strings to prevent query contamination.
    """

    @classmethod
    def validate_and_normalize(cls, indicator_type: IOCType, value: str) -> str:
        val = value.strip()
        if not val:
            raise ValueError("Indicator value cannot be empty.")

        if indicator_type == "ipv4":
            try:
                ip = ipaddress.IPv4Address(val)
                return str(ip)
            except ipaddress.AddressValueError:
                raise ValueError(f"Invalid IPv4 address format: '{val}'")

        elif indicator_type == "ipv6":
            try:
                ip = ipaddress.IPv6Address(val)
                return str(ip)
            except ipaddress.AddressValueError:
                raise ValueError(f"Invalid IPv6 address format: '{val}'")

        elif indicator_type == "domain":
            cleaned = val.lower()
            # Strip port or trailing slash if passed
            cleaned = cleaned.rstrip("/")
            if ":" in cleaned:
                cleaned = cleaned.split(":")[0]
            if not DOMAIN_REGEX.match(cleaned) or len(cleaned) > 253:
                raise ValueError(f"Invalid domain format: '{val}'")
            return cleaned

        elif indicator_type == "url":
            parsed = urlparse(val)
            if not parsed.scheme or parsed.scheme not in ("http", "https"):
                raise ValueError(f"URL must start with http:// or https://: '{val}'")
            if not parsed.netloc:
                raise ValueError(f"Invalid URL netloc/host: '{val}'")
            return val

        elif indicator_type == "md5":
            if not MD5_REGEX.match(val):
                raise ValueError(f"Invalid MD5 hash (must be 32 hex characters): '{val}'")
            return val.lower()

        elif indicator_type == "sha1":
            if not SHA1_REGEX.match(val):
                raise ValueError(f"Invalid SHA1 hash (must be 40 hex characters): '{val}'")
            return val.lower()

        elif indicator_type == "sha256":
            if not SHA256_REGEX.match(val):
                raise ValueError(f"Invalid SHA256 hash (must be 64 hex characters): '{val}'")
            return val.lower()

        else:
            raise ValueError(f"Unsupported indicator type: '{indicator_type}'")

    @classmethod
    def detect_type(cls, value: str) -> Tuple[IOCType, str]:
        """Automatically infers and normalizes the IOC type from string structure."""
        val = value.strip()
        # Hashes
        if SHA256_REGEX.match(val):
            return "sha256", val.lower()
        if SHA1_REGEX.match(val):
            return "sha1", val.lower()
        if MD5_REGEX.match(val):
            return "md5", val.lower()

        # IPs
        try:
            ipaddress.IPv4Address(val)
            return "ipv4", val
        except ipaddress.AddressValueError:
            pass

        try:
            ipaddress.IPv6Address(val)
            return "ipv6", val
        except ipaddress.AddressValueError:
            pass

        # URL
        if val.startswith("http://") or val.startswith("https://"):
            return "url", cls.validate_and_normalize("url", val)

        # Domain
        if DOMAIN_REGEX.match(val):
            return "domain", val.lower()

        raise ValueError(f"Could not infer valid IOC type for: '{value}'")
