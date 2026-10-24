"""SSL certificate validation and anomaly detection."""

import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from tridetect.shared.logger import get_logger

logger = get_logger(__name__)

_TRUSTED_ISSUERS = {
    "Let's Encrypt", "DigiCert", "Comodo", "Sectigo",
    "GlobalSign", "GeoTrust", "Entrust", "Verisign",
    "Amazon", "Google Trust Services",
}


def check_ssl(url: str, timeout: float = 3.0) -> dict:
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    result = {
        "valid": False,
        "age_days": None,
        "issuer": None,
        "expiry_days_left": None,
        "anomalies": [],
    }

    if not hostname:
        result["anomalies"].append("Cannot extract hostname")
        return result

    if parsed.scheme == "http":
        result["anomalies"].append("No HTTPS — plain HTTP connection")
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")

        fmt = "%b %d %H:%M:%S %Y %Z"
        now = datetime.now(tz=timezone.utc)

        if not_before_str:
            not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
            result["age_days"] = (now - not_before).days
            if result["age_days"] < 30:
                result["anomalies"].append(f"Certificate very new ({result['age_days']} days old)")

        if not_after_str:
            not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
            result["expiry_days_left"] = (not_after - now).days
            if result["expiry_days_left"] < 0:
                result["anomalies"].append("Certificate EXPIRED")
            elif result["expiry_days_left"] < 14:
                result["anomalies"].append(f"Certificate expiring soon ({result['expiry_days_left']} days)")

        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        org = issuer_parts.get("organizationName", "Unknown")
        result["issuer"] = org

        if not any(trusted in org for trusted in _TRUSTED_ISSUERS):
            result["anomalies"].append(f"Uncommon certificate issuer: {org}")

        result["valid"] = len(result["anomalies"]) == 0 or (
            result.get("expiry_days_left", 0) > 0
        )

    except ssl.SSLCertVerificationError as exc:
        result["anomalies"].append(f"SSL verification failed: {exc.reason}")
    except ssl.SSLError as exc:
        result["anomalies"].append(f"SSL error: {exc}")
    except (socket.timeout, TimeoutError):
        result["anomalies"].append("SSL check timed out")
    except OSError as exc:
        result["anomalies"].append(f"Connection error: {exc}")

    return result
