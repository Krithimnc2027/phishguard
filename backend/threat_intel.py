"""
Live Cyber Threat Intelligence (CTI) layer.

Mirrors SOC-style enrichment: passive DNS/WHOIS forensics, URLhaus reputation,
URL-obfuscation decoding, and typosquatting detection. Every lookup is wrapped
so that being offline (or rate-limited) degrades gracefully into a "skipped"
result instead of breaking the scan. The ML verdict never depends on the
network; CTI only *augments* it.
"""

from __future__ import annotations

import base64
import socket
from datetime import datetime, timezone
from urllib.parse import unquote, urlparse

import requests

# Brands commonly targeted by typosquatting.
PROTECTED_BRANDS = ["google", "paypal", "apple", "amazon", "microsoft",
                    "facebook", "instagram", "netflix", "chase", "wellsfargo",
                    "coinbase", "binance", "dhl", "fedex", "linkedin"]

REQUEST_TIMEOUT = 4  # seconds; keep enrichment from blocking the scan path.


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def decode_obfuscation(url: str) -> dict:
    """Detect and unwind common obfuscation tricks."""
    findings = []
    decoded = unquote(url)
    if decoded != url:
        findings.append("percent-encoding")
    if "@" in url:
        findings.append("@-redirect (credentials-in-host trick)")
    host = urlparse(url if "://" in url else "http://" + url).hostname or ""
    # IP encoded as hex/decimal
    if host.replace(".", "").isdigit() is False and host.startswith("0x"):
        findings.append("hex-encoded host")
    # base64-looking long path segments
    for seg in urlparse(decoded).path.split("/"):
        if len(seg) > 16 and seg.replace("=", "").isalnum():
            try:
                base64.b64decode(seg + "===")
                findings.append("possible base64 path segment")
                break
            except Exception:
                pass
    return {"decoded_url": decoded, "obfuscation": findings}


def typosquat_check(hostname: str) -> dict:
    """Flag hostnames that are 1–2 edits away from a protected brand but aren't
    the brand's real domain."""
    host = hostname.lower()
    labels = host.split(".")
    core = labels[-2] if len(labels) >= 2 else host
    hits = []
    for brand in PROTECTED_BRANDS:
        d = _levenshtein(core, brand)
        if 0 < d <= 2:
            hits.append({"brand": brand, "distance": d})
        # brand appears as a token but not as the registered domain
        elif brand in host and core != brand and not host.endswith(brand + ".com"):
            hits.append({"brand": brand, "distance": -1, "note": "brand-in-subdomain"})
    return {"typosquat": hits, "is_typosquat": bool(hits)}


def dns_lookup(hostname: str) -> dict:
    try:
        infos = socket.getaddrinfo(hostname, None)
        ips = sorted({i[4][0] for i in infos})
        return {"status": "ok", "resolved_ips": ips}
    except Exception as e:
        return {"status": "unresolved", "error": str(e)}


def whois_lookup(hostname: str) -> dict:
    """Domain age is a strong phishing signal — phishing domains are usually
    days old. Returns 'skipped' when python-whois or the network is unavailable."""
    try:
        import whois  # python-whois
        w = whois.whois(hostname)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        age_days = None
        if isinstance(created, datetime):
            now = datetime.now(timezone.utc)
            c = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
            age_days = (now - c).days
        return {
            "status": "ok",
            "registrar": str(w.registrar) if w.registrar else None,
            "creation_date": str(created) if created else None,
            "age_days": age_days,
            "newly_registered": age_days is not None and age_days < 90,
        }
    except Exception as e:
        return {"status": "skipped", "error": str(e)}


def urlhaus_lookup(url: str) -> dict:
    """Query URLhaus for known-malicious status. Free, no API key."""
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            timeout=REQUEST_TIMEOUT,
        )
        data = r.json()
        if data.get("query_status") == "ok":
            return {
                "status": "listed",
                "threat": data.get("threat"),
                "url_status": data.get("url_status"),
                "tags": data.get("tags"),
            }
        return {"status": "not_listed"}
    except Exception as e:
        return {"status": "skipped", "error": str(e)}


def enrich(url: str) -> dict:
    """Run the full CTI bundle for a URL."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    return {
        "hostname": host,
        **decode_obfuscation(url),
        **typosquat_check(host),
        "dns": dns_lookup(host),
        "whois": whois_lookup(host),
        "urlhaus": urlhaus_lookup(url),
    }
