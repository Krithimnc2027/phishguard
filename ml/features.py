"""
URL feature extraction for PhishGuard.

All features here are *lexical / host-based*: they are computed purely from the
URL string and require no network access. This is what makes inference fast
(sub-500ms) and lets the model run inside a browser-extension flow without
waiting on external services. Live threat-intel (WHOIS/DNS/URLhaus) is layered
on top separately in the backend.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urlparse

# Ordered list of feature names. The training pipeline and the inference
# pipeline both import this so the column order can never drift.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_at",
    "num_question",
    "num_ampersand",
    "num_equals",
    "num_underscore",
    "num_percent",
    "num_slash",
    "num_digits",
    "num_subdomains",
    "digit_ratio",
    "hostname_entropy",
    "has_ip",
    "has_https",
    "has_port",
    "is_punycode",
    "double_slash_in_path",
    "prefix_suffix_hyphen",
    "tld_length",
    "shortening_service",
    "suspicious_tld",
    "num_suspicious_words",
    "has_at_redirect",
]

# Common URL shorteners — phishers use these to hide the true destination.
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy",
}

# TLDs that are cheap/free and disproportionately abused in phishing campaigns.
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "work", "click", "link",
    "country", "kim", "science", "party", "gdn", "review", "loan", "men",
    "zip", "mov",
}

# Words frequently embedded in phishing URLs to mimic trusted brands/actions.
SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "banking", "bank", "confirm", "password", "credential",
    "ebayisapi", "webscr", "paypal", "appleid", "wallet", "billing", "invoice",
    "support", "unlock", "suspended", "recover", "free", "bonus", "gift",
]

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string. Random/algorithmically-generated hostnames
    (common in phishing) tend to have higher entropy than real brand names."""
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _normalize(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        # urlparse needs a scheme to populate netloc correctly.
        url = "http://" + url
    return url


def extract_features(url: str) -> dict:
    """Return the feature dict for a single URL. Always returns every key in
    FEATURE_NAMES so callers can rely on a fixed schema."""
    raw = url
    url = _normalize(url)
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    host_parts = hostname.split(".") if hostname else []
    tld = host_parts[-1] if len(host_parts) >= 2 else ""
    # subdomains = labels beyond domain + tld (e.g. a.b.example.com -> a, b)
    num_subdomains = max(0, len(host_parts) - 2) if len(host_parts) >= 2 else 0

    digits = sum(c.isdigit() for c in raw)

    feats = {
        "url_length": len(raw),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": raw.count("."),
        "num_hyphens": raw.count("-"),
        "num_at": raw.count("@"),
        "num_question": raw.count("?"),
        "num_ampersand": raw.count("&"),
        "num_equals": raw.count("="),
        "num_underscore": raw.count("_"),
        "num_percent": raw.count("%"),
        "num_slash": raw.count("/"),
        "num_digits": digits,
        "num_subdomains": num_subdomains,
        "digit_ratio": digits / len(raw) if raw else 0.0,
        "hostname_entropy": round(_shannon_entropy(hostname), 4),
        "has_ip": int(bool(_IP_RE.match(hostname))),
        "has_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None),
        "is_punycode": int("xn--" in hostname),
        "double_slash_in_path": int("//" in path),
        "prefix_suffix_hyphen": int("-" in (host_parts[-2] if len(host_parts) >= 2 else "")),
        "tld_length": len(tld),
        "shortening_service": int(hostname in SHORTENERS),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "num_suspicious_words": sum(w in raw.lower() for w in SUSPICIOUS_WORDS),
        "has_at_redirect": int("@" in raw),
    }
    return feats


def extract_vector(url: str) -> list:
    """Feature values as an ordered list matching FEATURE_NAMES."""
    f = extract_features(url)
    return [f[name] for name in FEATURE_NAMES]


if __name__ == "__main__":
    import json
    for u in ["https://www.google.com",
              "http://paypal.com.secure-login.verify-account.tk/webscr?cmd=update",
              "http://192.168.1.20@bit.ly/free-gift"]:
        print(u)
        print(json.dumps(extract_features(u), indent=2))
        print()
