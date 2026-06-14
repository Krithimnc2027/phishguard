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

# Multi-part public suffixes. Without these, a host like
# "boihackathon.cse.iith.ac.in" would treat ".in" as the TLD and "ac" as the
# registered domain, badly over-counting subdomains. These are the common
# country-code second-level suffixes; the list need not be exhaustive.
MULTI_PART_TLDS = {
    "co.uk", "ac.uk", "gov.uk", "org.uk", "me.uk", "net.uk", "sch.uk",
    "co.in", "ac.in", "gov.in", "edu.in", "org.in", "net.in", "res.in", "nic.in",
    "co.jp", "ac.jp", "go.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.br", "com.cn", "com.sg", "edu.sg", "gov.sg",
    "com.mx", "com.tr", "com.hk", "com.tw", "com.my", "com.ph",
}

_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _split_host(hostname: str):
    """Split a hostname into (subdomain_labels, registered_domain, suffix),
    correctly handling multi-part suffixes like 'ac.in' / 'co.uk'.

    Returns ([], "", "") for empty/IP hosts.
    """
    if not hostname or _IP_RE.match(hostname):
        return [], hostname, ""
    parts = hostname.split(".")
    if len(parts) < 2:
        return [], hostname, ""
    # Multi-part suffix (e.g. ac.in) takes two labels; otherwise one.
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_TLDS:
        suffix = ".".join(parts[-2:])
        domain = parts[-3]
        subdomains = parts[:-3]
    else:
        suffix = parts[-1]
        domain = parts[-2]
        subdomains = parts[:-2]
    return subdomains, domain, suffix


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

    # Split the host with multi-part-suffix awareness so country-code domains
    # (ac.in, co.uk, ...) don't inflate the subdomain count.
    subdomains, domain, tld = _split_host(hostname)
    num_subdomains = len(subdomains)

    digits = sum(c.isdigit() for c in raw)

    # Keyword match on word tokens, not raw substrings, so "secure" doesn't
    # fire inside "secured" and "free" doesn't fire inside "freelancer".
    raw_tokens = set(_TOKEN_RE.findall(raw.lower()))
    num_suspicious_words = sum(1 for w in SUSPICIOUS_WORDS if w in raw_tokens)

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
        "prefix_suffix_hyphen": int("-" in domain),
        "tld_length": len(tld),
        "shortening_service": int(hostname in SHORTENERS),
        "suspicious_tld": int(tld.split(".")[-1] in SUSPICIOUS_TLDS),
        "num_suspicious_words": num_suspicious_words,
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
