"""
Build a labeled URL dataset for training.

Two modes:

1. Real data (preferred): drop CSV files into ml/data/ and this script will
   merge them. Expected columns: a URL column (url/URL/domain) and optionally
   a label column (label/Label/type/result). Anything mapping to phishing/
   malicious/bad/1 is treated as phishing, everything else as legitimate.
   Sources referenced in the spec: PhishTank, URLhaus, Tranco Top 1M, ISCX 2016.

2. Synthetic fallback (default): if no CSVs are found, generate a realistic
   balanced dataset from URL *patterns* so the whole pipeline runs end-to-end
   offline. The synthetic generator mirrors the structural signals real
   phishing URLs exhibit (brand impersonation, IP hosts, shorteners, abusive
   TLDs, long subdomain chains, @-redirects), which is exactly what the lexical
   model keys off of.
"""

from __future__ import annotations

import csv
import os
import random
from pathlib import Path

HERE = Path(__file__).parent
DATA_DIR = HERE / "data"
OUT = HERE / "dataset.csv"

random.seed(1337)

# --- pools for synthetic generation -----------------------------------------

LEGIT_DOMAINS = [
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "paypal.com",
    "ebay.com", "cnn.com", "bbc.co.uk", "nytimes.com", "spotify.com",
    "dropbox.com", "adobe.com", "zoom.us", "slack.com", "shopify.com",
    "wordpress.com", "medium.com", "quora.com", "imdb.com", "espn.com",
    "bankofamerica.com", "chase.com", "wellsfargo.com", "hdfcbank.com", "sbi.co.in",
]

LEGIT_PATHS = [
    "", "/", "/about", "/contact", "/products", "/help/faq", "/blog/2026/spring",
    "/search?q=python", "/user/profile", "/watch?v=dQw4w9WgXcQ", "/news/world",
    "/docs/getting-started", "/account/settings", "/cart", "/login", "/signup",
    "/p/12345", "/category/electronics", "/articles/how-to-code", "/support",
]

BRANDS = ["paypal", "apple", "amazon", "microsoft", "google", "netflix",
          "facebook", "instagram", "chase", "wellsfargo", "hdfc", "sbi",
          "dhl", "fedex", "usps", "irs", "coinbase", "binance"]

PHISH_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "link",
              "loan", "review", "zip", "country"]

PHISH_WORDS = ["login", "secure", "verify", "verification", "account", "update",
               "confirm", "signin", "webscr", "billing", "unlock", "suspended",
               "recover", "wallet", "security", "support", "free-gift", "bonus"]

SHORTENERS = ["bit.ly", "tinyurl.com", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"]


def _rand_token(n_min=4, n_max=12):
    n = random.randint(n_min, n_max)
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


def gen_legit() -> str:
    dom = random.choice(LEGIT_DOMAINS)
    scheme = "https" if random.random() < 0.9 else "http"
    sub = ""
    if random.random() < 0.3:
        sub = random.choice(["www.", "www.", "m.", "shop.", "mail.", "blog."])
    path = random.choice(LEGIT_PATHS)
    return f"{scheme}://{sub}{dom}{path}"


def gen_phish() -> str:
    style = random.random()
    brand = random.choice(BRANDS)
    word = random.choice(PHISH_WORDS)

    if style < 0.25:
        # Brand buried in a long subdomain chain on an abusive TLD.
        tld = random.choice(PHISH_TLDS)
        host = f"{brand}.com-{word}.{_rand_token()}.{tld}"
        return f"http://{host}/{word}?cmd=_update&dispatch={_rand_token()}"
    if style < 0.45:
        # Raw IP host (no domain registration needed).
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        port = "" if random.random() < 0.5 else f":{random.choice([8080, 8000, 8443, 443])}"
        return f"http://{ip}{port}/{brand}/{word}/index.php?id={_rand_token()}"
    if style < 0.65:
        # URL shortener hiding the destination.
        sh = random.choice(SHORTENERS)
        return f"http://{sh}/{_rand_token(5, 8)}"
    if style < 0.82:
        # @-redirect trick: real-looking text before @, attacker host after.
        tld = random.choice(PHISH_TLDS)
        return f"http://{brand}.com@{_rand_token()}.{tld}/{word}-{word}/"
    # Typosquat with hyphens and suspicious words on a cheap TLD.
    tld = random.choice(PHISH_TLDS)
    host = f"{brand}-{word}-{_rand_token(3, 6)}.{tld}"
    return f"http://{host}/{word}/{word}.html?token={_rand_token()}"


def build_synthetic(n_per_class=6000):
    rows = []
    for _ in range(n_per_class):
        rows.append((gen_legit(), 0))
        rows.append((gen_phish(), 1))
    random.shuffle(rows)
    return rows


# --- real CSV ingestion ------------------------------------------------------

URL_KEYS = ("url", "URL", "Url", "domain", "Domain")
LABEL_KEYS = ("label", "Label", "type", "Type", "result", "Result", "class", "Class")
PHISH_TOKENS = {"phishing", "phish", "malicious", "malware", "bad", "spam",
                "defacement", "1", "true", "yes"}


def _coerce_label(val: str) -> int:
    return 1 if str(val).strip().lower() in PHISH_TOKENS else 0


def ingest_real() -> list:
    if not DATA_DIR.exists():
        return []
    rows = []
    for csv_path in DATA_DIR.glob("*.csv"):
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                continue
            url_col = next((k for k in URL_KEYS if k in reader.fieldnames), None)
            label_col = next((k for k in LABEL_KEYS if k in reader.fieldnames), None)
            if url_col is None:
                continue
            # If a file has no label column, infer from filename
            # (e.g. tranco/legit -> 0, phishtank/urlhaus -> 1).
            fname = csv_path.name.lower()
            default = 1 if any(t in fname for t in ("phish", "malicious", "urlhaus")) else 0
            for r in reader:
                url = (r.get(url_col) or "").strip()
                if not url:
                    continue
                label = _coerce_label(r[label_col]) if label_col else default
                rows.append((url, label))
        print(f"  ingested {csv_path.name}")
    return rows


def main():
    rows = ingest_real()
    source = "real CSVs in ml/data/"
    if not rows:
        rows = build_synthetic()
        source = "synthetic generator (no CSVs found in ml/data/)"

    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "label"])
        w.writerows(rows)

    n_phish = sum(1 for _, l in rows if l == 1)
    print(f"Wrote {len(rows)} rows to {OUT}")
    print(f"  source: {source}")
    print(f"  phishing: {n_phish}  legitimate: {len(rows) - n_phish}")


if __name__ == "__main__":
    main()
