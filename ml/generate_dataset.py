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
    "leetcode.com", "geeksforgeeks.org", "kaggle.com", "gitlab.com", "atlassian.net",
    "notion.so", "figma.com", "canva.com", "coursera.org", "udemy.com",
]

# Institutional / multi-part-suffix domains. Real universities and government
# sites legitimately use deep subdomains, so the model must NOT treat depth
# alone as phishing.
LEGIT_INSTITUTIONAL = [
    "iith.ac.in", "iitb.ac.in", "iisc.ac.in", "du.ac.in", "anna.edu.in",
    "ox.ac.uk", "cam.ac.uk", "mit.edu", "stanford.edu", "berkeley.edu",
    "nic.in", "gov.in", "rbi.org.in", "incometax.gov.in",
]

# Subdomains real sites use — including security-flavoured ones (accounts.,
# login., secure.) so the model learns these words are NOT phishing by themselves.
LEGIT_SUBDOMAINS = [
    "www", "m", "shop", "mail", "blog", "docs", "drive", "app", "api",
    "support", "help", "accounts", "login", "secure", "my", "portal", "dev",
]

# Realistic slug words for long, hyphenated legit paths (e.g. blog/article URLs).
SLUG_WORDS = [
    "how", "to", "build", "guide", "best", "practices", "getting", "started",
    "introduction", "complete", "tutorial", "cheapest", "flights", "within",
    "k", "stops", "system", "design", "interview", "questions", "data",
    "structures", "algorithms", "spring", "boot", "react", "python", "deep",
    "learning", "annual", "report", "2026", "release", "notes",
]


def _rand_id(n=22):
    """A document/object id like the ones in Google Docs / Drive / Notion URLs."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "".join(random.choice(chars) for _ in range(n))


def _slug():
    return "-".join(random.choice(SLUG_WORDS) for _ in range(random.randint(2, 6)))

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
    """Generate a realistic legitimate URL.

    Crucially these are NOT all short and clean: real legit URLs are often long,
    deeply nested, hyphenated, full of query params, and use words like 'login'
    or 'secure'. Earlier the synthetic legit URLs were trivially short, so the
    model learned "long/deep/has-query == phishing" and flagged real Google
    Docs / LeetCode / university URLs. These styles fix that.
    """
    style = random.random()

    # Almost always https for legit traffic.
    scheme = "https" if random.random() < 0.97 else "http"

    if style < 0.20:
        # Short, clean homepage-ish URL (still keep some of these).
        dom = random.choice(LEGIT_DOMAINS)
        sub = (random.choice(LEGIT_SUBDOMAINS) + ".") if random.random() < 0.4 else ""
        path = random.choice(["", "/", "/about", "/contact", "/pricing", "/help"])
        return f"{scheme}://{sub}{dom}{path}"

    if style < 0.40:
        # Document / drive style: long opaque id + query (Google Docs, Notion).
        dom = random.choice(["docs.google.com", "drive.google.com", "notion.so",
                             "dropbox.com", "figma.com"])
        kind = random.choice(["document", "spreadsheets", "presentation", "file/d", "d"])
        return f"{scheme}://{dom}/{kind}/d/{_rand_id(random.randint(28, 44))}/edit?tab=t.0"

    if style < 0.58:
        # Deep hyphenated content path with a numeric id (LeetCode, blogs, news).
        dom = random.choice(["leetcode.com", "geeksforgeeks.org", "medium.com",
                             "nytimes.com", "stackoverflow.com", "github.com"])
        return (f"{scheme}://{dom}/{random.choice(['problems', 'articles', 'questions', 'blog'])}/"
                f"{_slug()}/{random.choice(['submissions/', '', 'comments/'])}"
                f"{random.randint(100000, 99999999)}/")

    if style < 0.72:
        # E-commerce / search with a real query string (lots of params + digits).
        dom = random.choice(["amazon.com", "ebay.com", "google.com", "shopify.com"])
        return (f"{scheme}://www.{dom}/{random.choice(['search', 's', 'product', 'dp'])}"
                f"?q={_slug()}&page={random.randint(1, 9)}&ref=sr_{random.randint(1, 50)}"
                f"&sort=relevance")

    if style < 0.78:
        # Institutional deep subdomains on multi-part suffixes (ac.in, edu, ...).
        dom = random.choice(LEGIT_INSTITUTIONAL)
        sub = ".".join(random.choice(["dept", "cse", "ece", "events", "admin",
                                      "portal", "exam", "registration", "conf"])
                       for _ in range(random.randint(1, 2)))
        return (f"{scheme}://{sub}.{dom}/{random.choice(['admission', 'hackathon2026', 'events', 'notices'])}/"
                f"{random.choice(['register', 'apply', 'login', 'index.html'])}")

    # Legit URLs that genuinely contain 'login'/'secure'/'account' words, so the
    # model can't use those keywords alone as a phishing signal.
    host = random.choice(["accounts.google.com", "login.microsoftonline.com",
                          "secure.bankofamerica.com", "signin.aws.amazon.com",
                          "myaccount.google.com", "id.atlassian.com",
                          "login.live.com", "auth.services.adobe.com",
                          "secure.chase.com", "online.hdfcbank.com"])
    path = random.choice(["signin/v2/identifier", "login", "oauth2/authorize",
                          "ServiceLogin", "v3/signin/identifier", "account/login"])
    return (f"{scheme}://{host}/{path}"
            f"?service={random.choice(['mail', 'cloud', 'console'])}&continue=%2Fhome")


def _rand_word_token(n_min=4, n_max=9):
    """A digit-free lowercase token. Used so the model can't lean on 'has
    digits' as a phishing shortcut."""
    n = random.randint(n_min, n_max)
    return "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(n))


# Plausible-looking TLDs that are NOT on the abusive list — so the model can't
# rely on 'suspicious_tld' alone. Real phishing increasingly uses these.
NEUTRAL_TLDS = ["com", "net", "org", "info", "site", "online", "co"]


def gen_phish() -> str:
    style = random.random()
    brand = random.choice(BRANDS)
    word = random.choice(PHISH_WORDS)
    word2 = random.choice(PHISH_WORDS)
    # Most modern phishing is served over HTTPS — don't make http a giveaway.
    scheme = "https" if random.random() < 0.7 else "http"

    if style < 0.18:
        # Brand buried in a long subdomain chain on an abusive TLD.
        tld = random.choice(PHISH_TLDS)
        host = f"{brand}.com-{word}.{_rand_token()}.{tld}"
        return f"{scheme}://{host}/{word}?cmd=_update&dispatch={_rand_token()}"
    if style < 0.34:
        # Raw IP host (no domain registration needed). Always http in practice.
        ip = ".".join(str(random.randint(1, 255)) for _ in range(4))
        port = "" if random.random() < 0.5 else f":{random.choice([8080, 8000, 8443, 443])}"
        return f"http://{ip}{port}/{brand}/{word}/index.php?id={_rand_token()}"
    if style < 0.48:
        # URL shortener hiding the destination.
        sh = random.choice(SHORTENERS)
        return f"{scheme}://{sh}/{_rand_token(5, 8)}"
    if style < 0.60:
        # @-redirect trick: real-looking text before @, attacker host after.
        tld = random.choice(PHISH_TLDS)
        return f"{scheme}://{brand}.com@{_rand_token()}.{tld}/{word}-{word2}/"
    if style < 0.72:
        # Typosquat with hyphens and suspicious words on a cheap TLD.
        tld = random.choice(PHISH_TLDS)
        host = f"{brand}-{word}-{_rand_token(3, 6)}.{tld}"
        return f"{scheme}://{host}/{word}/{word}.html?token={_rand_token()}"

    # --- "stealthy" styles: HTTPS, digit-free, plausible TLD, no IP/@/shortener.
    # These are the cases the cruder rules miss; the model must learn that deep
    # subdomain chains + keyword density are themselves the signal.
    if style < 0.86:
        # Deep subdomain spoof where the brand is a SUBDOMAIN, not the domain.
        # e.g. login.update.secure.paypal.com.verify-account.site/auth
        attacker = f"{_rand_word_token()}-{word2}.{random.choice(NEUTRAL_TLDS)}"
        return (f"https://{word}.{word2}.secure.{brand}.com.{attacker}/"
                f"{word}/{word2}")
    # Long keyword-stuffed subdomain chain on a neutral TLD, https, no digits.
    tld = random.choice(NEUTRAL_TLDS)
    host = f"{word}-{word2}.{brand}-{_rand_word_token(4,7)}.{tld}"
    return f"https://{host}/{word}/{word2}/{_rand_word_token()}"


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
