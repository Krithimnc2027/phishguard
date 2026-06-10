"""
PhishGuard FastAPI backend.

Endpoints:
  POST /api/scan        -> classify a URL (ML verdict + optional CTI enrichment)
  GET  /api/history     -> recent scans
  GET  /api/stats       -> verdict distribution (for dashboard charts)
  GET  /api/report/{id} -> structured IoC report for a single scan (JSON)
  GET  /api/metrics     -> training metrics of the loaded model
  GET  /                -> analyst dashboard (static)

The ML model is loaded once at startup. CTI enrichment is opt-in per request
(`?intel=true`) so the fast path stays sub-500ms for the browser extension.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# Make the shared feature extractor importable from ../ml.
ML_DIR = Path(__file__).resolve().parent.parent / "ml"
sys.path.insert(0, str(ML_DIR))
from features import FEATURE_NAMES, extract_features  # noqa: E402

import db  # noqa: E402
import threat_intel  # noqa: E402

MODEL_PATH = ML_DIR / "model.joblib"
METRICS_PATH = ML_DIR / "metrics.json"
STATIC_DIR = Path(__file__).parent / "static"

# Risk thresholds on the model's phishing probability.
PHISH_THRESHOLD = 0.80
SUSPICIOUS_THRESHOLD = 0.45

app = FastAPI(title="PhishGuard API", version="1.0.0")

# The Chrome extension and dashboard call this from other origins.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_bundle = None


def get_model():
    global _bundle
    if _bundle is None:
        if not MODEL_PATH.exists():
            raise RuntimeError(
                "model.joblib not found. Train first:\n"
                "  cd ml && python generate_dataset.py && python train.py"
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


@app.on_event("startup")
def _startup():
    db.init_db()
    try:
        get_model()
        print("Model loaded.")
    except Exception as e:
        print(f"WARNING: {e}")


class ScanRequest(BaseModel):
    url: str


def _classify(url: str):
    """Return (verdict, prob, reasons) from lexical features only."""
    feats = extract_features(url)
    X = pd.DataFrame([[feats[n] for n in FEATURE_NAMES]], columns=FEATURE_NAMES)
    prob = float(get_model()["model"].predict_proba(X)[0, 1])

    if prob >= PHISH_THRESHOLD:
        verdict = "phishing"
    elif prob >= SUSPICIOUS_THRESHOLD:
        verdict = "suspicious"
    else:
        verdict = "legitimate"

    # Human-readable reasons keyed off the strongest structural signals.
    reasons = []
    if feats["has_ip"]:
        reasons.append("Host is a raw IP address")
    if feats["has_at_redirect"]:
        reasons.append("URL contains '@' redirect (credentials-in-host trick)")
    if feats["shortening_service"]:
        reasons.append("Uses a URL-shortening service")
    if feats["suspicious_tld"]:
        reasons.append("Abusive/free top-level domain")
    if feats["num_suspicious_words"] >= 2:
        reasons.append(f"Contains {feats['num_suspicious_words']} phishing keywords")
    if feats["num_subdomains"] >= 3:
        reasons.append("Unusually deep subdomain chain")
    if feats["is_punycode"]:
        reasons.append("Punycode host (possible homograph attack)")
    if feats["prefix_suffix_hyphen"]:
        reasons.append("Hyphenated domain (common in typosquats)")
    if not reasons and verdict != "legitimate":
        reasons.append("Model flagged based on combined lexical signals")

    return verdict, round(prob, 4), reasons, feats


@app.post("/api/scan")
def scan(req: ScanRequest, intel: bool = Query(False)):
    if not req.url or len(req.url) > 4000:
        raise HTTPException(400, "Invalid URL")

    t0 = time.time()
    verdict, prob, reasons, feats = _classify(req.url)

    intel_data = {}
    if intel:
        intel_data = threat_intel.enrich(req.url)
        # CTI can escalate the verdict regardless of the lexical score.
        if intel_data.get("urlhaus", {}).get("status") == "listed":
            verdict, prob = "phishing", max(prob, 0.99)
            reasons.insert(0, "Listed on URLhaus malicious-URL feed")
        if intel_data.get("is_typosquat"):
            reasons.append("Typosquatting a known brand (CTI)")
            if verdict == "legitimate":
                verdict = "suspicious"
        if intel_data.get("whois", {}).get("newly_registered"):
            reasons.append("Domain registered within last 90 days (CTI)")

    from urllib.parse import urlparse
    host = urlparse(req.url if "://" in req.url else "http://" + req.url).hostname

    latency_ms = round((time.time() - t0) * 1000, 2)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "url": req.url,
        "hostname": intel_data.get("hostname") or host,
        "verdict": verdict,
        "risk_score": prob,
        "reasons": reasons,
        "intel": intel_data,
        "latency_ms": latency_ms,
    }
    record["id"] = db.insert_scan(record)
    return record


@app.get("/api/history")
def history(limit: int = 100):
    return {"scans": db.recent_scans(limit)}


@app.get("/api/stats")
def get_stats():
    return db.stats()


@app.get("/api/report/{scan_id}")
def report(scan_id: int):
    """Structured IoC report for a single scan (downloadable JSON)."""
    s = db.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "Scan not found")
    intel = s.get("intel", {})
    return {
        "report_type": "PhishGuard IoC Report",
        "generated": datetime.now(timezone.utc).isoformat(),
        "scan_id": scan_id,
        "indicator": s["url"],
        "hostname": s.get("hostname"),
        "verdict": s["verdict"],
        "risk_score": s["risk_score"],
        "reasons": s["reasons"],
        "resolved_ips": intel.get("dns", {}).get("resolved_ips", []),
        "whois": intel.get("whois", {}),
        "urlhaus": intel.get("urlhaus", {}),
        "typosquat": intel.get("typosquat", []),
        "obfuscation": intel.get("obfuscation", []),
    }


@app.get("/api/metrics")
def metrics():
    import json
    if METRICS_PATH.exists():
        return json.loads(METRICS_PATH.read_text())
    return {"error": "metrics.json not found — train the model first"}


# --- static dashboard --------------------------------------------------------
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def dashboard():
    index = STATIC_DIR / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return {"message": "PhishGuard API running. Dashboard not found."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=False)
