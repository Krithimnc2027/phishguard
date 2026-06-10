# PhishGuard

An ML-powered phishing URL detector with a live threat-intelligence layer, a
FastAPI backend, an analyst dashboard, and a Chrome extension for real-time
protection.

Built by Kota Sai Krithi.

The idea: static blacklists miss freshly registered phishing domains, so
instead of matching against a list, PhishGuard learns the *structure* of
phishing URLs and combines that with live reputation checks the way a SOC
analyst would.

## How it fits together

```
            ┌─────────────────┐
            │ Chrome extension│  scans every page you visit, badges the toolbar
            └────────┬────────┘
                     │ POST /api/scan
            ┌────────▼────────┐
            │  FastAPI backend│  feature extraction → model → (optional) CTI
            └────┬───────┬────┘
       loads     │       │   reads/writes
   model.joblib  │       │
        ┌────────▼─┐   ┌─▼──────────┐
        │ ML model │   │ sqlite     │  scan history + IoC reports
        │ (XGBoost)│   │ phishguard.db
        └──────────┘   └────────────┘
                     ▲
            ┌────────┴────────┐
            │ Analyst dashboard│ scan, history, charts, exportable reports
            └─────────────────┘
```

There are two analysis paths:

- **Fast path** (`intel=false`) — lexical features only, ~10 ms. This is what
  the browser extension uses so it never blocks page loads. Well under the
  500 ms target in the brief.
- **Deep path** (`intel=true`) — adds WHOIS domain-age, DNS resolution,
  URLhaus reputation, obfuscation decoding, and typosquatting checks. URLhaus
  hits or a brand typosquat can escalate the verdict on their own.

## Project layout

```
phishguard/
  ml/
    features.py          shared URL feature extractor (28 lexical/host features)
    generate_dataset.py  build dataset.csv (real CSVs if present, else synthetic)
    train.py             train + evaluate, writes model.joblib and metrics.json
  backend/
    main.py              FastAPI app and endpoints
    threat_intel.py      WHOIS / DNS / URLhaus / typosquat / obfuscation
    db.py                sqlite scan history
    static/              the analyst dashboard (no build step)
  extension/             Chrome MV3 extension (no build step)
  requirements.txt
  PROJECT_REPORT.md
```

## Running it

```bash
# 1. install deps
pip install -r requirements.txt

# 2. build the dataset and train the model
cd ml
python generate_dataset.py
python train.py            # writes model.joblib + metrics.json

# 3. start the backend (serves the API and the dashboard)
cd ../backend
python main.py             # http://127.0.0.1:8000
```

Open <http://127.0.0.1:8000> for the analyst dashboard.

### Loading the Chrome extension

1. Open `chrome://extensions`, turn on Developer mode.
2. "Load unpacked" → select the `extension/` folder.
3. Browse normally. The toolbar badge shows the verdict for each page
   (`✓` legitimate, `?` suspicious, `!` phishing), and phishing pages raise a
   notification. Click the icon for details and a re-scan with full threat intel.

The backend must be running on `127.0.0.1:8000` for the extension to work.

## About the dataset and the accuracy number

By default the model trains on a **synthetic** dataset generated from URL
patterns, so the whole pipeline runs offline with no downloads. Because the
synthetic phishing and legitimate URLs are structurally very distinct, the
model scores near-perfect on it — that number reflects the easiness of the
synthetic data, not real-world performance.

To get a realistic figure (typically ~96–98% with this feature set), drop real
labelled CSVs into `ml/data/` and re-run `generate_dataset.py`. It auto-detects
a URL column and a label column. Sources from the brief:

- PhishTank — verified phishing URLs
- URLhaus — live malicious URLs
- Tranco Top 1M — legitimate domains
- ISCX-URL-2016 (Kaggle) — labelled benchmark

## API reference

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/scan?intel=false` | Classify a URL. Body: `{"url": "..."}` |
| GET | `/api/history?limit=100` | Recent scans |
| GET | `/api/stats` | Verdict distribution |
| GET | `/api/report/{id}` | Structured IoC report (JSON) |
| GET | `/api/metrics` | Loaded model's training metrics |

## Notes

- WHOIS and URLhaus calls need network access; when offline they return
  `skipped`/`not_listed` and the scan still completes on the model verdict.
- The model artifact (`model.joblib`) stores the feature order alongside the
  classifier, so `features.py` is the single source of truth shared by training
  and inference — the columns can't drift between the two.
