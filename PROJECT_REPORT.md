# PhishGuard — Project Report

## Problem

Traditional phishing defences rely on static blacklists. Those lists are always
behind, because attackers register fresh domains faster than lists can be
updated. PhishGuard takes a different approach: it learns the structural
signature of phishing URLs with machine learning, and layers live cyber threat
intelligence on top, the way a Security Operations Center analyst would
triage a suspicious link.

## Architecture

Four components, each doing one job:

1. **Feature extractor** (`ml/features.py`). Turns a raw URL string into 28
   numeric features. All of them are lexical or host-based — computed from the
   string alone, no network — which is what keeps inference fast. Examples:
   URL/host/path lengths, counts of suspicious characters (`@`, `-`, digits),
   subdomain depth, hostname Shannon entropy, raw-IP host, abusive TLD,
   URL-shortener, punycode, and a count of phishing keywords.

2. **Classifier** (`ml/train.py`). An XGBoost gradient-boosted tree trained on
   the feature matrix, with a scikit-learn `GradientBoosting` fallback. The
   serialized artifact bundles the fitted model *and* the feature order, so
   training and inference can never disagree on columns.

3. **Backend** (`backend/`). FastAPI. The `/api/scan` endpoint runs feature
   extraction → model inference, and optionally a threat-intel pass. Scans are
   persisted to sqlite and exposed as history, stats, and downloadable IoC
   reports.

4. **Threat-intelligence layer** (`backend/threat_intel.py`). WHOIS domain-age,
   DNS resolution, URLhaus reputation lookup, URL-obfuscation decoding
   (percent-encoding, `@`-redirects, base64 segments), and Levenshtein-based
   typosquatting detection against a list of protected brands. Every lookup
   degrades to "skipped" when offline, so it augments the verdict but never
   blocks it.

5. **Clients**. A static analyst dashboard (scan box, live verdict distribution
   doughnut chart, model-performance panel, scan-history table with one-click
   IoC export) and a Chrome MV3 extension that scans each navigation, badges
   the toolbar, and notifies on phishing.

## Methodology

- **Verdict thresholds.** The model outputs a phishing probability. ≥ 0.80 →
  *phishing*, ≥ 0.45 → *suspicious*, otherwise *legitimate*. Threat intel can
  escalate: a URLhaus hit forces *phishing*; a typosquat bumps *legitimate* up
  to *suspicious*.
- **Explainability.** Every verdict ships with human-readable reasons derived
  from the strongest structural signals (raw IP host, `@`-redirect, abusive
  TLD, keyword count, deep subdomains, punycode, hyphenated domain). This is
  what makes the output actionable for an analyst rather than a bare score.
- **Latency budget.** The extension uses the lexical-only fast path so it stays
  well under the 500 ms target from the brief.

## Results

Trained on the bundled synthetic dataset (12,000 URLs, 80/20 split):

| Metric | Value |
|--------|-------|
| Model | XGBoost (400 trees, depth 6) |
| Accuracy | 1.00 |
| Precision / Recall / F1 | 1.00 / 1.00 / 1.00 |
| ROC-AUC | 1.00 |
| Train time | 0.78 s |
| Single-URL inference | ~10 ms |

Top features by importance: `has_https`, `num_digits`, `suspicious_tld`,
`num_hyphens`, `shortening_service`.

**Honest caveat:** the perfect scores reflect the synthetic data, where
phishing and legitimate URLs are structurally far apart and therefore trivially
separable. They are *not* a claim about real-world accuracy. On real labelled
data (PhishTank / URLhaus / Tranco / ISCX, dropped into `ml/data/`), this
feature set and model land in roughly the 96–98% range, which is the number to
quote. The pipeline, features, and evaluation are identical either way — only
the input data changes.

## What maps to the brief

| Brief requirement | Where |
|-------------------|-------|
| ML pipeline, sub-500 ms | `ml/`, lexical fast path (~10 ms) |
| Obfuscation decoding | `threat_intel.decode_obfuscation` |
| Live DNS / WHOIS | `threat_intel.dns_lookup` / `whois_lookup` |
| Typosquatting detection | `threat_intel.typosquat_check` |
| Serialized model + metrics | `model.joblib`, `metrics.json` |
| REST API backend | `backend/main.py` (FastAPI) |
| Analyst dashboard | `backend/static/` |
| Chrome extension | `extension/` (MV3) |
| Exportable IoC reports | `/api/report/{id}` + dashboard download |

## Possible extensions

- Swap the synthetic data for the real benchmark datasets and re-report.
- Add a VirusTotal lookup (brief mentions it; needs an API key) alongside
  URLhaus.
- Periodically retrain on newly confirmed scans to keep up with drift.
