"""
Train the PhishGuard phishing-URL classifier.

Pipeline:
  1. Load dataset.csv (run generate_dataset.py first).
  2. Vectorize every URL with the shared lexical feature extractor.
  3. Train an XGBoost classifier (falls back to sklearn GradientBoosting if
     xgboost is unavailable).
  4. Evaluate on a held-out test split and write metrics.json.
  5. Serialize the fitted model + feature order to model.joblib.

The serialized artifact is what the FastAPI backend loads at startup.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_score, recall_score,
                             roc_auc_score, f1_score)
from sklearn.model_selection import train_test_split

from features import FEATURE_NAMES, extract_features

HERE = Path(__file__).parent
DATASET = HERE / "dataset.csv"
MODEL_OUT = HERE / "model.joblib"
METRICS_OUT = HERE / "metrics.json"


def build_classifier():
    try:
        from xgboost import XGBClassifier
        clf = XGBClassifier(
            n_estimators=400,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            n_jobs=-1,
            random_state=42,
        )
        return clf, "XGBoost"
    except Exception as e:  # pragma: no cover
        print(f"  xgboost unavailable ({e}); falling back to GradientBoosting")
        from sklearn.ensemble import GradientBoostingClassifier
        return GradientBoostingClassifier(random_state=42), "GradientBoosting"


def main():
    if not DATASET.exists():
        raise SystemExit("dataset.csv not found — run: python generate_dataset.py")

    df = pd.read_csv(DATASET)
    print(f"Loaded {len(df)} rows")

    # Vectorize URLs -> feature matrix.
    feats = [extract_features(u) for u in df["url"].astype(str)]
    X = pd.DataFrame(feats, columns=FEATURE_NAMES)
    y = df["label"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf, name = build_classifier()
    print(f"Training {name} on {len(X_train)} samples...")
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_secs = round(time.time() - t0, 2)

    # Predict + time a single inference for the latency claim.
    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    t1 = time.time()
    _ = clf.predict(X_test.iloc[[0]])
    single_ms = round((time.time() - t1) * 1000, 2)

    metrics = {
        "model": name,
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision": round(float(precision_score(y_test, y_pred)), 4),
        "recall": round(float(recall_score(y_test, y_pred)), 4),
        "f1": round(float(f1_score(y_test, y_pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, y_prob)), 4),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "train_seconds": train_secs,
        "single_inference_ms": single_ms,
    }

    # Feature importances (top signals — useful for the report / dashboard).
    try:
        importances = clf.feature_importances_
        ranked = sorted(zip(FEATURE_NAMES, importances), key=lambda t: -t[1])
        metrics["top_features"] = [
            {"feature": f, "importance": round(float(i), 4)} for f, i in ranked[:10]
        ]
    except Exception:
        pass

    print("\n=== Evaluation ===")
    print(classification_report(y_test, y_pred, target_names=["legit", "phishing"]))
    print(f"Accuracy : {metrics['accuracy']}")
    print(f"ROC-AUC  : {metrics['roc_auc']}")
    print(f"Single inference: {single_ms} ms")

    joblib.dump({"model": clf, "features": FEATURE_NAMES, "algo": name}, MODEL_OUT)
    METRICS_OUT.write_text(json.dumps(metrics, indent=2))
    print(f"\nSaved model -> {MODEL_OUT}")
    print(f"Saved metrics -> {METRICS_OUT}")


if __name__ == "__main__":
    main()
