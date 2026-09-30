#!/usr/bin/env python3
"""
Vulnix - Phase 3: SLA-breach risk model training.

Reads the feature store CSV exported by the backend (GET /api/ml/features/export.csv,
built from Phase 0 internal labels + Phase 1/2 external EPSS/KEV enrichment), trains
a baseline model and a stronger model, and reports an ablation study comparing
"internal features only" against "internal + external data" - the actual evidence
that combining both data sources is worth the added complexity, not just a claim.

Usage:
    python train.py --csv cve_ml_features.csv
    python train.py --csv cve_ml_features.csv --out model.joblib

Methodology notes (read before touching the feature list):

  * The model must predict AT DETECTION TIME. Every feature is therefore restricted to
    information available on or before `first_seen_at` for that row - nothing derived
    from what happened afterwards. On the backend side, epss_score_latest/epss_score_trend
    are already computed this way (only EPSS snapshots dated <= first_seen_at). `days_to_fix`
    is excluded entirely - it is computed from the exact same event as the label
    (sla_breached), so including it would let the model read the answer instead of
    learning to predict it.

  * `days_to_kev_listing` is reduced to a binary `kev_known_before_detection` flag (true
    only when KEV-listing happened at or before detection). A positive day count would
    mean the model is being handed information from the future relative to detection;
    the binary keeps the genuinely useful signal ("already a known-exploited
    vulnerability when we found it") without that leak.

  * The train/validation/test split is CHRONOLOGICAL AND GROUPED BY CVE, not a random
    80/20. Two things matter here:
      1. Chronological: the model learns on the past and is evaluated on the future,
         which is how it will actually be used. A random split lets it "see the future".
      2. Grouped by CVE: the same CVE/package pair often appears in several repos (we
         observed some CVEs recurring across up to 4 repos). If two rows of the same CVE
         ended up on different sides of the split, the model could partly memorize that
         specific CVE's behaviour rather than generalize - inflating the test score
         without the model having actually learned anything general. Every row of a given
         CVE is therefore kept on the same side of the split, and the split boundary is
         still chosen chronologically (by each CVE's earliest detection date).
"""
import argparse
import sys
import warnings

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score, confusion_matrix, f1_score,
    precision_score, recall_score, roc_auc_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

warnings.filterwarnings("ignore", category=UserWarning)

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

NUMERIC_INTERNAL = ["cvss_score"]
CATEGORICAL_INTERNAL = ["severity", "cwe_id", "ecosystem"]
BOOLEAN_INTERNAL = ["exploit_available"]

NUMERIC_EXTERNAL = ["epss_score_at_detection", "epss_score_latest", "epss_score_trend",
                     "epss_observation_count"]
BOOLEAN_EXTERNAL = ["kev_listed", "kev_ransomware", "kev_known_before_detection"]

TOP_CWE_COUNT = 12  # collapse rare CWEs into "OTHER" to avoid an explosion of sparse one-hot columns


def _to_bool(series: pd.Series) -> pd.Series:
    """PostgreSQL's COPY exports booleans as the literal text 't'/'f' - naively calling
    .astype(bool) on that treats the non-empty string 'f' as truthy (Python string
    semantics), silently turning every False into True. Map explicitly instead."""
    if series.dtype == bool:
        return series
    return series.astype(str).str.strip().str.lower().isin(["t", "true", "1"])


def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, parse_dates=["first_seen_at"])

    for col in ["sla_breached", "kev_listed", "kev_ransomware", "exploit_available"]:
        df[col] = _to_bool(df[col]).astype(int)

    df["kev_known_before_detection"] = (
        (df["kev_listed"] == 1)
        & df["days_to_kev_listing"].notna()
        & (df["days_to_kev_listing"] <= 0)
    ).astype(int)

    top_cwe = df["cwe_id"].value_counts().nlargest(TOP_CWE_COUNT).index
    df["cwe_id"] = df["cwe_id"].where(df["cwe_id"].isin(top_cwe), other="OTHER")
    df["cwe_id"] = df["cwe_id"].fillna("UNKNOWN")
    df["ecosystem"] = df["ecosystem"].fillna("UNKNOWN")

    return df


def build_pipeline(model, numeric_cols, categorical_cols, boolean_cols):
    numeric_transform = Pipeline([("impute", SimpleImputer(strategy="median"))])
    categorical_transform = Pipeline([
        ("impute", SimpleImputer(strategy="constant", fill_value="UNKNOWN")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])
    boolean_transform = Pipeline([("impute", SimpleImputer(strategy="constant", fill_value=0))])

    preprocessor = ColumnTransformer([
        ("num", numeric_transform, numeric_cols),
        ("cat", categorical_transform, categorical_cols),
        ("bool", boolean_transform, boolean_cols),
    ])
    return Pipeline([("prep", preprocessor), ("model", model)])


def grouped_chronological_split(df: pd.DataFrame, train_frac=0.70, val_frac=0.15):
    """Splits by CVE group (every row of a CVE stays on one side), ordered by each
    CVE's earliest detection date, with train/val/test cut at cumulative ROW fractions."""
    first_seen_per_cve = df.groupby("canonical_id")["first_seen_at"].min().sort_values()
    counts_per_cve = df["canonical_id"].value_counts()

    ordered_cves = first_seen_per_cve.index.tolist()
    total_rows = len(df)
    cum_rows = 0
    train_cves, val_cves, test_cves = [], [], []
    for cve in ordered_cves:
        cum_rows += counts_per_cve[cve]
        frac_so_far = cum_rows / total_rows
        if frac_so_far <= train_frac:
            train_cves.append(cve)
        elif frac_so_far <= train_frac + val_frac:
            val_cves.append(cve)
        else:
            test_cves.append(cve)

    train_df = df[df["canonical_id"].isin(train_cves)].copy()
    val_df = df[df["canonical_id"].isin(val_cves)].copy()
    test_df = df[df["canonical_id"].isin(test_cves)].copy()
    return train_df, val_df, test_df


def evaluate(pipeline, X_test, y_test, label: str):
    if y_test.nunique() < 2:
        print(f"  [{label}] Skipped - test split has only one class (too little data for a real metric).")
        return None
    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    auc = roc_auc_score(y_test, proba)
    pr_auc = average_precision_score(y_test, proba)
    precision = precision_score(y_test, pred, zero_division=0)
    recall = recall_score(y_test, pred, zero_division=0)
    f1 = f1_score(y_test, pred, zero_division=0)
    cm = confusion_matrix(y_test, pred)
    print(f"  [{label}] ROC-AUC={auc:.3f}  PR-AUC={pr_auc:.3f}  "
          f"precision={precision:.3f}  recall={recall:.3f}  f1={f1:.3f}")
    print(f"           confusion matrix [[TN FP] [FN TP]] = {cm.tolist()}")
    return auc


def run_ablation(train_df, val_df, test_df, model_name: str, model_factory):
    configs = {
        "internal only": (NUMERIC_INTERNAL, CATEGORICAL_INTERNAL, BOOLEAN_INTERNAL),
        "internal + external (EPSS/KEV)": (
            NUMERIC_INTERNAL + NUMERIC_EXTERNAL,
            CATEGORICAL_INTERNAL,
            BOOLEAN_INTERNAL + BOOLEAN_EXTERNAL,
        ),
    }

    results = {}
    fitted_pipelines = {}
    print(f"\n=== {model_name} ===")
    for label, (num_cols, cat_cols, bool_cols) in configs.items():
        cols = num_cols + cat_cols + bool_cols
        pipeline = build_pipeline(model_factory(), num_cols, cat_cols, bool_cols)
        pipeline.fit(train_df[cols], train_df["sla_breached"])
        print(f" -- {label} -- (validation)")
        evaluate(pipeline, val_df[cols], val_df["sla_breached"], label + " / val")
        print(f" -- {label} -- (final held-out test)")
        auc = evaluate(pipeline, test_df[cols], test_df["sla_breached"], label + " / test")
        results[label] = auc
        fitted_pipelines[label] = pipeline

    if results.get("internal only") is not None and results.get("internal + external (EPSS/KEV)") is not None:
        delta = results["internal + external (EPSS/KEV)"] - results["internal only"]
        sign = "+" if delta >= 0 else ""
        print(f"  -> External data changes test ROC-AUC by {sign}{delta:.3f}")

    return results, fitted_pipelines


def print_feature_importance(pipeline, top_n=10):
    model = pipeline.named_steps["model"]
    if not hasattr(model, "feature_importances_"):
        return
    try:
        feature_names = pipeline.named_steps["prep"].get_feature_names_out()
    except Exception:
        return
    importances = model.feature_importances_
    order = np.argsort(importances)[::-1][:top_n]
    print("\nTop feature importances (internal + external model):")
    for idx in order:
        print(f"  {feature_names[idx]:<40s} {importances[idx]:.4f}")


def main():
    parser = argparse.ArgumentParser(description="Train the Vulnix SLA-breach risk model.")
    parser.add_argument("--csv", required=True, help="Path to cve_ml_features.csv (from /api/ml/features/export.csv)")
    parser.add_argument("--out", default="model.joblib", help="Where to save the trained model")
    args = parser.parse_args()

    df = load_data(args.csv)
    print(f"Loaded {len(df)} labeled examples ({df['sla_breached'].mean():.1%} breached) "
          f"spanning {df['first_seen_at'].min()} -> {df['first_seen_at'].max()}")
    print(f"Distinct CVEs: {df['canonical_id'].nunique()} "
          f"(some recur across repos - split keeps every occurrence of a CVE on one side)")

    if len(df) < 50:
        print("\n[WARNING] Very small dataset - metrics below are indicative only, not production-grade.")

    train_df, val_df, test_df = grouped_chronological_split(df)
    print(f"\nSplit (grouped by CVE, chronological, ~70/15/15): "
          f"{len(train_df)} train / {len(val_df)} val / {len(test_df)} test")
    print(f"  train ends by {train_df['first_seen_at'].max()}, "
          f"test starts from {test_df['first_seen_at'].min()}")

    _, log_reg_pipelines = run_ablation(train_df, val_df, test_df, "Baseline: Logistic Regression",
                                         lambda: LogisticRegression(max_iter=1000, class_weight="balanced"))

    if HAS_XGBOOST:
        model_name, model_factory = "XGBoost", lambda: XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.1, eval_metric="logloss",
            scale_pos_weight=1.0, random_state=42)
    else:
        print("\n[INFO] xgboost not installed - falling back to RandomForestClassifier.")
        model_name, model_factory = "Random Forest", lambda: RandomForestClassifier(
            n_estimators=300, max_depth=6, class_weight="balanced", random_state=42)

    _, best_pipelines = run_ablation(train_df, val_df, test_df, model_name, model_factory)
    print_feature_importance(best_pipelines["internal + external (EPSS/KEV)"])

    joblib.dump(best_pipelines["internal + external (EPSS/KEV)"], args.out)
    print(f"\nSaved trained model to {args.out}")


if __name__ == "__main__":
    sys.exit(main())
