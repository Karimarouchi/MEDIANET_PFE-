#!/usr/bin/env python3
"""
Vulnix — Experiment A: P(dépassement du seuil de remédiation 15/30/60/90).

These thresholds are a laboratory label definition, not Medianet's release
deadline. The product question (release readiness vs client date) comes later
from the days_to_fix regression. This script only trains the existing
classifier and writes reproducible metrics automatically.

Usage (from repo root or ml/):
    python train.py --csv cve_ml_features.csv
    python train.py --csv cve_ml_features.csv --out artifacts/classifier_expA.joblib

Methodology (do not break these):

  * Predict AT DETECTION TIME. Features are restricted to information available
    on or before first_seen_at. EPSS snapshots are already filtered that way
    in FeatureStoreBuilderService.
  * days_to_fix is a LABEL for the future regressor — never a classifier feature.
    It is derived from the same event as sla_breached; using it as X is leakage.
  * days_to_kev_listing is reduced to kev_known_before_detection (KEV listed at
    or before detection). A positive day count would leak the future.
  * Split is chronological AND grouped by CVE (every row of a CVE stays on one
    side). Random 80/20 is forbidden.
  * External sources (EPSS, KEV) enrich features only. They do not create labels.
    Labels come from Medianet scan history.
"""
import argparse
import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

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

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL_OUT = SCRIPT_DIR / "artifacts" / "classifier_expA.joblib"
DEFAULT_METRICS_OUT = SCRIPT_DIR / "artifacts" / "metrics_expA.json"

LABEL_DEFINITION = "sla_breached vs thresholds CRITICAL=15 HIGH=30 MEDIUM=60 LOW=90"

MEDIANET_NUMERIC = [
    "affected_repo_count",
    "package_occurrence_count",
    "hist_mean_days_cwe",
    "hist_mean_days_ecosystem",
    "hist_mean_days_repo",
    "hist_mean_days_package",
    "dependency_depth",
]
MEDIANET_BOOLEAN = ["direct_dependency", "fix_available"]

NUMERIC_INTERNAL = ["cvss_score", *MEDIANET_NUMERIC]
CATEGORICAL_INTERNAL = ["severity", "cwe_id", "ecosystem"]
BOOLEAN_INTERNAL = ["exploit_available", *MEDIANET_BOOLEAN]

NUMERIC_EXTERNAL = ["epss_score_at_detection", "epss_score_latest", "epss_score_trend",
                     "epss_observation_count"]
BOOLEAN_EXTERNAL = ["kev_listed", "kev_ransomware", "kev_known_before_detection"]

INFERENCE_COLUMNS = (
    NUMERIC_INTERNAL + CATEGORICAL_INTERNAL + BOOLEAN_INTERNAL
    + NUMERIC_EXTERNAL + BOOLEAN_EXTERNAL
)

CONFIG_INTERNAL = "internal only"
CONFIG_EXTERNAL = "internal + external (EPSS/KEV)"

TOP_CWE_COUNT = 12

SKIPPED_METRICS = {
    "skipped": True,
    "reason": "split has only one class (too little data for a real metric)",
    "precision": None,
    "recall": None,
    "f1": None,
    "pr_auc": None,
    "roc_auc": None,
    "confusion": None,
}


def _to_bool(series: pd.Series) -> pd.Series:
    """PostgreSQL COPY exports booleans as 't'/'f'. Naive astype(bool) treats
    the non-empty string 'f' as truthy. Map explicitly instead."""
    if series.dtype == bool:
        return series
    return series.astype(str).str.strip().str.lower().isin(["t", "true", "1"])


def _iso_ts(value) -> str | None:
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return None
    if pd.isna(value):
        return None
    ts = pd.Timestamp(value)
    if pd.isna(ts):
        return None
    return ts.isoformat()


def _json_safe_float(value) -> float | None:
    if value is None:
        return None
    number = float(value)
    if np.isnan(number) or np.isinf(number):
        return None
    return number


def load_data(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, parse_dates=["first_seen_at"])

    for col in MEDIANET_NUMERIC:
        if col not in df.columns:
            df[col] = np.nan
    for col in MEDIANET_BOOLEAN:
        if col not in df.columns:
            df[col] = np.nan

    for col in ["sla_breached", "kev_listed", "kev_ransomware", "exploit_available", *MEDIANET_BOOLEAN]:
        if col in df.columns:
            df[col] = _to_bool(df[col]).astype(int)

    df["kev_known_before_detection"] = (
        (df["kev_listed"] == 1)
        & df["days_to_kev_listing"].notna()
        & (df["days_to_kev_listing"] <= 0)
    ).astype(int)

    top_cwe = df["cwe_id"].value_counts().nlargest(TOP_CWE_COUNT).index
    df.attrs["top_cwe"] = [str(cwe) for cwe in top_cwe]
    df["cwe_id"] = df["cwe_id"].where(df["cwe_id"].isin(top_cwe), other="OTHER")
    df["cwe_id"] = df["cwe_id"].fillna("UNKNOWN")
    df["ecosystem"] = df["ecosystem"].fillna("UNKNOWN")

    return df


def build_pipeline(model, numeric_cols, categorical_cols, boolean_cols):
    numeric_transform = Pipeline([("impute", SimpleImputer(strategy="median", keep_empty_features=True))])
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


def grouped_chronological_split(df: pd.DataFrame, train_frac=0.70, val_frac=0.15, purge=False):
    """Splits by CVE group (every row of a CVE stays on one side), ordered by each
    CVE's earliest detection date, with train/val/test cut at cumulative ROW fractions.

    A CVE seen again later in another repository puts some train rows *after* the
    start of val/test. By default they are kept (and the overlap is reported in the
    metrics JSON). With ``purge=True`` they are dropped so train < val < test strictly;
    on small, clumped datasets this can empty the train set. Purged counts are kept
    in ``train_df.attrs['purged_rows']`` / ``val_df.attrs['purged_rows']``."""
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

    purged_train = purged_val = 0
    if purge and len(test_df):
        test_start = test_df["first_seen_at"].min()
        keep = val_df["first_seen_at"] < test_start
        purged_val = int((~keep).sum())
        val_df = val_df[keep]
    later_start = None
    if len(val_df):
        later_start = val_df["first_seen_at"].min()
    elif len(test_df):
        later_start = test_df["first_seen_at"].min()
    if purge and later_start is not None:
        keep = train_df["first_seen_at"] < later_start
        purged_train = int((~keep).sum())
        train_df = train_df[keep]

    train_df = train_df.copy()
    val_df = val_df.copy()
    train_df.attrs["overlap_rows"] = int(
        (train_df["first_seen_at"] >= later_start).sum()) if later_start is not None else 0
    train_df.attrs["purged_rows"] = purged_train
    val_df.attrs["purged_rows"] = purged_val
    return train_df, val_df, test_df


def select_config(val_metrics: dict, key: str, higher_is_better: bool,
                  fallback_metrics: dict | None = None) -> tuple[str, str]:
    """Pick the feature configuration on the VALIDATION split (never on test).
    External signals are adopted only if they are strictly better; otherwise the
    simpler internal-only model wins. Returns (config, reason)."""
    source = "validation"
    internal = (val_metrics.get(CONFIG_INTERNAL) or {}).get(key)
    external = (val_metrics.get(CONFIG_EXTERNAL) or {}).get(key)
    if (internal is None or external is None) and fallback_metrics:
        source = "grouped CV (validation unusable)"
        internal = (fallback_metrics.get(CONFIG_INTERNAL) or {}).get(key)
        external = (fallback_metrics.get(CONFIG_EXTERNAL) or {}).get(key)
    if internal is None or external is None:
        return CONFIG_INTERNAL, f"{source} {key} unavailable -> simpler internal-only model"
    better = external > internal if higher_is_better else external < internal
    if better:
        return CONFIG_EXTERNAL, f"{source} {key}: external {external:.4f} beats internal {internal:.4f}"
    return CONFIG_INTERNAL, f"{source} {key}: external {external:.4f} does not beat internal {internal:.4f}"


def evaluate(pipeline, X_test, y_test, label: str) -> dict:
    """Return a full metric dict. Never invent 0.0 when the split is unusable."""
    n_positive = int(y_test.sum())
    n_negative = int(len(y_test) - n_positive)
    if y_test.nunique() < 2:
        print(f"  [{label}] Skipped - split has only one class (too little data for a real metric).")
        return {**SKIPPED_METRICS, "n": int(len(y_test)), "n_positive": n_positive, "n_negative": n_negative}

    proba = pipeline.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "skipped": False,
        "reason": None,
        "n": int(len(y_test)),
        "n_positive": n_positive,
        "n_negative": n_negative,
        "precision": _json_safe_float(precision_score(y_test, pred, zero_division=0)),
        "recall": _json_safe_float(recall_score(y_test, pred, zero_division=0)),
        "f1": _json_safe_float(f1_score(y_test, pred, zero_division=0)),
        "pr_auc": _json_safe_float(average_precision_score(y_test, proba)),
        "roc_auc": _json_safe_float(roc_auc_score(y_test, proba)),
        "confusion": confusion_matrix(y_test, pred).tolist(),
    }
    print(f"  [{label}] ROC-AUC={metrics['roc_auc']:.3f}  PR-AUC={metrics['pr_auc']:.3f}  "
          f"precision={metrics['precision']:.3f}  recall={metrics['recall']:.3f}  f1={metrics['f1']:.3f}")
    print(f"           confusion matrix [[TN FP] [FN TP]] = {metrics['confusion']}")
    return metrics


def run_ablation(train_df, val_df, test_df, model_name: str, model_factory):
    configs = {
        CONFIG_INTERNAL: (NUMERIC_INTERNAL, CATEGORICAL_INTERNAL, BOOLEAN_INTERNAL),
        CONFIG_EXTERNAL: (
            NUMERIC_INTERNAL + NUMERIC_EXTERNAL,
            CATEGORICAL_INTERNAL,
            BOOLEAN_INTERNAL + BOOLEAN_EXTERNAL,
        ),
    }

    test_metrics = {}
    val_metrics = {}
    fitted_pipelines = {}
    print(f"\n=== {model_name} ===")
    for label, (num_cols, cat_cols, bool_cols) in configs.items():
        cols = num_cols + cat_cols + bool_cols
        pipeline = build_pipeline(model_factory(), num_cols, cat_cols, bool_cols)
        pipeline.fit(train_df[cols], train_df["sla_breached"])
        print(f" -- {label} -- (validation)")
        val_metrics[label] = evaluate(pipeline, val_df[cols], val_df["sla_breached"], label + " / val")
        print(f" -- {label} -- (final held-out test)")
        test_metrics[label] = evaluate(pipeline, test_df[cols], test_df["sla_breached"], label + " / test")
        fitted_pipelines[label] = pipeline

    internal_auc = (test_metrics.get(CONFIG_INTERNAL) or {}).get("roc_auc")
    external_auc = (test_metrics.get(CONFIG_EXTERNAL) or {}).get("roc_auc")
    if internal_auc is not None and external_auc is not None:
        delta = external_auc - internal_auc
        sign = "+" if delta >= 0 else ""
        print(f"  -> External data changes test ROC-AUC by {sign}{delta:.3f}")

    return test_metrics, val_metrics, fitted_pipelines


def grouped_cv_metrics(df: pd.DataFrame, model_factory, n_splits: int = 5) -> tuple[dict, dict]:
    """Out-of-fold ROC-AUC/PR-AUC with CVE-grouped, stratified folds.

    NOT chronological - it complements the chronological split when that one is
    too small or single-class to say anything (it still never splits one CVE
    across folds, and features are already leak-free by construction). Reported
    separately and labelled as such."""
    from sklearn.model_selection import StratifiedGroupKFold

    configs = {
        CONFIG_INTERNAL: (NUMERIC_INTERNAL, CATEGORICAL_INTERNAL, BOOLEAN_INTERNAL),
        CONFIG_EXTERNAL: (NUMERIC_INTERNAL + NUMERIC_EXTERNAL, CATEGORICAL_INTERNAL,
                          BOOLEAN_INTERNAL + BOOLEAN_EXTERNAL),
    }
    y = df["sla_breached"].reset_index(drop=True)
    groups = df["canonical_id"].reset_index(drop=True)
    out = {}
    oofs = {}
    for label, (num_cols, cat_cols, bool_cols) in configs.items():
        cols = num_cols + cat_cols + bool_cols
        X = df[cols].reset_index(drop=True)
        oof = np.full(len(df), np.nan)
        try:
            folds = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=42)
            for tr, te in folds.split(X, y, groups):
                if y.iloc[tr].nunique() < 2:
                    continue
                pipe = build_pipeline(model_factory(), num_cols, cat_cols, bool_cols)
                pipe.fit(X.iloc[tr], y.iloc[tr])
                oof[te] = pipe.predict_proba(X.iloc[te])[:, 1]
        except ValueError as exc:
            out[label] = {"skipped": True, "reason": str(exc), "roc_auc": None, "pr_auc": None, "n": 0}
            continue
        mask = ~np.isnan(oof)
        oofs[label] = oof[mask]
        if mask.sum() == 0 or y[mask].nunique() < 2:
            out[label] = {"skipped": True, "reason": "no usable out-of-fold predictions",
                          "roc_auc": None, "pr_auc": None, "n": int(mask.sum())}
            continue
        out[label] = {
            "skipped": False,
            "reason": None,
            "n": int(mask.sum()),
            "n_positive": int(y[mask].sum()),
            "n_negative": int((1 - y[mask]).sum()),
            "n_folds": n_splits,
            "roc_auc": _json_safe_float(roc_auc_score(y[mask], oof[mask])),
            "pr_auc": _json_safe_float(average_precision_score(y[mask], oof[mask])),
        }
        print(f"  [grouped CV / {label}] ROC-AUC={out[label]['roc_auc']:.3f}  "
              f"PR-AUC={out[label]['pr_auc']:.3f}  n={out[label]['n']}")
    return out, oofs


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


def _delta_roc_auc(internal_metrics: dict, external_metrics: dict):
    internal_auc = internal_metrics.get("roc_auc")
    external_auc = external_metrics.get("roc_auc")
    if internal_auc is None or external_auc is None:
        return None
    return _json_safe_float(external_auc - internal_auc)


MIN_MINORITY_FOR_AUC = 20


def split_warnings(test_metrics: dict, split_info: dict) -> list[str]:
    """Plain-language caveats written into the JSON so the report cannot overstate."""
    out = []
    for config, m in test_metrics.items():
        n_pos, n_neg = m.get("n_positive"), m.get("n_negative")
        if n_pos is None or n_neg is None:
            continue
        minority = min(n_pos, n_neg)
        if minority < MIN_MINORITY_FOR_AUC:
            out.append(
                f"[{config}] held-out test has only {minority} rows in its minority class "
                f"({n_pos} positive / {n_neg} negative): ROC-AUC, PR-AUC and the internal-vs-external "
                f"delta are not statistically meaningful."
            )
    if split_info.get("train_rows_overlapping_later_split"):
        out.append(
            f"{split_info['train_rows_overlapping_later_split']} train rows were first seen at or after the "
            f"start of the validation/test period (a CVE re-detected in another repository). "
            f"Re-run with --strict-chrono to purge them (may leave very little training data)."
        )
    if split_info.get("purged_train_rows") or split_info.get("purged_val_rows"):
        out.append(
            f"{split_info.get('purged_train_rows', 0)} train / {split_info.get('purged_val_rows', 0)} val rows "
            f"were purged because they were first seen after the start of a later split (strict chronology)."
        )
    return out


def split_summary(train_df, val_df, test_df, train_frac, val_frac) -> dict:
    def bound(frame, fn):
        return _iso_ts(fn(frame["first_seen_at"])) if len(frame) else None

    return {
        "method": "grouped_chronological_cve",
        "train_frac": train_frac,
        "val_frac": val_frac,
        "test_frac": round(1.0 - train_frac - val_frac, 2),
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
        "purged_train_rows": int(train_df.attrs.get("purged_rows", 0)),
        "purged_val_rows": int(val_df.attrs.get("purged_rows", 0)),
        "train_rows_overlapping_later_split": int(train_df.attrs.get("overlap_rows", 0)),
        "train_start": bound(train_df, min),
        "train_end": bound(train_df, max),
        "val_start": bound(val_df, min),
        "val_end": bound(val_df, max),
        "test_start": bound(test_df, min),
        "test_end": bound(test_df, max),
        "train_test_strictly_ordered": bool(
            len(train_df) == 0 or len(test_df) == 0
            or train_df["first_seen_at"].max() < test_df["first_seen_at"].min()
        ),
    }


def write_metrics_exp_a(
    path: Path,
    *,
    csv_path: str,
    model_name: str,
    df: pd.DataFrame,
    split: dict,
    test_metrics: dict,
    val_metrics: dict,
    selected_config: str,
    selection_reason: str,
    bands: dict,
    cv_metrics: dict,
):
    payload = {
        "experiment": "A",
        "label_definition": LABEL_DEFINITION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "csv": str(Path(csv_path).resolve()),
        "model_name": model_name,
        "selected_config": selected_config,
        "selection_reason": selection_reason,
        "dataset": {
            "rows": int(len(df)),
            "distinct_cves": int(df["canonical_id"].nunique()),
            "breach_rate": _json_safe_float(df["sla_breached"].mean()),
            "first_seen_min": _iso_ts(df["first_seen_at"].min()) if len(df) else None,
            "first_seen_max": _iso_ts(df["first_seen_at"].max()) if len(df) else None,
        },
        "split": split,
        "grouped_cv": {
            "note": "CVE-grouped stratified 5-fold, out-of-fold, NOT chronological. "
                    "Complements the chronological split when it is too small / single-class.",
            "internal_only": cv_metrics.get(CONFIG_INTERNAL),
            "internal_external": cv_metrics.get(CONFIG_EXTERNAL),
        },
        "internal_only": test_metrics.get(CONFIG_INTERNAL, dict(SKIPPED_METRICS)),
        "internal_external": test_metrics.get(CONFIG_EXTERNAL, dict(SKIPPED_METRICS)),
        "internal_only_val": val_metrics.get(CONFIG_INTERNAL),
        "internal_external_val": val_metrics.get(CONFIG_EXTERNAL),
        "delta_roc_auc_external_minus_internal": _delta_roc_auc(
            test_metrics.get(CONFIG_INTERNAL, {}),
            test_metrics.get(CONFIG_EXTERNAL, {}),
        ),
        "remediation_bands": bands,
        "warnings": split_warnings(test_metrics, split),
        "notes": {
            "days_to_fix_used_as_feature": False,
            "epss_restricted_to_first_seen": True,
            "kev_restricted_to_first_seen": True,
            "label_is_not_client_release_deadline": True,
            "product_use": (
                "UI may display this probability as a remediation-risk indicator. "
                "The report must call it P(lab SLA threshold breach), not "
                "'probability of a long fix' as an objective definition."
            ),
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nSaved Experiment A metrics to {path}")
    for w in payload["warnings"]:
        print(f"[WARNING] {w}")
    return payload


def compute_band_thresholds(probas, method: str = "heldout_proba_tertiles") -> dict:
    """Tertiles of held-out predicted P(sla_breached). Never invent 0.33 if we can measure."""
    values = np.asarray(probas, dtype=float)
    values = values[np.isfinite(values)]
    if values.size == 0:
        medium_min, high_min = 1.0 / 3.0, 2.0 / 3.0
        method = "fallback_equal_thirds"
    else:
        medium_min, high_min = np.quantile(values, [1.0 / 3.0, 2.0 / 3.0])
        if high_min < medium_min:
            medium_min, high_min = high_min, medium_min
    return {
        "medium_min": _json_safe_float(medium_min),
        "high_min": _json_safe_float(high_min),
        "method": method,
        "n": int(values.size),
    }


def write_inference_meta(path: Path, *, model_name: str, top_cwe: list[str], bands: dict,
                         selected_config: str):
    payload = {
        "experiment": "A",
        "label_definition": LABEL_DEFINITION,
        "model_name": model_name,
        "selected_config": selected_config,
        "feature_columns": INFERENCE_COLUMNS,
        "top_cwe": top_cwe,
        "remediation_bands": bands,
        "days_to_fix_used_as_feature": False,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Saved inference metadata to {path}")


def main():
    parser = argparse.ArgumentParser(
        description="Train Experiment A: P(lab SLA threshold breach). Writes metrics_expA.json automatically."
    )
    parser.add_argument("--csv", required=True, help="Path to cve_ml_features.csv (from /api/ml/features/export.csv)")
    parser.add_argument("--out", default=str(DEFAULT_MODEL_OUT), help="Where to save the trained model")
    parser.add_argument(
        "--metrics-out",
        default=str(DEFAULT_METRICS_OUT),
        help="Where to write reproducible Experiment A metrics (JSON)",
    )
    parser.add_argument("--strict-chrono", action="store_true",
                        help="Purge train/val rows first seen after the start of a later split")
    args = parser.parse_args()

    df = load_data(args.csv)
    print(f"Loaded {len(df)} labeled examples ({df['sla_breached'].mean():.1%} breached) "
          f"spanning {df['first_seen_at'].min()} -> {df['first_seen_at'].max()}")
    print(f"Distinct CVEs: {df['canonical_id'].nunique()} "
          f"(some recur across repos - split keeps every occurrence of a CVE on one side)")
    print("Label = Experiment A lab thresholds (CRIT 15 / HIGH 30 / MED 60 / LOW 90), "
          "not the client release deadline.")

    if len(df) < 50:
        print("\n[WARNING] Very small dataset - metrics below are indicative only, not production-grade.")

    train_frac, val_frac = 0.70, 0.15
    train_df, val_df, test_df = grouped_chronological_split(
        df, train_frac=train_frac, val_frac=val_frac, purge=args.strict_chrono)
    split = split_summary(train_df, val_df, test_df, train_frac, val_frac)
    print(f"\nSplit (grouped by CVE, chronological by first detection, ~70/15/15): "
          f"{len(train_df)} train / {len(val_df)} val / {len(test_df)} test "
          f"(purged {split['purged_train_rows']} train, {split['purged_val_rows']} val)")
    if len(train_df) and len(test_df):
        print(f"  train ends by {train_df['first_seen_at'].max()}, "
              f"test starts from {test_df['first_seen_at'].min()}")

    run_ablation(
        train_df, val_df, test_df, "Baseline: Logistic Regression",
        lambda: LogisticRegression(max_iter=1000, class_weight="balanced"),
    )

    if HAS_XGBOOST:
        model_name, model_factory = "XGBoost", lambda: XGBClassifier(
            n_estimators=200, max_depth=4, learning_rate=0.1, eval_metric="logloss",
            scale_pos_weight=1.0, random_state=42)
    else:
        print("\n[INFO] xgboost not installed - falling back to RandomForestClassifier.")
        model_name, model_factory = "Random Forest", lambda: RandomForestClassifier(
            n_estimators=300, max_depth=6, class_weight="balanced", random_state=42)

    test_metrics, val_metrics, pipelines = run_ablation(
        train_df, val_df, test_df, model_name, model_factory
    )

    print("\nGrouped (CVE) stratified cross-validation - not chronological, complements the tiny split:")
    cv_metrics, cv_oof = grouped_cv_metrics(df, model_factory)

    selected, reason = select_config(val_metrics, "roc_auc", higher_is_better=True,
                                     fallback_metrics=cv_metrics)
    print(f"\nSelected configuration (on validation): {selected} - {reason}")
    if selected == CONFIG_EXTERNAL:
        print_feature_importance(pipelines[selected])

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipelines[selected], out_path)
    print(f"Saved trained model to {out_path}")

    # Bands come from the distribution of out-of-fold probabilities of the selected model
    # (all labelled rows, never fitted on) - a tiny or single-class held-out test would give
    # degenerate tertiles. Fall back to held-out val+test when CV is unusable.
    oof = cv_oof.get(selected)
    if oof is not None and len(oof) >= 30:
        bands = compute_band_thresholds(oof, method="grouped_cv_oof_proba_tertiles")
    else:
        inference_cols = [c for c in INFERENCE_COLUMNS if c in df.columns]
        heldout = pd.concat([val_df, test_df])
        heldout_proba = (pipelines[selected].predict_proba(heldout[inference_cols])[:, 1]
                         if len(heldout) else [])
        bands = compute_band_thresholds(heldout_proba, method="heldout_val_test_proba_tertiles")
    print(f"Remediation bands (tertiles, n={bands['n']}): "
          f"FAIBLE < {bands['medium_min']:.3f} <= MOYEN < {bands['high_min']:.3f} <= ELEVE")

    write_metrics_exp_a(
        Path(args.metrics_out),
        csv_path=args.csv,
        model_name=model_name,
        df=df,
        split=split,
        test_metrics=test_metrics,
        val_metrics=val_metrics,
        selected_config=selected,
        selection_reason=reason,
        bands=bands,
        cv_metrics=cv_metrics,
    )

    write_inference_meta(
        SCRIPT_DIR / "artifacts" / "inference_meta.json",
        model_name=model_name,
        top_cwe=list(df.attrs.get("top_cwe") or []),
        bands=bands,
        selected_config=selected,
    )


if __name__ == "__main__":
    sys.exit(main())
