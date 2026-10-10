#!/usr/bin/env python3
"""
Vulnix — days_to_fix regression (Phase 4).

Trains only on already-resolved remediations. days_to_fix is the LABEL, never a
feature. Same chronological CVE-grouped split and the same feature families as
Experiment A. Writes metrics_reg.json automatically.

Usage:
    python train_regress.py --csv cve_ml_features.csv
"""
import argparse
import json
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestRegressor
import pandas as pd
from sklearn.metrics import mean_absolute_error, mean_squared_error, median_absolute_error

from train import (
    BOOLEAN_EXTERNAL,
    BOOLEAN_INTERNAL,
    CATEGORICAL_INTERNAL,
    CONFIG_EXTERNAL,
    CONFIG_INTERNAL,
    INFERENCE_COLUMNS,
    NUMERIC_EXTERNAL,
    NUMERIC_INTERNAL,
    SCRIPT_DIR,
    build_pipeline,
    grouped_chronological_split,
    load_data,
    select_config,
    split_summary,
    _json_safe_float,
)

warnings.filterwarnings("ignore", category=UserWarning)

try:
    from xgboost import XGBRegressor
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

DEFAULT_MODEL_OUT = SCRIPT_DIR / "artifacts" / "regressor.joblib"
DEFAULT_METRICS_OUT = SCRIPT_DIR / "artifacts" / "metrics_reg.json"


def evaluate_reg(pipeline, X, y, label: str) -> dict:
    if len(y) == 0:
        print(f"  [{label}] Skipped - empty split.")
        return {"skipped": True, "reason": "empty split", "mae": None, "rmse": None, "n": 0}
    pred = np.clip(pipeline.predict(X), 0, None)
    mae = mean_absolute_error(y, pred)
    rmse = float(np.sqrt(mean_squared_error(y, pred)))
    print(f"  [{label}] MAE={mae:.3f}  RMSE={rmse:.3f}  n={len(y)}")
    return {
        "skipped": False,
        "reason": None,
        "mae": _json_safe_float(mae),
        "median_ae": _json_safe_float(median_absolute_error(y, pred)),
        "rmse": _json_safe_float(rmse),
        "n": int(len(y)),
    }


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
    fitted = {}
    print(f"\n=== {model_name} ===")
    for label, (num_cols, cat_cols, bool_cols) in configs.items():
        cols = [c for c in num_cols + cat_cols + bool_cols if c != "days_to_fix"]
        pipeline = build_pipeline(model_factory(), num_cols, cat_cols, bool_cols)
        pipeline.fit(train_df[cols], train_df["days_to_fix"])
        print(f" -- {label} -- (validation)")
        val_metrics[label] = evaluate_reg(pipeline, val_df[cols], val_df["days_to_fix"], label + " / val")
        print(f" -- {label} -- (final held-out test)")
        test_metrics[label] = evaluate_reg(pipeline, test_df[cols], test_df["days_to_fix"], label + " / test")
        fitted[label] = pipeline
    return test_metrics, val_metrics, fitted


def write_metrics(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"\nSaved regression metrics to {path}")


def main():
    parser = argparse.ArgumentParser(description="Train days_to_fix regressor. Writes metrics_reg.json automatically.")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--out", default=str(DEFAULT_MODEL_OUT))
    parser.add_argument("--metrics-out", default=str(DEFAULT_METRICS_OUT))
    parser.add_argument("--strict-chrono", action="store_true",
                        help="Purge train/val rows first seen after the start of a later split")
    args = parser.parse_args()

    df = load_data(args.csv)
    if "days_to_fix" not in df.columns:
        print("[ERROR] CSV has no days_to_fix column.", file=sys.stderr)
        return 2
    leaked = [c for c in INFERENCE_COLUMNS if c == "days_to_fix"]
    if leaked:
        print("[ERROR] days_to_fix leaked into inference columns.", file=sys.stderr)
        return 2

    resolved = df[df["days_to_fix"].notna()].copy()
    print(f"Resolved remediations: {len(resolved)} / {len(df)} "
          f"(mean days_to_fix={resolved['days_to_fix'].mean():.2f})")
    if len(resolved) < 20:
        print("[WARNING] Very few resolved rows - MAE will be indicative only.")

    train_frac, val_frac = 0.70, 0.15
    # Same split as the classifier (computed on ALL rows, then restricted to resolved
    # ones) so both models share identical train/val/test boundaries.
    train_all, val_all, test_all = grouped_chronological_split(
        df, train_frac=train_frac, val_frac=val_frac, purge=args.strict_chrono)
    split = split_summary(train_all, val_all, test_all, train_frac, val_frac)
    train_df = train_all[train_all["days_to_fix"].notna()]
    val_df = val_all[val_all["days_to_fix"].notna()]
    test_df = test_all[test_all["days_to_fix"].notna()]
    split.update({
        "subset": "resolved_only",
        "train_rows": int(len(train_df)),
        "val_rows": int(len(val_df)),
        "test_rows": int(len(test_df)),
    })
    print(f"Split (same as classifier, resolved only): "
          f"{len(train_df)} train / {len(val_df)} val / {len(test_df)} test")
    if len(train_df) == 0 or len(val_df) + len(test_df) == 0:
        print("[ERROR] Not enough resolved rows across train and held-out splits.", file=sys.stderr)
        return 2

    warnings_out = []
    distinct_targets = int(resolved["days_to_fix"].nunique())
    if distinct_targets <= 3:
        warnings_out.append(
            f"days_to_fix takes only {distinct_targets} distinct value(s) "
            f"({sorted(resolved['days_to_fix'].unique().tolist())}): the regression has almost no signal "
            f"and MAE is not a reliable uncertainty estimate."
        )
    if len(test_df) < 30:
        warnings_out.append(f"held-out test has only {len(test_df)} resolved rows: a single outlier moves the MAE.")
    for w in warnings_out:
        print(f"[WARNING] {w}")
    if warnings_out:
        print("[WARNING] mae_reliable=false: the product falls back to a fixed 2-day margin instead of this MAE.")

    if HAS_XGBOOST:
        model_name, model_factory = "XGBoostRegressor", lambda: XGBRegressor(
            n_estimators=200, max_depth=4, learning_rate=0.1, random_state=42,
            objective="reg:squarederror")
    else:
        print("[INFO] xgboost not installed - falling back to RandomForestRegressor.")
        model_name, model_factory = "RandomForestRegressor", lambda: RandomForestRegressor(
            n_estimators=300, max_depth=6, random_state=42)

    test_metrics, val_metrics, pipelines = run_ablation(
        train_df, val_df, test_df, model_name, model_factory
    )

    selected, reason = select_config(val_metrics, "mae", higher_is_better=False)
    print(f"\nSelected configuration (on validation): {selected} - {reason}")

    # The MAE used by the product (interval around estimatedDays) is pooled over ALL
    # held-out resolved rows (val + test): more rows than test alone, and never used to fit.
    heldout = pd.concat([val_df, test_df])
    sel_cfg = {
        CONFIG_INTERNAL: (NUMERIC_INTERNAL, CATEGORICAL_INTERNAL, BOOLEAN_INTERNAL),
        CONFIG_EXTERNAL: (NUMERIC_INTERNAL + NUMERIC_EXTERNAL, CATEGORICAL_INTERNAL,
                          BOOLEAN_INTERNAL + BOOLEAN_EXTERNAL),
    }[selected]
    cols = sel_cfg[0] + sel_cfg[1] + sel_cfg[2]
    pooled = evaluate_reg(pipelines[selected], heldout[cols], heldout["days_to_fix"], "selected / val+test")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipelines[selected], out_path)
    print(f"Saved regressor to {out_path}")

    payload = {
        "experiment": "days_to_fix",
        "label_definition": "days between first_seen and disappearance in a later scan",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "csv": str(Path(args.csv).resolve()),
        "model_name": model_name,
        "selected_config": selected,
        "selection_reason": reason,
        "n_resolved": int(len(resolved)),
        "n_all_rows": int(len(df)),
        "mae": pooled.get("mae"),
        "mae_reliable": bool(distinct_targets > 3 and len(heldout) >= 30),
        "mae_basis": "held-out val+test, selected configuration",
        "mae_test_only": (test_metrics.get(selected) or {}).get("mae"),
        "rmse": pooled.get("rmse"),
        "split": split,
        "internal_only": test_metrics.get(CONFIG_INTERNAL),
        "internal_external": test_metrics.get(CONFIG_EXTERNAL),
        "internal_only_val": val_metrics.get(CONFIG_INTERNAL),
        "internal_external_val": val_metrics.get(CONFIG_EXTERNAL),
        "heldout_pooled": pooled,
        "warnings": warnings_out,
        "notes": {
            "days_to_fix_used_as_feature": False,
            "epss_restricted_to_first_seen": True,
            "kev_restricted_to_first_seen": True,
            "product_use": "estimatedDays compared to the client release deadline (Release Readiness).",
        },
    }
    write_metrics(Path(args.metrics_out), payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
