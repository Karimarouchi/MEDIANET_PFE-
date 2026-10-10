#!/usr/bin/env python3
"""
Score one CVE, or a batch, at detection time.

Reads a JSON object or array on stdin (same feature names as the training CSV,
without days_to_fix / sla_breached). Writes slaBreachProba + remediationBand,
and estimatedDays when the regressor artifact exists. A list loads models once.

Usage:
    python predict.py < features.json
    python predict.py --json features.json
"""
import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

from train import INFERENCE_COLUMNS, _to_bool

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL = SCRIPT_DIR / "artifacts" / "classifier_expA.joblib"
DEFAULT_META = SCRIPT_DIR / "artifacts" / "inference_meta.json"
DEFAULT_REGRESSOR = SCRIPT_DIR / "artifacts" / "regressor.joblib"
DEFAULT_REG_METRICS = SCRIPT_DIR / "artifacts" / "metrics_reg.json"
FORBIDDEN_LABELS = ("days_to_fix", "sla_breached", "sla_threshold_days")


def remediation_band(proba: float, medium_min: float, high_min: float) -> str:
    if proba >= high_min:
        return "ELEVE"
    if proba >= medium_min:
        return "MOYEN"
    return "FAIBLE"


def prepare_features(payload: dict, top_cwe: list[str]) -> dict:
    cleaned = {key: value for key, value in payload.items() if key not in FORBIDDEN_LABELS}
    row = {col: cleaned.get(col) for col in INFERENCE_COLUMNS}

    if row.get("kev_known_before_detection") is None:
        days = cleaned.get("days_to_kev_listing")
        kev = cleaned.get("kev_listed")
        kev_true = str(kev).strip().lower() in {"t", "true", "1"} if kev is not None else False
        row["kev_known_before_detection"] = bool(kev_true and days is not None and float(days) <= 0)

    cwe = row.get("cwe_id") or "UNKNOWN"
    if top_cwe and cwe not in top_cwe and cwe != "UNKNOWN":
        cwe = "OTHER"
    row["cwe_id"] = cwe
    row["ecosystem"] = row.get("ecosystem") or "UNKNOWN"
    return row


def load_bands(meta: dict) -> tuple[float, float, str]:
    bands = meta.get("remediation_bands") or {}
    medium_min = float(bands.get("medium_min") if bands.get("medium_min") is not None else 1.0 / 3.0)
    high_min = float(bands.get("high_min") if bands.get("high_min") is not None else 2.0 / 3.0)
    if high_min < medium_min:
        medium_min, high_min = high_min, medium_min
    return medium_min, high_min, bands.get("method", "fallback_equal_thirds")


def load_regressor(regressor_path: Path, metrics_path: Path):
    if not regressor_path.is_file():
        return None, None
    pipeline = joblib.load(regressor_path)
    mae = None
    if metrics_path.is_file():
        metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
        # Only a trustworthy MAE may drive the product interval. When the regression target
        # is degenerate or the held-out set tiny, the caller falls back to a fixed margin.
        mae = metrics.get("mae") if metrics.get("mae_reliable") else None
    return pipeline, mae


def features_frame(payload: dict, top_cwe: list[str]) -> pd.DataFrame:
    row = prepare_features(payload, top_cwe)
    frame = pd.DataFrame([row], columns=INFERENCE_COLUMNS)
    for col in ["exploit_available", "direct_dependency", "fix_available",
                "kev_listed", "kev_ransomware", "kev_known_before_detection"]:
        if col in frame.columns:
            frame[col] = _to_bool(frame[col]).astype(int)
    return frame


def score_row(payload: dict, classifier, meta: dict, medium_min: float, high_min: float,
              band_method: str, regressor, mae) -> dict:
    frame = features_frame(payload, list(meta.get("top_cwe") or []))
    proba = float(classifier.predict_proba(frame[INFERENCE_COLUMNS])[0, 1])
    result = {
        "slaBreachProba": round(proba, 6),
        "remediationBand": remediation_band(proba, medium_min, high_min),
        "labelDefinition": meta.get("label_definition"),
        "bandMethod": band_method,
        "mediumMin": medium_min,
        "highMin": high_min,
    }
    if regressor is not None:
        days = max(0.0, float(regressor.predict(frame[INFERENCE_COLUMNS])[0]))
        result["estimatedDays"] = round(days, 1)
        result["estimatedDaysMae"] = None if mae is None else round(float(mae), 2)
    return result


def score(payload: dict, model_path: Path, meta_path: Path,
          regressor_path: Path = DEFAULT_REGRESSOR,
          reg_metrics_path: Path = DEFAULT_REG_METRICS) -> dict:
    return score_many([payload], model_path, meta_path, regressor_path, reg_metrics_path)[0]


def score_many(payloads: list[dict], model_path: Path, meta_path: Path,
               regressor_path: Path = DEFAULT_REGRESSOR,
               reg_metrics_path: Path = DEFAULT_REG_METRICS) -> list[dict]:
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    medium_min, high_min, band_method = load_bands(meta)
    classifier = joblib.load(model_path)
    regressor, mae = load_regressor(regressor_path, reg_metrics_path)
    return [
        score_row(payload, classifier, meta, medium_min, high_min, band_method, regressor, mae)
        for payload in payloads
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Predict Experiment A remediation-risk probability.")
    parser.add_argument("--json", help="Path to a JSON feature object or array (default: stdin)")
    parser.add_argument("--model", default=str(DEFAULT_MODEL))
    parser.add_argument("--meta", default=str(DEFAULT_META))
    args = parser.parse_args()

    raw = Path(args.json).read_text(encoding="utf-8-sig") if args.json else sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"error": "empty feature payload"}), file=sys.stderr)
        return 2
    payload = json.loads(raw)
    model = Path(args.model)
    meta = Path(args.meta)
    if isinstance(payload, list):
        if any(not isinstance(item, dict) for item in payload):
            print(json.dumps({"error": "batch payload must be an array of objects"}), file=sys.stderr)
            return 2
        result = score_many(payload, model, meta, DEFAULT_REGRESSOR, DEFAULT_REG_METRICS)
    elif isinstance(payload, dict):
        result = score(payload, model, meta, DEFAULT_REGRESSOR, DEFAULT_REG_METRICS)
    else:
        print(json.dumps({"error": "feature payload must be a JSON object or array"}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
