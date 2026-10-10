"""Trains the final secret-triage model on all of CredData and exports the runtime bundle.

Steps: cross-fitted (grouped by repo) scores -> isotonic calibration -> tier thresholds -> final fit on everything.
Run from ml/:  python secrets/export.py
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, brier_score_loss, roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402
import evaluate as E  # noqa: E402
import features as F  # noqa: E402

ART = Path(__file__).resolve().parent / "artifacts"
VERSION = "secrets-v1"
FALSE_RECALL = 0.99      # "probablement faux positif" only below the score that still keeps 99% of the real secrets
REAL_PRECISION = 0.95    # "probablement réel" from the score where >= 95% of the flagged are real


def xgb_params():
    return dict(n_estimators=900, max_depth=7, learning_rate=0.03, min_child_weight=2, colsample_bytree=0.6, gamma=0.1)


def real_from_threshold(y: np.ndarray, p: np.ndarray, precision: float) -> float:
    order = np.argsort(-p)
    ys = y[order]
    cum_prec = np.cumsum(ys) / (np.arange(len(ys)) + 1)
    ok = np.where(cum_prec >= precision)[0]
    if len(ok) == 0:
        return 1.01  # never confident enough
    return float(p[order][ok.max()])


def main() -> int:
    ART.mkdir(exist_ok=True)
    raw = pd.read_pickle(Path(r"E:\MEDIANET ML\secrets\creddata_records.pkl"))
    df = D.gitleaks_view(D.clean(raw))
    X = F.featurize(df, use_rule=False)
    y = df["y"].to_numpy()
    g = df["repo"].to_numpy()
    cols = list(X.columns)

    # 1. cross-fitted scores: every row is scored by a model that never saw its repository
    oof = np.zeros(len(df))
    for fold, (tr, te) in enumerate(StratifiedGroupKFold(5, shuffle=True, random_state=0).split(X, y, g)):
        clf = E._xgb_cfg(X.iloc[tr], y[tr], **xgb_params())
        oof[te] = clf.predict_proba(X.iloc[te])[:, 1]
        print(f"fold {fold + 1}/5")

    # 2. calibration + thresholds on the cross-fitted scores
    iso = IsotonicRegression(out_of_bounds="clip").fit(oof, y)
    p = iso.predict(oof)
    t_false = E.threshold_for_recall(y, p, FALSE_RECALL)
    t_real = real_from_threshold(y, p, REAL_PRECISION)
    verdict = np.where(p < t_false, "LIKELY_FALSE_POSITIVE", np.where(p >= t_real, "LIKELY_REAL", "REVIEW"))
    tiers = {}
    for v in ("LIKELY_FALSE_POSITIVE", "REVIEW", "LIKELY_REAL"):
        m = verdict == v
        tiers[v] = {"n": int(m.sum()), "share": float(m.mean()), "real_share": float(y[m].mean()) if m.any() else None,
                    "real_kept": int(y[m].sum())}
    metrics = {
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": {"name": "CredData (Samsung)", "rows": int(len(df)), "repos": int(df['repo'].nunique()),
                    "real_share": float(y.mean()), "view": "gitleaks (match + value + path, no context)"},
        "cross_fitted": {"roc_auc": float(roc_auc_score(y, oof)), "pr_auc": float(average_precision_score(y, oof)),
                         "brier_calibrated": float(brier_score_loss(y, p)),
                         "brier_raw": float(brier_score_loss(y, oof))},
        "thresholds": {"likely_false_below": float(t_false), "likely_real_from": float(t_real),
                       "false_recall_target": FALSE_RECALL, "real_precision_target": REAL_PRECISION},
        "tiers": tiers,
        "note": "thresholds and calibration are fitted on the cross-fitted scores (optimistic by a small margin); "
                "the honest nested numbers are in results/comparaison_*_gitleaks.csv",
    }

    # 3. final model on everything
    final = E._xgb_cfg(X, y, **xgb_params())
    joblib.dump({"model": final, "isotonic": iso, "columns": cols, "version": VERSION,
                 "thresholds": {"likely_false_below": float(t_false), "likely_real_from": float(t_real)}},
                ART / "secret_triage.joblib")
    (ART / "metrics.json").write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(metrics["thresholds"]), json.dumps(tiers, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
