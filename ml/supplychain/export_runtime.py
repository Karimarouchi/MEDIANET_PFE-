#!/usr/bin/env python3
"""
Package everything needed to score a NEW package into ONE file (artifacts/runtime_bundle.joblib), and
PROVE it behaves exactly like the trained pipeline (parity check on held-out test rows).

Ships to production : runtime_bundle.joblib, known_malicious_npm.json, top_npm.txt (+ the .py files)
Stays on a disk      : data/raw (30,000 training packages, 1.5 GB) - only needed to RE-train.

Usage (from ml/):  python supplychain/export_runtime.py
"""
import hashlib
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import repair as R  # noqa: E402
import runtime  # noqa: E402

ECO = os.environ.get("SC_ECO", "npm")
ART = HERE / ("artifacts" if ECO == "npm" else f"artifacts_{ECO}")
CLEAN = HERE / "data" / ("clean" if ECO == "npm" else f"clean_{ECO}")
RAW = HERE / "data" / "raw"
READ = dict(keep_default_na=False, na_values=[""], low_memory=False)


def build_known_malicious():
    import ossf_extract
    rows = [json.loads(l) for l in (RAW / f"ossf_{ECO}.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    known = ossf_extract.build_known(rows, ECO)
    (ART / f"known_malicious_{ECO}.json").write_text(json.dumps(known, separators=(",", ":")), encoding="utf-8")
    return known


def main():
    pre = joblib.load(ART / "preprocessing.joblib")
    clf = joblib.load(ART / "supplychain_model.joblib")
    tr = pd.read_csv(CLEAN / "train_raw.csv", **READ)

    scorers = {}
    for name, (getter, factory) in R.text_scorers().items():
        scorers[name] = factory().fit(getter(tr).reset_index(drop=True), tr["label"].to_numpy())

    metrics = json.loads((ART / "metrics_supplychain.json").read_text(encoding="utf-8"))
    bundle = {
        "columns_numeric": pre["columns"], "imputer": pre["imputer"], "scaler": pre["scaler"],
        "isolation_forest": pre["isolation_forest"], "autoencoder": pre["autoencoder"],
        "name_scorer": scorers["name_char_score"], "meta_scorer": scorers["meta_text_score"],
        "model": clf["model"], "model_columns": clf["columns"], "tiers": clf["tiers"],
        "meta": {"built_at": datetime.now(timezone.utc).isoformat(), "selected": metrics["selected"]["model"],
                 "training_rows": metrics["rows"]},
    }
    joblib.dump(bundle, ART / "runtime_bundle.joblib")
    known = build_known_malicious()
    top = RAW / f"top_{ECO}.txt"
    if top.exists():
        shutil.copy(top, ART / f"top_{ECO}.txt")
    sha = hashlib.sha256((ART / "runtime_bundle.joblib").read_bytes()).hexdigest()[:16]
    print(f"bundle written ({sha}); known-malicious names: {len(known)}")

    # ---------------- parity: runtime path vs the trained pipeline, on rows the model never trained on
    scorer = runtime.Scorer(ECO)
    te_raw = pd.read_csv(CLEAN / "test_raw.csv", **READ)
    te_ready = pd.read_csv(CLEAN / "test_ready.csv", **READ)
    idx = np.random.default_rng(1).choice(len(te_raw), size=400, replace=False)
    expected = clf["model"].predict_proba(te_ready.loc[idx, clf["columns"]])[:, 1]
    got = np.array([scorer.score_features(te_raw.loc[i].to_dict())["suspicionProba"] for i in idx])
    diff = np.abs(expected - got)
    tier_agree = np.mean([(e >= clf["tiers"]["review"]) == (g >= clf["tiers"]["review"]) for e, g in zip(expected, got)])
    print(f"parity on 400 test rows: max |diff| = {diff.max():.2e}, mean = {diff.mean():.2e}, same alert decision = {tier_agree:.1%}")
    assert diff.max() < 1e-3, "runtime scoring does not reproduce the trained pipeline"
    (ART / "runtime_parity.json").write_text(json.dumps({
        "bundle_sha256_16": sha, "n_rows": 400, "max_abs_diff": float(diff.max()), "mean_abs_diff": float(diff.mean()),
        "same_alert_decision": float(tier_agree)}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
