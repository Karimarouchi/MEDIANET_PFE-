#!/usr/bin/env python3
"""
Step 4 - REPAIR the data: fill missing values, then build the anomaly scores.

Everything here is FITTED ON THE TRAIN SPLIT ONLY, then applied to validation and test.

4a. Missing values. Three imputers compete on the same job and the best one is kept:
      * median (baseline)    * KNN (5 nearest packages)    * Random Forest (IterativeImputer / MissForest style)
    Score = normalised RMSE on cells we deliberately hide (10 % of the known values of the
    validation rows) and then try to recover. Lowest error wins.
    Absence of a file is already encoded by explicit indicator columns (has_package_json,
    n_code_files), so imputation never erases that signal.
4b. Anomaly detectors, trained on BENIGN train packages only ("what a normal package looks like"):
      * Isolation Forest      * Auto-encoder (small neural network that learns to rebuild normal packages;
                                a high rebuild error means "unlike anything normal")
    Their scores are added as features for the supervised model. To avoid the classic stacking leak
    (benign train rows would look "more normal" than benign test rows because the detector saw them),
    benign train rows receive OUT-OF-FOLD scores. The detectors are also evaluated on their own
    (can they find malware without ever seeing a malicious example?).
    Highly anomalous BENIGN training packages are written to a review file: they may be
    undiscovered malware in the "benign" sample. They are NOT deleted automatically.

Usage (from ml/):  python supplychain/repair.py
"""
import json
import os
import sys
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestRegressor
from sklearn.experimental import enable_iterative_imputer  # noqa: F401
from sklearn.impute import IterativeImputer, KNNImputer, SimpleImputer
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import KFold, StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")

HERE = Path(__file__).resolve().parent
ECO = os.environ.get("SC_ECO", "npm")
CLEAN = HERE / "data" / ("clean" if ECO == "npm" else f"clean_{ECO}")
ART = HERE / ("artifacts" if ECO == "npm" else f"artifacts_{ECO}")
SEED = 42
ID_COLS = ["name", "label", "kind", "file", "archive_readable", "content_hash", "code_hash", "error",
           "group_id", "split", "mal_type", "meta_text"]


def numeric_columns(df):
    cols = [c for c in df.columns if c not in ID_COLS and pd.api.types.is_numeric_dtype(df[c])]
    return [c for c in cols if df[c].notna().any()]


def log_transform(frame, cols):
    """Counts and sizes are heavy-tailed: log1p keeps order, tames outliers."""
    out = frame.copy()
    for c in cols:
        if c.startswith(("n_", "hook_n", "hook_target", "code_bytes", "max_line_len", "install_script_len", "description_len", "name_len")) \
                or c.endswith("_per_kb"):
            out[c] = np.log1p(out[c].clip(lower=0))
    return out


def impute_error(imputer_factory, train_x, val_x, cols, rng):
    """Normalised RMSE of recovering hidden known cells of the validation rows."""
    std = train_x.std().replace(0, 1)
    known = val_x.notna().to_numpy()
    mask = known & (rng.random(known.shape) < 0.10)
    if mask.sum() == 0:
        return None
    hidden_arr = val_x.to_numpy(dtype=float, copy=True)
    hidden_arr[mask] = np.nan
    hidden = pd.DataFrame(hidden_arr, columns=cols, index=val_x.index)
    imp = imputer_factory()
    imp.fit(train_x.to_numpy(dtype=float, copy=True))
    filled = pd.DataFrame(imp.transform(hidden_arr.copy()), columns=cols, index=val_x.index)
    diff = (filled.to_numpy() - val_x.to_numpy())[mask]
    scale = np.broadcast_to(std.to_numpy(), mask.shape)[mask]
    return float(np.sqrt(np.mean((diff / scale) ** 2)))


def make_autoencoder():
    # 3 hidden layers with a narrow middle (the "bottleneck"): input -> 8 numbers -> input
    return MLPRegressor(hidden_layer_sizes=(32, 8, 32), activation="relu", max_iter=400,
                        early_stopping=True, random_state=SEED)


def reconstruction_error(model, scaler, frame):
    x = scaler.transform(frame)
    return ((model.predict(x) - x) ** 2).mean(axis=1)


def evaluate_detector(name, scores, y):
    if len(set(y)) < 2:
        return {"skipped": True}
    return {"roc_auc": float(roc_auc_score(y, scores)), "pr_auc": float(average_precision_score(y, scores)),
            "n": int(len(y)), "n_malicious": int(sum(y))}


def text_scorers():
    """Two small text models whose OUTPUT becomes a feature for the main model:
       * name_char_score  : which character patterns inside the NAME look malicious
       * meta_text_score  : which words in the package description / keywords / author look malicious"""
    return {
        "name_char_score": (lambda d: d["name"].fillna("").str.lower(),
                            lambda: make_pipeline(
                                TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, sublinear_tf=True,
                                                max_features=120_000),
                                LogisticRegression(C=2.0, max_iter=1000, class_weight="balanced"))),
        "meta_text_score": (lambda d: d["meta_text"].fillna("").str.lower(),
                            lambda: make_pipeline(
                                TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=3, sublinear_tf=True,
                                                max_features=60_000),
                                LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced"))),
    }


def stack_text_scores(tr, va, te):
    """Out-of-fold for train (grouped by campaign, so a campaign never scores itself), fitted-on-train for
    validation/test. Same protection as the anomaly scores: the main model never sees a score produced by a
    model that had already seen that very row."""
    out = {"train": {}, "val": {}, "test": {}}
    report = {}
    y = tr["label"].to_numpy()
    for name, (getter, factory) in text_scorers().items():
        x_tr = getter(tr).reset_index(drop=True)
        oof = np.zeros(len(tr))
        for fit_i, hold_i in StratifiedGroupKFold(5, shuffle=True, random_state=SEED).split(x_tr, y, tr["group_id"]):
            m = factory().fit(x_tr.iloc[fit_i], y[fit_i])
            oof[hold_i] = m.predict_proba(x_tr.iloc[hold_i])[:, 1]
        full = factory().fit(x_tr, y)
        out["train"][name] = oof
        out["val"][name] = full.predict_proba(getter(va))[:, 1]
        out["test"][name] = full.predict_proba(getter(te))[:, 1]
        report[name] = {s: evaluate_detector(name, out[s][name], d["label"].tolist())
                        for s, d in (("val", va), ("test", te))}
        print(f"  {name}: val ROC-AUC={report[name]['val']['roc_auc']:.3f}  test ROC-AUC={report[name]['test']['roc_auc']:.3f}")
    return out, report


def main():
    ART.mkdir(exist_ok=True)
    tr, va, te = (pd.read_csv(CLEAN / f"{s}_raw.csv", keep_default_na=False, na_values=[""], low_memory=False) for s in ("train", "val", "test"))
    cols = numeric_columns(tr)
    X = {k: log_transform(d[cols], cols) for k, d in (("train", tr), ("val", va), ("test", te))}
    report = {"n_features": len(cols), "missing_rate_train": float(X["train"].isna().mean().mean())}
    print(f"{len(cols)} numeric features, {report['missing_rate_train']:.1%} missing cells in train")

    # ---- 4a. imputation contest
    rng = np.random.default_rng(SEED)
    candidates = {
        "median": lambda: SimpleImputer(strategy="median", keep_empty_features=True),
        "knn": lambda: KNNImputer(n_neighbors=5),
        "random_forest": lambda: IterativeImputer(
            estimator=RandomForestRegressor(n_estimators=40, max_depth=8, n_jobs=-1, random_state=SEED),
            max_iter=3, random_state=SEED, keep_empty_features=True),
    }
    errors = {}
    for name, factory in candidates.items():
        errors[name] = impute_error(factory, X["train"], X["val"], cols, np.random.default_rng(SEED))
        print(f"  imputer {name:14s} normalised RMSE = {errors[name]}")
    best = min((n for n in errors if errors[n] is not None), key=lambda n: errors[n], default="median")
    imputer = candidates[best]()
    imputer.fit(X["train"].to_numpy(dtype=float, copy=True))
    report["imputation"] = {"rmse_by_method": errors, "selected": best,
                            "note": "RMSE on 10% hidden known cells of validation rows, normalised by train std"}
    print(f"-> imputer kept: {best}")
    filled = {k: pd.DataFrame(imputer.transform(v.to_numpy(dtype=float, copy=True)), columns=cols, index=v.index) for k, v in X.items()}

    # ---- 4b. anomaly detectors (benign train only)
    benign_train = filled["train"][tr["label"] == 0]
    scaler = StandardScaler().fit(benign_train)

    def fit_detectors(frame):
        iso = IsolationForest(n_estimators=300, random_state=SEED, n_jobs=-1).fit(frame)
        ae = make_autoencoder().fit(scaler.transform(frame), scaler.transform(frame))
        return iso, ae

    def score(iso, ae, frame):
        return -iso.score_samples(frame), reconstruction_error(ae, scaler, frame)

    iso_full, ae_full = fit_detectors(benign_train)
    scores = {}
    for k in ("val", "test"):
        scores[k] = score(iso_full, ae_full, filled[k])
    # train: benign rows out-of-fold, malicious rows scored by the full model
    iso_tr = np.zeros(len(tr))
    ae_tr = np.zeros(len(tr))
    benign_idx = np.where(tr["label"].to_numpy() == 0)[0]
    for fit_i, hold_i in KFold(5, shuffle=True, random_state=SEED).split(benign_idx):
        iso_k, ae_k = fit_detectors(filled["train"].iloc[benign_idx[fit_i]])
        a, b = score(iso_k, ae_k, filled["train"].iloc[benign_idx[hold_i]])
        iso_tr[benign_idx[hold_i]] = a
        ae_tr[benign_idx[hold_i]] = b
    mal_idx = np.where(tr["label"].to_numpy() == 1)[0]
    a, b = score(iso_full, ae_full, filled["train"].iloc[mal_idx])
    iso_tr[mal_idx], ae_tr[mal_idx] = a, b
    scores["train"] = (iso_tr, ae_tr)

    report["unsupervised_detectors"] = {}
    for split_name, frame in (("val", va), ("test", te), ("train_oof", tr)):
        key = "train" if split_name == "train_oof" else split_name
        y = frame["label"].tolist()
        report["unsupervised_detectors"][split_name] = {
            "isolation_forest": evaluate_detector("iso", scores[key][0], y),
            "autoencoder": evaluate_detector("ae", scores[key][1], y),
        }
    print(json.dumps(report["unsupervised_detectors"], indent=2))

    # ---- review list: benign train packages the detectors find most abnormal
    review = tr.loc[tr["label"] == 0, ["name", "kind", "file"]].copy()
    review["iforest_score"] = iso_tr[tr["label"].to_numpy() == 0]
    review["autoencoder_error"] = ae_tr[tr["label"].to_numpy() == 0]
    review = review.sort_values("iforest_score", ascending=False).head(60)
    review.to_csv(CLEAN / "benign_review_candidates.csv", index=False)

    # ---- text scorers (stacked, out-of-fold)
    print("text scorers:")
    text_out, text_report = stack_text_scores(tr, va, te)
    report["text_scorers"] = text_report

    # ---- write model-ready tables
    for k, raw in (("train", tr), ("val", va), ("test", te)):
        out = filled[k].copy()
        out["iforest_score"], out["autoencoder_error"] = scores[k]
        for tname, values in text_out[k].items():
            out[tname] = values
        for c in ("name", "label", "kind", "group_id", "split", "mal_type"):
            out[c] = raw[c].to_numpy()
        out.to_csv(CLEAN / f"{k}_ready.csv", index=False)
    joblib.dump({"imputer": imputer, "columns": cols, "scaler": scaler,
                 "isolation_forest": iso_full, "autoencoder": ae_full}, ART / "preprocessing.joblib")
    (ART / "repair_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("saved tables + preprocessing.joblib + repair_report.json")


if __name__ == "__main__":
    sys.exit(main())
