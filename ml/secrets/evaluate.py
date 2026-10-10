"""Honest evaluation of secret-triage models on CredData.

* grouped by repository (no repo is ever in both train and test), repeated over several seeds;
* the decision threshold is chosen on held-out *training* repos to keep >= TARGET_RECALL of the real secrets, then
  applied untouched on the test repos: we report the recall actually obtained and the share of false positives removed;
* cluster bootstrap over repositories for confidence intervals.
Run from ml/:  python secrets/evaluate.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402
import features as F  # noqa: E402

TARGET_RECALL = 0.98
RESULTS_DIR = Path(__file__).resolve().parent / "results"


# ───────────────────────── models: fit(train_df, X_train, y) -> scorer(df, X) ─────────────────────────

def model_all_real(df_tr, X_tr, y_tr):
    """What a scanner does today: everything is reported as a secret."""
    return lambda df, X: np.ones(len(df))


def model_entropy(df_tr, X_tr, y_tr):
    return lambda df, X: X["v_entropy"].to_numpy()


def model_rules(df_tr, X_tr, y_tr):
    """Hand rules a human would write: placeholder / variable / example / test-looking => unlikely real."""
    def score(df, X):
        s = 1.0
        s = s - 0.5 * X["v_placeholder"] - 0.4 * X["v_var_ref"] - 0.3 * X["p_example"] - 0.2 * X["p_doc"]
        s = s - 0.3 * X["v_looks_word"] - 0.2 * X["l_has_example_word"] - 0.2 * X["v_hexlen_hash"]
        s = s + 0.2 * X["v_known_prefix"] + 0.0003 * X["v_entropy"]
        return s.to_numpy()
    return score


def model_logreg(df_tr, X_tr, y_tr):
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), min_df=3, max_features=60000, sublinear_tf=True)
    T = vec.fit_transform([F.masked_text(r) for r in df_tr.to_dict("records")])
    sc = StandardScaler()
    N = sc.fit_transform(X_tr.clip(-50, 500).to_numpy())
    clf = LogisticRegression(C=0.5, max_iter=400, class_weight="balanced", solver="liblinear")
    clf.fit(sparse.hstack([T, sparse.csr_matrix(N)]).tocsr(), y_tr)

    def score(df, X):
        t = vec.transform([F.masked_text(r) for r in df.to_dict("records")])
        n = sc.transform(X.clip(-50, 500).to_numpy())
        return clf.predict_proba(sparse.hstack([t, sparse.csr_matrix(n)]).tocsr())[:, 1]
    return score


def _xgb(X_tr, y_tr, seed=0):
    import xgboost as xgb
    pos = max(int(y_tr.sum()), 1)
    clf = xgb.XGBClassifier(
        n_estimators=400, max_depth=5, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
        min_child_weight=3, reg_lambda=2.0, scale_pos_weight=(len(y_tr) - pos) / pos, eval_metric="logloss",
        n_jobs=4, random_state=seed, tree_method="hist")
    clf.fit(X_tr, y_tr)
    return clf


def model_xgb(df_tr, X_tr, y_tr):
    clf = _xgb(X_tr, y_tr)
    return lambda df, X: clf.predict_proba(X)[:, 1]


def model_xgb_norule(df_tr, X_tr, y_tr):
    cols = [c for c in X_tr.columns if not c.startswith("r_")]
    clf = _xgb(X_tr[cols], y_tr)
    return lambda df, X: clf.predict_proba(X[cols])[:, 1]


def model_xgb_nopath(df_tr, X_tr, y_tr):
    cols = [c for c in X_tr.columns if not c.startswith("p_")]
    clf = _xgb(X_tr[cols], y_tr)
    return lambda df, X: clf.predict_proba(X[cols])[:, 1]


def _xgb_cfg(X_tr, y_tr, seed=0, **kw):
    import xgboost as xgb
    pos = max(int(y_tr.sum()), 1)
    params = dict(n_estimators=400, max_depth=5, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8,
                  min_child_weight=3, reg_lambda=2.0, scale_pos_weight=(len(y_tr) - pos) / pos,
                  eval_metric="logloss", n_jobs=4, random_state=seed, tree_method="hist")
    params.update(kw)
    clf = xgb.XGBClassifier(**params)
    clf.fit(X_tr, y_tr)
    return clf


def model_xgb_deep(df_tr, X_tr, y_tr):
    clf = _xgb_cfg(X_tr, y_tr, n_estimators=900, max_depth=7, learning_rate=0.03, min_child_weight=2,
                   colsample_bytree=0.6, gamma=0.1)
    return lambda df, X: clf.predict_proba(X)[:, 1]


def model_xgb_shallow(df_tr, X_tr, y_tr):
    clf = _xgb_cfg(X_tr, y_tr, n_estimators=600, max_depth=3, learning_rate=0.05, min_child_weight=5)
    return lambda df, X: clf.predict_proba(X)[:, 1]


def model_blend(df_tr, X_tr, y_tr):
    """Average of the n-gram logistic regression and XGBoost probabilities: the two see different things."""
    lr = model_logreg(df_tr, X_tr, y_tr)
    xg = model_xgb_deep(df_tr, X_tr, y_tr)
    return lambda df, X: 0.35 * lr(df, X) + 0.65 * xg(df, X)


MODELS = {
    "xgboost_profond": model_xgb_deep,
    "xgboost_peu_profond": model_xgb_shallow,
    "melange_logreg_xgboost": model_blend,
    "gitleaks_tout_reel": model_all_real,
    "entropie_seule": model_entropy,
    "regles_a_la_main": model_rules,
    "regression_logistique": model_logreg,
    "xgboost": model_xgb,
    "xgboost_sans_regle_detecteur": model_xgb_norule,
    "xgboost_sans_chemin": model_xgb_nopath,
}


# ───────────────────────── metrics ─────────────────────────

def threshold_for_recall(y: np.ndarray, s: np.ndarray, target: float) -> float:
    """Largest threshold keeping >= target of the positives above it (ties kept)."""
    pos = np.sort(s[y == 1])
    if len(pos) == 0:
        return -np.inf
    k = int(np.floor((1 - target) * len(pos)))
    return float(pos[k]) if k < len(pos) else float(pos[-1])


def operating_point(y: np.ndarray, s: np.ndarray, thr: float) -> dict:
    keep = s >= thr
    tp = int((keep & (y == 1)).sum())
    fn = int((~keep & (y == 1)).sum())
    fp = int((keep & (y == 0)).sum())
    tn = int((~keep & (y == 0)).sum())
    return {"recall_reel": tp / max(tp + fn, 1), "faux_positifs_ecartes": tn / max(tn + fp, 1),
            "precision": tp / max(tp + fp, 1), "tp": tp, "fn": fn, "fp": fp, "tn": tn}


def run(df: pd.DataFrame, X: pd.DataFrame, names, seeds=(0, 1, 2), n_splits=5, log=print):
    y = df["y"].to_numpy()
    g = df["repo"].to_numpy()
    out = {n: {"auc": [], "pr_auc": [], "recall": [], "fp_removed": [], "oof": []} for n in names}
    for seed in seeds:
        skf = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
        oof_scores = {n: np.zeros(len(df)) for n in names}
        oof_keep = {n: np.zeros(len(df), dtype=bool) for n in names}
        for fold, (tr, te) in enumerate(skf.split(X, y, g)):
            inner = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed * 100 + fold)
            itr, iva = next(inner.split(tr, y[tr], g[tr]))
            itr, iva = tr[itr], tr[iva]
            for n in names:
                t0 = time.time()
                scorer = MODELS[n](df.iloc[itr], X.iloc[itr], y[itr])
                thr = threshold_for_recall(y[iva], scorer(df.iloc[iva], X.iloc[iva]), TARGET_RECALL)
                s_te = scorer(df.iloc[te], X.iloc[te])
                oof_scores[n][te] = s_te
                oof_keep[n][te] = s_te >= thr
            log(f"  seed {seed} fold {fold + 1}/{n_splits} done")
        for n in names:
            s = oof_scores[n]
            auc = roc_auc_score(y, s) if len(np.unique(s)) > 1 else 0.5
            pr = average_precision_score(y, s)
            k = oof_keep[n]
            rec = (k & (y == 1)).sum() / max((y == 1).sum(), 1)
            rem = (~k & (y == 0)).sum() / max((y == 0).sum(), 1)
            out[n]["auc"].append(float(auc))
            out[n]["pr_auc"].append(float(pr))
            out[n]["recall"].append(float(rec))
            out[n]["fp_removed"].append(float(rem))
            if seed == seeds[0]:
                out[n]["oof"] = (s, k)
    return out


def cluster_bootstrap(df: pd.DataFrame, keep: np.ndarray, n_boot=500, seed=0) -> dict:
    """95% CI of recall / FP-removed by resampling repositories (the unit that varies in practice)."""
    rng = np.random.default_rng(seed)
    y = df["y"].to_numpy()
    repos = df["repo"].to_numpy()
    uniq = np.unique(repos)
    idx_by = {r: np.where(repos == r)[0] for r in uniq}
    rec, rem = [], []
    for _ in range(n_boot):
        pick = rng.choice(uniq, size=len(uniq), replace=True)
        ii = np.concatenate([idx_by[r] for r in pick])
        yy, kk = y[ii], keep[ii]
        if (yy == 1).sum() == 0 or (yy == 0).sum() == 0:
            continue
        rec.append((kk & (yy == 1)).sum() / (yy == 1).sum())
        rem.append((~kk & (yy == 0)).sum() / (yy == 0).sum())
    lo = lambda a: float(np.percentile(a, 2.5))
    hi = lambda a: float(np.percentile(a, 97.5))
    return {"recall": [lo(rec), hi(rec)], "fp_removed": [lo(rem), hi(rem)]}


def summarize(out: dict, df: pd.DataFrame) -> list[dict]:
    rows = []
    for n, r in out.items():
        s, k = r["oof"]
        ci = cluster_bootstrap(df, k)
        rows.append({
            "modele": n,
            "auc": f"{np.mean(r['auc']):.3f} ± {np.std(r['auc']):.3f}",
            "pr_auc": f"{np.mean(r['pr_auc']):.3f} ± {np.std(r['pr_auc']):.3f}",
            "rappel_vrais_secrets": f"{np.mean(r['recall']):.3f} [{ci['recall'][0]:.3f}-{ci['recall'][1]:.3f}]",
            "faux_positifs_ecartes": f"{np.mean(r['fp_removed']):.3f} [{ci['fp_removed'][0]:.3f}-{ci['fp_removed'][1]:.3f}]",
        })
    return rows


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default=",".join(MODELS))
    ap.add_argument("--seeds", default="0,1,2")
    ap.add_argument("--drop-unknown", action="store_true")
    ap.add_argument("--limit-repos", type=int, default=None)
    ap.add_argument("--view", choices=["full", "gitleaks"], default="gitleaks",
                    help="gitleaks = what a scanner provides (match + value + path, no context lines): the deployable setting")
    args = ap.parse_args(argv)

    RESULTS_DIR.mkdir(exist_ok=True)
    pkl = Path(r"E:\MEDIANET ML\secrets\creddata_records.pkl")
    raw = pd.read_pickle(pkl) if pkl.exists() and not args.limit_repos else D.load_creddata(limit_repos=args.limit_repos)
    df = D.clean(raw, drop_unknown=args.drop_unknown)
    print(f"{len(df)} candidats, {df['repo'].nunique()} depots, {df['y'].mean():.1%} de vrais secrets")
    if args.view == "gitleaks":
        df = D.gitleaks_view(df)
    X = F.featurize(df, use_rule=args.view == "full")
    names = [m for m in args.models.split(",") if m]
    t0 = time.time()
    out = run(df, X, names, seeds=tuple(int(s) for s in args.seeds.split(",")))
    rows = summarize(out, df)
    print(f"termine en {time.time() - t0:.0f}s")
    tbl = pd.DataFrame(rows)
    print(tbl.to_string(index=False))
    tag = ("sans_X" if args.drop_unknown else "avec_X") + "_" + args.view
    tbl.to_csv(RESULTS_DIR / f"comparaison_{tag}.csv", index=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
