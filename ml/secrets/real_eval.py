"""Secret triage on REAL scanner candidates (big_eval pool, hand labels R/F): does adding them to training help?

Labels: big_eval/labels.json, labels2.json, labels3.json ({pool index: "R"|"F"|"U"}; U is dropped).
Every number is measured on repositories the model under test never saw: leave-one-repository-out over the 14 real
repositories, CredData always in training. The decision measured is the one Vulnix shows: a candidate is hidden
when the verdict is "probablement faux positif" (model threshold + noise rules), shown otherwise.

  python secrets/real_eval.py errors      current model: what it gets wrong on the real labels
  python secrets/real_eval.py compare     current model vs retrained with the real labels (weights 0 / 3 / 10 / 30)
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import StratifiedGroupKFold

sys.path.insert(0, str(Path(__file__).resolve().parent))
import data as D  # noqa: E402
import evaluate as E  # noqa: E402
import export as X  # noqa: E402
import features as F  # noqa: E402
import runtime as R  # noqa: E402

BIG = Path(r"E:\MEDIANET ML\secrets\big_eval")
LABEL_FILES = ("labels.json", "labels2.json", "labels3.json")


def finding(item: dict) -> dict:
    return {"RuleID": item["rules"][0], "File": "/" + item["file"], "Match": item["match"][:600], "Secret": item["secret"]}


def load_real() -> pd.DataFrame:
    """One row per (repository, value): the same key copied in ten folders counts once. Conflicting labels are dropped."""
    pool = json.loads((BIG / "pool.json").read_text(encoding="utf-8"))
    labels: dict[int, str] = {}
    for f in LABEL_FILES:
        if (BIG / f).exists():
            labels.update({int(k): v for k, v in json.loads((BIG / f).read_text(encoding="utf-8")).items()})
    rows, seen = [], {}
    for i, v in labels.items():
        if v not in ("R", "F"):
            continue
        it = pool[i]
        key = (it["repo"], it["secret"].strip())
        if key in seen:
            if seen[key] != v:
                seen[key] = "conflict"
            continue
        seen[key] = v
        rec = R.finding_to_record(finding(it))
        rows.append({**rec, "repo": "real:" + it["repo"], "pool_id": i, "y": int(v == "R"),
                     "scope": R.path_scope(rec["path"], rec["ext"]), "file": it["file"], "secret": it["secret"]})
    df = pd.DataFrame(rows)
    bad = {k for k, v in seen.items() if v == "conflict"}
    if bad:
        df = df[[(r[5:], s.strip()) not in bad for r, s in zip(df["repo"], df["secret"])]]
    return df.reset_index(drop=True)


def rule_mask(df: pd.DataFrame) -> np.ndarray:
    return np.array([R.noise_reason(r) is not None for r in df.to_dict("records")])


def decision(p_raw: np.ndarray, t_raw: float, rules: np.ndarray) -> np.ndarray:
    """True = shown to the user (not 'probablement faux positif')."""
    return (p_raw >= t_raw) & ~rules


def report(name: str, y: np.ndarray, shown: np.ndarray, score: np.ndarray, groups: np.ndarray, rng) -> dict:
    rec = shown[y == 1].mean()
    cut = (~shown[y == 0]).mean()
    # repository bootstrap: the honest spread when 14 repositories carry the whole test
    reps = np.unique(groups)
    bs_rec, bs_cut = [], []
    for _ in range(1000):
        pick = rng.choice(reps, size=len(reps))
        idx = np.concatenate([np.where(groups == r)[0] for r in pick])
        yy, ss = y[idx], shown[idx]
        if (yy == 1).any() and (yy == 0).any():
            bs_rec.append(ss[yy == 1].mean())
            bs_cut.append((~ss[yy == 0]).mean())
    auc = roc_auc_score(y, score) if len(set(y)) == 2 else float("nan")
    out = {"name": name, "recall": rec, "fp_removed": cut, "auc": auc,
           "recall_ci": np.percentile(bs_rec, [2.5, 97.5]).tolist(), "fp_removed_ci": np.percentile(bs_cut, [2.5, 97.5]).tolist(),
           "missed": int((~shown[y == 1]).sum()), "fp_shown": int(shown[y == 0].sum())}
    print(f"{name:<44} vrais gardés {rec:6.1%} [{out['recall_ci'][0]:.0%}-{out['recall_ci'][1]:.0%}]   "
          f"faux écartés {cut:6.1%} [{out['fp_removed_ci'][0]:.0%}-{out['fp_removed_ci'][1]:.0%}]   "
          f"AUC {auc:.3f}   ({out['missed']} vrais perdus, {out['fp_shown']} faux affichés)")
    return out


def creddata():
    raw = pd.read_pickle(Path(r"E:\MEDIANET ML\secrets\creddata_records.pkl"))
    df = D.gitleaks_view(D.clean(raw))
    return df, F.featurize(df, use_rule=False), df["y"].to_numpy(), df["repo"].to_numpy()


def fit_with_threshold(Xtr, ytr, gtr, wtr, inner=3, seed=0):
    """Same recipe as export.py: cross-fitted scores -> 99%-recall threshold -> final fit on everything.
    Returns (model, raw threshold). The threshold is found on raw scores (isotonic is monotonic, so equivalent)."""
    import xgboost as xgb
    params = X.xgb_params()
    oof = np.zeros(len(ytr))
    for tr, te in StratifiedGroupKFold(inner, shuffle=True, random_state=seed).split(Xtr, ytr, gtr):
        m = _fit(Xtr.iloc[tr], ytr[tr], wtr[tr], params, seed)
        oof[te] = m.predict_proba(Xtr.iloc[te])[:, 1]
    iso = IsotonicRegression(out_of_bounds="clip").fit(oof, ytr, sample_weight=wtr)
    p = iso.predict(oof)
    t_cal = weighted_threshold_for_recall(ytr, p, wtr, X.FALSE_RECALL)
    t_raw = float(oof[p >= t_cal].min()) if (p >= t_cal).any() else 1.0
    return _fit(Xtr, ytr, wtr, params, seed), t_raw, iso, t_cal, oof


def _fit(Xtr, ytr, wtr, params, seed):
    import xgboost as xgb
    pos = max(float(wtr[ytr == 1].sum()), 1.0)
    neg = float(wtr[ytr == 0].sum())
    clf = xgb.XGBClassifier(**{**dict(subsample=0.8, min_child_weight=3, reg_lambda=2.0, eval_metric="logloss",
                                      n_jobs=4, tree_method="hist"), **params,
                               "scale_pos_weight": neg / pos, "random_state": seed})
    clf.fit(Xtr, ytr, sample_weight=wtr)
    return clf


def weighted_threshold_for_recall(y, s, w, target):
    pos = np.where(y == 1)[0]
    order = pos[np.argsort(-s[pos])]
    cum = np.cumsum(w[order]) / w[order].sum()
    k = int(np.searchsorted(cum, target))
    return float(s[order[min(k, len(order) - 1)]])


def errors() -> None:
    real = load_real()
    tri = R.SecretTriage()
    out = []
    for k in range(0, len(real), 300):
        chunk = real.iloc[k:k + 300]
        out += tri.score([{"RuleID": "", "File": p, "Match": l, "Secret": v} for p, l, v in zip(chunk["path"], chunk["line"], chunk["value"])])
    real["verdict"] = [o["verdict"] for o in out]
    real["p"] = [o["probaReal"] for o in out]
    shown = (real["verdict"] != "LIKELY_FALSE_POSITIVE").to_numpy()
    y = real["y"].to_numpy()
    print(f"{len(real)} candidats réels distincts ({y.sum()} vrais, {(1 - y).sum()} faux) sur {real['repo'].nunique()} dépôts\n")
    report("modèle actuel (secrets-v1 + règles)", y, shown, real["p"].to_numpy(), real["repo"].to_numpy(), np.random.default_rng(0))
    print("\n--- vrais secrets cachés à tort")
    for r in real[(y == 1) & ~shown].itertuples():
        print(f"  p={r.p:.3f} {r.repo[5:]:<28} {r.file[-45:]:<45} | {r.value[:50]!r}")
    print("\n--- faux positifs encore affichés, par motif de fichier")
    fp = real[(y == 0) & shown]
    print(collections.Counter(Path(f).suffix or Path(f).name for f in fp["file"]).most_common(15))
    for r in fp.itertuples():
        print(f"  {r.verdict[:6]} p={r.p:.3f} {r.repo[5:]:<26} {r.file[-42:]:<42} | {r.line[:70]!r}")


def compare(weights=(0, 3, 10, 30)) -> None:
    real = load_real()
    cd, Xcd, ycd, gcd = creddata()
    Xr = F.featurize(real, use_rule=False).reindex(columns=Xcd.columns, fill_value=0.0)
    yr, gr = real["y"].to_numpy(), real["repo"].to_numpy()
    rules = rule_mask(real)
    print(f"{len(real)} candidats réels ({yr.sum()} vrais) sur {len(set(gr))} dépôts ; CredData {len(ycd)} lignes\n")

    rng = np.random.default_rng(0)
    results = {}
    # current deployed bundle, as a reference (trained on CredData only, never saw these repositories)
    import joblib
    b = joblib.load(Path(__file__).resolve().parent / "artifacts" / "secret_triage.joblib")
    p_cur = b["isotonic"].predict(b["model"].predict_proba(Xr[b["columns"]])[:, 1])
    shown_cur = (p_cur >= b["thresholds"]["likely_false_below"]) & ~rules
    results["actuel"] = report("modèle actuel secrets-v1 (déployé)", yr, shown_cur, p_cur, gr, rng)

    for w in weights:
        p_oof = np.zeros(len(real))
        shown = np.zeros(len(real), dtype=bool)
        for rep in sorted(set(gr)):
            te = gr == rep
            tr_real = ~te
            if w > 0:
                Xtr = pd.concat([Xcd, Xr[tr_real]], ignore_index=True)
                ytr = np.concatenate([ycd, yr[tr_real]])
                gtr = np.concatenate([gcd, gr[tr_real]])
                wtr = np.concatenate([np.ones(len(ycd)), np.full(tr_real.sum(), float(w))])
            else:
                Xtr, ytr, gtr, wtr = Xcd, ycd, gcd, np.ones(len(ycd))
            if w == 0 and "w0" in results:
                break
            model, t_raw, *_ = fit_with_threshold(Xtr, ytr, gtr, wtr)
            if w == 0:   # does not depend on the held-out repository: one model for all
                p = model.predict_proba(Xr)[:, 1]
                p_oof, shown = p, decision(p, t_raw, rules)
                results["w0"] = True
                break
            p = model.predict_proba(Xr[te])[:, 1]
            p_oof[te] = p
            shown[te] = decision(p, t_raw, rules[te])
            print(f"   poids {w}: dépôt {rep[5:]} fait", flush=True)
        results[f"w{w}"] = report(f"réentraîné, vraies étiquettes poids {w}", yr, shown, p_oof, gr, np.random.default_rng(0))
    (Path(__file__).resolve().parent / "results" / "real_labels_compare.json").write_text(
        json.dumps({k: v for k, v in results.items() if isinstance(v, dict)}, indent=1, default=float), encoding="utf-8")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "errors"
    if cmd == "compare" and len(sys.argv) > 2:
        compare(tuple(int(w) for w in sys.argv[2].split(",")))
    else:
        {"errors": errors, "compare": compare}[cmd]()
