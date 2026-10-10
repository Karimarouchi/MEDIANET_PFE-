#!/usr/bin/env python3
"""
Steps 6 + 7 - TRAIN the detectors and EVALUATE them honestly.

Models compared on the same split
  baselines : "name looks like a popular package" rule, "suspicious install script" rule
  supervised: Logistic Regression, Random Forest, XGBoost
  hybrid    : supervised + the anomaly scores (Isolation Forest / auto-encoder) from repair.py
Ablation by feature family (name / package.json / code / anomaly) shows what really helps.

Model choice uses the VALIDATION split only. The alert threshold is also fixed on validation
(highest recall with at most 1 % false positives). The test split is used ONCE, at the end.

Metrics that matter for a rare-event detector
  * PR-AUC and ROC-AUC
  * recall at 1 % and 0.1 % false-positive rate
  * precision at realistic prevalence: the dataset is ~50/50 by construction, but in a real
    dependency tree malicious packages are maybe 1 in 1000+. With TPR/FPR measured here we compute
    the precision a user would actually see (precision = TPR*p / (TPR*p + FPR*(1-p))).

Usage (from ml/):  python supplychain/train.py
"""
import json
import os
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score, roc_curve
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings("ignore")
try:
    from xgboost import XGBClassifier
except ImportError:  # pragma: no cover
    XGBClassifier = None

HERE = Path(__file__).resolve().parent
ECO = os.environ.get("SC_ECO", "npm")
TAG = os.environ.get("SC_TAG", "")  # suffix for output files, to compare variants side by side
DROP = {c for c in os.environ.get("SC_DROP", "").split(",") if c}  # features removed from the model, e.g. name_char_score
CLEAN = HERE / "data" / ("clean" if ECO == "npm" else f"clean_{ECO}")
ART = HERE / ("artifacts" if ECO == "npm" else f"artifacts_{ECO}")
SEED = 42
META = {"name", "label", "kind", "group_id", "split", "mal_type"}
TEXT_SCORES = ["name_char_score", "meta_text_score"]
ANOMALY = ["iforest_score", "autoencoder_error"]
PREVALENCES = [1 / 100, 1 / 1000, 1 / 10000]


STRUCTURE = {"n_files_total", "has_binding_gyp", "n_native_sources", "n_binary_files", "has_prebuilds",
             "has_license_file", "has_tests_dir", "has_ci_config", "has_changelog", "has_typescript_types",
             "has_readme"}


def family(col: str) -> str:
    if col in ANOMALY:
        return "anomaly"
    if col.startswith("name_"):
        return "name"
    if col.startswith("hook_"):
        return "install_semantics"
    if col in TEXT_SCORES:
        return "text_scores"
    if col.startswith("ast_"):
        return "ast"
    if col.startswith(("version_", "md_")):
        return "package_json"
    if col in STRUCTURE:
        return "structure"
    if col in {"has_package_json", "has_install_script", "install_script_len", "install_script_suspicious",
               "install_script_runs_node", "n_dependencies", "n_dev_dependencies", "has_repository",
               "has_homepage", "has_description", "description_len", "has_license", "has_author",
               "n_keywords", "has_main", "has_bin", "n_scripts"}:
        return "package_json"
    return "code"


def recall_at_fpr(y, score, fpr_max):
    fpr, tpr, thr = roc_curve(y, score)
    ok = fpr <= fpr_max
    return float(tpr[ok].max()) if ok.any() else 0.0


def threshold_for_fpr(y, score, fpr_max):
    fpr, tpr, thr = roc_curve(y, score)
    ok = np.where(fpr <= fpr_max)[0]
    i = ok[np.argmax(tpr[ok])]
    return float(thr[i])


def prevalence_precision(tpr, fpr):
    out = {}
    for p in PREVALENCES:
        denom = tpr * p + fpr * (1 - p)
        out[f"1_in_{int(round(1 / p))}"] = float(tpr * p / denom) if denom > 0 else None
    return out


def metrics(y, score, threshold=None):
    y = np.asarray(y)
    out = {
        "n": int(len(y)), "n_malicious": int(y.sum()), "n_benign": int(len(y) - y.sum()),
        "roc_auc": float(roc_auc_score(y, score)),
        "pr_auc": float(average_precision_score(y, score)),
        "recall_at_fpr_1pct": recall_at_fpr(y, score, 0.01),
        "recall_at_fpr_0_1pct": recall_at_fpr(y, score, 0.001),
    }
    if threshold is not None:
        pred = (score >= threshold).astype(int)
        tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
        tpr, fpr = tp / max(tp + fn, 1), fp / max(fp + tn, 1)
        out["at_validation_threshold"] = {
            "threshold": threshold, "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
            "recall": float(tpr), "false_positive_rate": float(fpr),
            "precision_at_realistic_prevalence": prevalence_precision(tpr, fpr),
        }
    return out


def cap_groups(df, cap=25, seed=SEED):
    """Keep at most `cap` rows per campaign group in TRAINING data, so one huge campaign
    (hundreds of near-identical packages) cannot dominate what the model learns."""
    shuffled = df.sample(frac=1.0, random_state=seed)
    return shuffled[shuffled.groupby("group_id").cumcount() < cap]


def campaign_recall(df, score, threshold, big=100):
    """Recall measured per campaign instead of per package.
    micro  = every malicious package counts once (huge campaigns dominate)
    macro  = every campaign counts once
    micro_without_big = micro recall after removing campaigns with >= `big` malicious packages"""
    d = df.loc[df["label"] == 1, ["group_id"]].copy()
    d["hit"] = (np.asarray(score)[(df["label"] == 1).to_numpy()] >= threshold).astype(int)
    per = d.groupby("group_id")["hit"].agg(["mean", "size"])
    small = per[per["size"] < big]
    return {
        "micro": float(d["hit"].mean()),
        "macro_by_campaign": float(per["mean"].mean()),
        "n_campaigns": int(len(per)),
        "micro_without_big_campaigns": float((small["mean"] * small["size"]).sum() / small["size"].sum())
        if len(small) else None,
        "big_campaigns": [{"size": int(r["size"]), "recall": float(r["mean"])}
                          for _, r in per[per["size"] >= big].sort_values("size", ascending=False).iterrows()],
    }


HARD_WEIGHTS = {"hard-negative weight x1": 1.0, "hard-negative weight x5": 5.0}
TIERS = {"review": 0.01, "high_confidence": 0.001}  # max false-positive rate on validation


def wilson_interval(k, n, z=1.96):
    """95% confidence interval of a rate k/n. With few samples the interval is wide on purpose:
    '3 false alarms out of 17' is NOT '17.6%', it is anywhere between ~6% and ~41%."""
    if n == 0:
        return None, None
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return float(max(0.0, centre - half)), float(min(1.0, centre + half))


def sample_weights(frame, hard_weight):
    """Legitimate packages that run an install script (hard negatives) count `hard_weight` times:
    a false alarm on them costs more than one on an ordinary package."""
    return np.where((frame["label"] == 0) & (frame["kind"] == "hard_negative"), hard_weight, 1.0)


def fit_model(factory, frame, cols, hard_weight):
    model = factory()
    weights = sample_weights(frame, hard_weight)
    if hasattr(model, "steps"):  # sklearn Pipeline (scaler + logistic regression)
        model.fit(frame[cols], frame["label"], **{model.steps[-1][0] + "__sample_weight": weights})
    else:
        model.fit(frame[cols], frame["label"], sample_weight=weights)
    return model


def models():
    out = {
        "logistic_regression": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=3000, C=0.5)),
        "random_forest": lambda: RandomForestClassifier(n_estimators=400, min_samples_leaf=2, n_jobs=-1,
                                                        random_state=SEED),
    }
    out["extra_trees"] = lambda: ExtraTreesClassifier(n_estimators=500, min_samples_leaf=2, n_jobs=-1,
                                                       random_state=SEED)
    if XGBClassifier is not None:
        out["ensemble_xgb_rf_et"] = lambda: VotingClassifier(
            estimators=[
                ("xgb", XGBClassifier(n_estimators=500, max_depth=6, learning_rate=0.05, subsample=0.9,
                                      colsample_bytree=0.8, min_child_weight=2, eval_metric="logloss",
                                      random_state=SEED, n_jobs=4)),
                ("rf", RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=SEED)),
                ("et", ExtraTreesClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=SEED)),
            ], voting="soft")
        for depth, trees, lr in ((3, 400, 0.10), (4, 300, 0.08), (6, 600, 0.05), (8, 800, 0.03)):
            out[f"xgboost_d{depth}"] = (lambda d=depth, n=trees, r=lr: XGBClassifier(
                n_estimators=n, max_depth=d, learning_rate=r, subsample=0.9, colsample_bytree=0.8,
                min_child_weight=2, eval_metric="logloss", random_state=SEED, n_jobs=4))
    return out


def tier_report(te, s_te, thresholds):
    """For each alert tier: recall on malware and false-alarm rates (with 95% CI) on the test split."""
    out = {}
    benign = (te["label"] == 0).to_numpy()
    malicious = (te["label"] == 1).to_numpy()
    for tier, thr in thresholds.items():
        flagged = s_te >= thr
        fp_all, n_all = int(flagged[benign].sum()), int(benign.sum())
        entry = {
            "threshold": float(thr),
            "recall": float(flagged[malicious].mean()),
            "false_alarm_rate_all_benign": {"fp": fp_all, "n": n_all, "rate": fp_all / max(n_all, 1),
                                            "ci95": wilson_interval(fp_all, n_all)},
            "by_benign_kind": {},
        }
        for kind in sorted(te.loc[te["label"] == 0, "kind"].dropna().unique()):
            m = benign & (te["kind"] == kind).to_numpy()
            k, n = int(flagged[m].sum()), int(m.sum())
            entry["by_benign_kind"][kind] = {"fp": k, "n": n, "rate": k / max(n, 1), "ci95": wilson_interval(k, n)}
        entry["recall_by_malicious_type"] = {}
        if "mal_type" in te.columns:
            for mtype in sorted(te.loc[te["label"] == 1, "mal_type"].dropna().unique()):
                m = malicious & (te["mal_type"] == mtype).to_numpy()
                entry["recall_by_malicious_type"][mtype] = {"n": int(m.sum()), "recall": float(flagged[m].mean())}
        out[tier] = entry
    return out


def main():
    tr, va, te = (pd.read_csv(CLEAN / f"{s}_ready.csv", keep_default_na=False, na_values=[""], low_memory=False) for s in ("train", "val", "test"))
    feats = [c for c in tr.columns if c not in META and c not in DROP]
    if DROP:
        print(f"[ablation] features removed: {sorted(DROP)}")
    fam = {c: family(c) for c in feats}
    sets = {
        "name only": [c for c in feats if fam[c] == "name"],
        "package.json only": [c for c in feats if fam[c] == "package_json"],
        "install semantics + archive structure": [c for c in feats if fam[c] in ("install_semantics", "structure")],
        "code only": [c for c in feats if fam[c] == "code"],
        "AST (parsed code) only": [c for c in feats if fam[c] == "ast"],
        "name + description text scores only": [c for c in feats if fam[c] == "text_scores"],
        "all content (no text scores, no anomaly)": [c for c in feats if fam[c] not in ("anomaly", "text_scores")],
        "all content (no anomaly)": [c for c in feats if fam[c] != "anomaly"],
        "all content + anomaly (hybrid)": feats,
    }
    ytr, yva, yte = tr["label"].to_numpy(), va["label"].to_numpy(), te["label"].to_numpy()
    n_hard = {k: int(((d["label"] == 0) & (d["kind"] == "hard_negative")).sum()) for k, d in (("train", tr), ("val", va), ("test", te))}
    print(f"train {len(tr)} / val {len(va)} / test {len(te)}  ({len(feats)} features)  hard negatives {n_hard}")

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "split_method": "campaign-grouped (DBSCAN + identical content), StratifiedGroupKFold",
        "rows": {"train": len(tr), "val": len(va), "test": len(te)},
        "hard_negatives": n_hard,
        "baselines": {}, "unsupervised": {}, "ablation": {}, "warnings": [],
    }

    # ---- baselines (no learning)
    base_scores = {
        "rule: name close to a popular package": lambda d: 1 - d["name_edit_dist_norm"].to_numpy(),
        "rule: has install script": lambda d: d["has_install_script"].to_numpy(),
        "rule: install script looks suspicious": lambda d: d["install_script_suspicious"].to_numpy(),
    }
    for name, fn in base_scores.items():
        report["baselines"][name] = {"val": metrics(yva, fn(va)), "test": metrics(yte, fn(te))}
    for c in ANOMALY:
        report["unsupervised"][c] = {"val": metrics(yva, va[c].to_numpy()), "test": metrics(yte, te[c].to_numpy())}

    # ---- supervised models x feature sets x hard-negative weight
    best = None
    for set_name, cols in sets.items():
        for model_name, factory in models().items():
            weights_to_try = HARD_WEIGHTS if set_name.startswith("all content") else {"hard-negative weight x1": 1.0}
            for weight_name, hard_w in weights_to_try.items():
                if model_name in ("logistic_regression",) and not set_name.startswith(("all", "name", "package")):
                    continue
                model = fit_model(factory, tr, cols, hard_w)
                s_va = model.predict_proba(va[cols])[:, 1]
                m_va = metrics(yva, s_va)
                thr = threshold_for_fpr(yva, s_va, 0.01)
                s_te = model.predict_proba(te[cols])[:, 1]
                m_te = metrics(yte, s_te, thr)
                m_te["campaign_view"] = campaign_recall(te, s_te, thr)
                key = f"{model_name} | {set_name} | {weight_name}"
                report["ablation"][key] = {"val": m_va, "test": m_te}
                print(f"  {key:78s} val PR-AUC={m_va['pr_auc']:.3f}  recall@0.1%FPR={m_va['recall_at_fpr_0_1pct']:.3f}")
                # choose on VALIDATION: PR-AUC first, recall at 0.1% false alarms as the tie-breaker
                score_key = (round(m_va["pr_auc"], 4), m_va["recall_at_fpr_0_1pct"])
                if best is None or score_key > best["score_key"]:
                    best = {"key": key, "score_key": score_key, "val_pr_auc": m_va["pr_auc"], "model": model,
                            "cols": cols, "threshold": thr, "model_name": model_name, "hard_w": hard_w}

    # ---- final choice, evaluated once on test; thresholds come from VALIDATION only
    chosen = report["ablation"][best["key"]]
    final_model = best["model"]
    s_va_best = final_model.predict_proba(va[best["cols"]])[:, 1]
    thresholds = {tier: threshold_for_fpr(yva, s_va_best, fpr) for tier, fpr in TIERS.items()}
    s_te = final_model.predict_proba(te[best["cols"]])[:, 1]
    cv_view = chosen["test"].get("campaign_view")
    kind_recall = {}
    for kind in sorted(te.loc[te["label"] == 1, "kind"].dropna().unique()):
        mask = ((te["label"] == 1) & (te["kind"] == kind)).to_numpy()
        kind_recall[kind] = {"n": int(mask.sum()), "recall_at_threshold": float((s_te[mask] >= best["threshold"]).mean())}
    tiers = tier_report(te, s_te, thresholds)
    report["selected"] = {
        "model": best["key"],
        "selection_rule": "highest validation PR-AUC (tie: recall at 0.1% FPR); thresholds = best recall under 1% / 0.1% false positives on validation",
        "threshold": best["threshold"], "test": chosen["test"], "test_recall_by_malicious_kind": kind_recall,
        "alert_tiers": tiers,
    }
    for tier, t in tiers.items():
        hn = t["by_benign_kind"].get("hard_negative")
        print(f"  tier {tier:16s} recall={t['recall']:.3f}  false alarms all={t['false_alarm_rate_all_benign']['rate']:.4f}"
              + (f"  hard negatives {hn['fp']}/{hn['n']} = {hn['rate']:.3f} (CI {hn['ci95'][0]:.3f}-{hn['ci95'][1]:.3f})" if hn else ""))

    # honesty
    if report["rows"]["test"] < 1000 or chosen["test"]["n_malicious"] < 100:
        report["warnings"].append("Test split has fewer than 100 malicious packages: rates have wide error bars.")
    if n_hard["test"] < 200:
        report["warnings"].append(
            f"Only {n_hard['test']} hard negatives in the test split: the false-alarm rate on them has a wide "
            "confidence interval (see ci95).")
    report["warnings"].append(
        "Test set is ~balanced by construction. Use precision_at_realistic_prevalence, not raw precision, "
        "to describe what a user sees on real dependency trees.")
    report["warnings"].append(
        "Malicious samples come from public datasets dominated by automated campaigns; targeted attacks are "
        "likely harder. Registry metadata is intentionally unused because it exists only for benign packages.")
    for big in (cv_view or {}).get("big_campaigns", []):
        if big["recall"] < 0.6:
            report["warnings"].append(
                f"One unseen campaign of {big['size']} malicious packages is caught only {big['recall']:.0%}: "
                "overall recall (micro) is dominated by it; read macro-by-campaign and the grouped CV too.")
    best_rule = max(report["baselines"].values(), key=lambda r: r["val"]["pr_auc"])
    if chosen["val"]["pr_auc"] <= best_rule["val"]["pr_auc"]:
        report["warnings"].append("The selected model does not beat the best simple rule on validation PR-AUC.")

    # importance of the winner
    imp = None
    inner = final_model[-1] if hasattr(final_model, "__getitem__") else final_model
    if hasattr(inner, "feature_importances_"):
        imp = sorted(zip(best["cols"], map(float, inner.feature_importances_)), key=lambda t: -t[1])[:15]
    elif hasattr(inner, "coef_"):
        imp = sorted(zip(best["cols"], map(float, np.abs(inner.coef_[0]))), key=lambda t: -t[1])[:15]
    report["top_features"] = imp

    # ---- grouped cross-validation over ALL data (every campaign is held out once)
    from sklearn.model_selection import StratifiedGroupKFold
    full = pd.concat([tr, va, te], ignore_index=True)
    oof = np.zeros(len(full))
    for fit_i, hold_i in StratifiedGroupKFold(5, shuffle=True, random_state=SEED).split(full, full["label"], full["group_id"]):
        m = fit_model(models()[best["model_name"]], full.iloc[fit_i], best["cols"], best["hard_w"])
        oof[hold_i] = m.predict_proba(full.iloc[hold_i][best["cols"]])[:, 1]
    cv_thr = threshold_for_fpr(full["label"].to_numpy(), oof, 0.01)
    report["grouped_cv_all_data"] = {
        "note": "5-fold, every campaign held out once; threshold chosen on the same out-of-fold scores "
                "(slightly optimistic for recall). Shows how much the result depends on WHICH campaigns are unseen.",
        **metrics(full["label"].to_numpy(), oof, cv_thr),
        "campaign_view": campaign_recall(full, oof, cv_thr),
        "alert_tiers": tier_report(full, oof, {t: threshold_for_fpr(full["label"].to_numpy(), oof, f)
                                               for t, f in TIERS.items()}),
    }
    cv = report["grouped_cv_all_data"]
    print(f"\nGrouped CV (all data): ROC-AUC={cv['roc_auc']:.3f} PR-AUC={cv['pr_auc']:.3f} "
          f"micro recall={cv['campaign_view']['micro']:.3f} macro-by-campaign={cv['campaign_view']['macro_by_campaign']:.3f}")
    hn_cv = cv["alert_tiers"]["review"]["by_benign_kind"].get("hard_negative")
    if hn_cv:
        print(f"  CV hard-negative false alarms (review tier): {hn_cv['fp']}/{hn_cv['n']} = {hn_cv['rate']:.3f} "
              f"(CI {hn_cv['ci95'][0]:.3f}-{hn_cv['ci95'][1]:.3f})")

    ART.mkdir(exist_ok=True)
    joblib.dump({"model": final_model, "columns": best["cols"], "threshold": best["threshold"], "tiers": thresholds},
                ART / f"supplychain_model{TAG}.joblib")
    (ART / f"metrics_supplychain{TAG}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("\nSELECTED:", best["key"])
    print(json.dumps(report["selected"], indent=2))
    for w in report["warnings"]:
        print("[WARNING]", w)


if __name__ == "__main__":
    sys.exit(main())
