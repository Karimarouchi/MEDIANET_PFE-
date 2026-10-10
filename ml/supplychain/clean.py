#!/usr/bin/env python3
"""
Steps 2 + 3 - CLEAN the raw feature table, then SPLIT it into train / validation / test.

Nothing statistical is learned here except the campaign groups. The split happens BEFORE any
imputation / outlier model is fitted (repair.py), so the test set never influences them.

Cleaning
  * drop unreadable archives and packages with no readable text file at all
  * drop duplicate package names
  * exact content duplicates: keep one copy per label; if the same content appears with both
    labels it is label noise -> drop every copy
Campaign groups (DBSCAN)
  Malicious packages come in campaigns (dozens of near-identical names / identical code from one
  attacker). If a campaign were spread over train and test the test would be far too easy. We
  therefore group packages and keep every group on ONE side of the split:
    1. identical content hash  -> same group
    2. DBSCAN (cosine) over character n-grams of the package name -> same group
  DBSCAN noise points (isolated packages) stay alone.
Split: StratifiedGroupKFold(7) -> 1 fold test, 1 fold validation, 5 folds train (~72/14/14).
There is no publication date that exists for BOTH classes, so a chronological split is not possible
here; the campaign-grouped split replaces it and is the stricter test for this problem.

Usage (from ml/):  python supplychain/clean.py
"""
import json
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import StratifiedGroupKFold

from types_rules import add_types

HERE = Path(__file__).resolve().parent
ECO = os.environ.get("SC_ECO", "npm")  # npm | pypi : same pipeline, separate data and artifacts
CLEAN = HERE / "data" / ("clean" if ECO == "npm" else f"clean_{ECO}")
SEED = 42
DBSCAN_EPS = 0.25
DBSCAN_MIN_SAMPLES = 3
CONTENT_EPS = 0.2


class UnionFind:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


def clean(df: pd.DataFrame):
    report = {"rows_in": int(len(df)), "by_label_in": df["label"].value_counts().to_dict()}

    unreadable = df["archive_readable"].fillna(0).astype(int) == 0
    report["dropped_unreadable"] = df[unreadable]["label"].value_counts().to_dict()
    df = df[~unreadable]

    empty = df["n_text_files"].fillna(0) == 0
    report["dropped_no_text_files"] = df[empty]["label"].value_counts().to_dict()
    df = df[~empty]

    before = len(df)
    df = df.drop_duplicates(subset="name", keep="first")
    report["dropped_duplicate_name"] = int(before - len(df))

    # same content under both labels = label noise
    per_hash = df.dropna(subset=["content_hash"]).groupby("content_hash")["label"].nunique()
    conflicting = set(per_hash[per_hash > 1].index)
    report["dropped_label_conflict"] = int(df["content_hash"].isin(conflicting).sum())
    df = df[~df["content_hash"].isin(conflicting)]

    before = df["label"].value_counts().to_dict()
    df = df.sort_values("name").drop_duplicates(subset=["content_hash", "label"], keep="first") \
        if df["content_hash"].notna().any() else df
    # packages without a hash (should not happen) were kept by drop_duplicates above only once
    report["dropped_identical_content"] = {int(k): int(before[k] - df["label"].value_counts().get(k, 0))
                                           for k in before}
    report["rows_out"] = int(len(df))
    report["by_label_out"] = {int(k): int(v) for k, v in df["label"].value_counts().items()}
    return df.reset_index(drop=True), report


def campaign_groups(df: pd.DataFrame):
    n = len(df)
    uf = UnionFind(n)

    # 1) identical content
    first_by_hash = {}
    for i, h in enumerate(df["content_hash"]):
        if isinstance(h, str):
            if h in first_by_hash:
                uf.union(first_by_hash[h], i)
            else:
                first_by_hash[h] = i

    # 1b) identical SOURCE CODE (package.json excluded): same attacker copy-pasting one payload
    #     under hundreds of names - the name inside package.json is the only thing that differs
    first_by_code = {}
    for i, h in enumerate(df["code_hash"]):
        if isinstance(h, str):
            if h in first_by_code:
                uf.union(first_by_code[h], i)
            else:
                first_by_code[h] = i

    # 2) DBSCAN over name character n-grams
    names = df["name"].str.lower().str.replace(r"^@[^/]+/", "", regex=True)
    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 4), min_df=2)
    matrix = vec.fit_transform(names)
    labels = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric="cosine", n_jobs=-1).fit_predict(matrix)
    first_by_cluster = {}
    for i, c in enumerate(labels):
        if c == -1:
            continue
        if c in first_by_cluster:
            uf.union(first_by_cluster[c], i)
        else:
            first_by_cluster[c] = i

    # 3) DBSCAN over the numeric CONTENT profile: near-identical payloads with small edits
    prof_cols = [c for c in df.columns if c.startswith("n_") and not c.endswith("_per_kb")] +                 ["code_bytes", "max_line_len", "install_script_len", "code_entropy"]
    prof = df[[c for c in prof_cols if c in df.columns]].fillna(0).clip(lower=0)
    has_code = (df["code_bytes"].fillna(0) > 0).to_numpy()
    prof = np.log1p(prof.to_numpy())
    prof = (prof - prof.mean(axis=0)) / np.where(prof.std(axis=0) == 0, 1, prof.std(axis=0))
    idx = np.where(has_code)[0]
    prof_labels = DBSCAN(eps=CONTENT_EPS, min_samples=4, n_jobs=-1).fit_predict(prof[idx])
    first_by_prof = {}
    for j, c in zip(idx, prof_labels):
        if c == -1:
            continue
        if c in first_by_prof:
            uf.union(first_by_prof[c], j)
        else:
            first_by_prof[c] = j

    roots = np.array([uf.find(i) for i in range(n)])
    _, group_ids = np.unique(roots, return_inverse=True)
    return group_ids, int((labels == -1).sum()), int(len(first_by_cluster))


def split(df: pd.DataFrame, groups):
    folds = StratifiedGroupKFold(n_splits=7, shuffle=True, random_state=SEED)
    fold_of = np.full(len(df), -1)
    for k, (_, test_idx) in enumerate(folds.split(df, df["label"], groups)):
        fold_of[test_idx] = k
    name = np.where(fold_of == 0, "test", np.where(fold_of == 1, "val", "train"))
    return pd.Series(name, index=df.index)


def main():
    raw = pd.read_csv(CLEAN / "features_raw.csv", keep_default_na=False, na_values=[""], low_memory=False)
    large = CLEAN / "features_large.jsonl"
    if large.exists():
        extra = pd.read_json(large, lines=True, dtype=False)
        print(f"merging {len(extra)} streamed large legitimate packages (kind='large')")
        raw = pd.concat([raw, extra], ignore_index=True)
    df, report = clean(raw)
    df = add_types(df)  # heuristic type of each malicious package (reporting only)
    report["malicious_types"] = {k: int(v) for k, v in df.loc[df["label"] == 1, "mal_type"].value_counts().items()}
    groups, db_noise, db_clusters = campaign_groups(df)
    df["group_id"] = groups
    df["split"] = split(df, groups)

    sizes = pd.Series(groups).value_counts()
    leak = df.groupby("group_id")["split"].nunique().max()
    report["campaign_groups"] = {
        "n_groups": int(len(sizes)), "dbscan_clusters": db_clusters, "dbscan_noise_points": db_noise,
        "largest_groups": [int(x) for x in sizes.head(5)],
        "max_splits_per_group": int(leak),
    }
    assert leak == 1, "a campaign group leaked across splits"
    report["split"] = {
        s: {"rows": int((df["split"] == s).sum()),
            "malicious": int(((df["split"] == s) & (df["label"] == 1)).sum()),
            "benign": int(((df["split"] == s) & (df["label"] == 0)).sum())}
        for s in ("train", "val", "test")
    }

    for s in ("train", "val", "test"):
        df[df["split"] == s].to_csv(CLEAN / f"{s}_raw.csv", index=False)
    (CLEAN / "cleaning_report.json").write_text(json.dumps(report, indent=2, default=int), encoding="utf-8")
    print(json.dumps(report, indent=2, default=int))


if __name__ == "__main__":
    sys.exit(main())
