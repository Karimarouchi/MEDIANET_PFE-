#!/usr/bin/env python3
"""
Independent real-world check of a runtime bundle. NOTHING here is used for training.

Three sets, scored through the exact production path (runtime.score_package):
  1. the 210 npm dependencies of a real project (eval/realworld_sm_travellet.json)  -> expected: no alert
  2. 400 random npm packages never seen by the model (fixed seed)                     -> false-alarm rate
  3. well-known LARGE frameworks (the population that produced the first false alarms) -> expected: no alert
  4. known-malicious samples (DataDog, held-out test split) scored from local archives  -> detection rate

Usage (from ml/):  python supplychain/eval/realworld_check.py [--eco npm] [--out supplychain/eval/realworld_v5.json]
"""
import argparse
import collections
import json
import random
import string
import sys
import warnings
from pathlib import Path

warnings.filterwarnings("ignore")
HERE = Path(__file__).resolve().parent
SC = HERE.parent
sys.path.insert(0, str(SC))

import runtime  # noqa: E402

FRAMEWORKS = ["react-router", "react-dom", "react", "next", "vue", "@angular/core", "nodemailer", "winston", "express",
              "webpack", "typescript", "eslint", "prettier", "jest", "mongoose", "sequelize", "socket.io", "axios",
              "lodash", "moment", "aws-sdk", "@babel/core", "rxjs", "tailwindcss", "vite", "electron", "puppeteer",
              "@nestjs/core", "graphql", "apollo-server", "sharp", "canvas", "pg", "mysql2", "redis", "bull",
              "passport", "jsonwebtoken", "bcrypt", "multer", "helmet", "cors", "dotenv", "chalk", "commander",
              "yargs", "inquirer", "ora", "rollup", "esbuild", "@mui/material", "antd", "chart.js", "three", "d3"]


def tally(results):
    c = collections.Counter()
    for r in results:
        c[r["tier"] if r.get("status") == "SCORED" else r.get("status", "?")] += 1
    return dict(c)


def run(scorer, items, workers=4):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda it: runtime.score_package(scorer, it["name"], it.get("version") or None), items))


def random_names(n, seen, seed=2026):
    import requests
    rng = random.Random(seed)
    alpha = string.ascii_lowercase + string.digits
    names = []
    while len(names) < n:
        key = "".join(rng.choice(alpha) for _ in range(rng.randint(2, 5)))
        r = requests.get("https://replicate.npmjs.com/_all_docs", params={"limit": 4, "startkey": json.dumps(key)}, timeout=30)
        for row in r.json().get("rows", []):
            nm = row["id"]
            if nm.lower() not in seen and nm not in names:
                names.append(nm)
    return names[:n]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--eco", default="npm")
    ap.add_argument("--out", default=str(HERE / "realworld_latest.json"))
    ap.add_argument("--random", type=int, default=400)
    args = ap.parse_args()
    scorer = runtime.Scorer(args.eco)
    report = {}

    project = json.loads((HERE / "realworld_sm_travellet.json").read_text(encoding="utf-8"))
    res = run(scorer, project)
    report["project_210_dependencies"] = {"n": len(res), "tiers": tally(res),
                                          "flagged": [(r["name"], r["version"], r["tier"], round(r["suspicionProba"], 2))
                                                      for r in res if r.get("tier") in ("REVIEW", "HIGH_CONFIDENCE")]}

    known = set()
    mf = SC / "data" / "raw" / "manifest_benign.jsonl"
    for line in mf.read_text(encoding="utf-8").splitlines():
        if line.strip():
            known.add(json.loads(line)["name"].lower())
    names = random_names(args.random, known)
    res = run(scorer, [{"name": n} for n in names])
    report["random_unseen"] = {"n": len(res), "tiers": tally(res),
                               "flagged": [(r["name"], r["tier"], round(r["suspicionProba"], 2)) for r in res
                                           if r.get("tier") in ("REVIEW", "HIGH_CONFIDENCE")]}

    res = run(scorer, [{"name": n} for n in FRAMEWORKS])
    report["large_frameworks"] = {"n": len(res), "tiers": tally(res),
                                  "flagged": [(r["name"], r["tier"], round(r["suspicionProba"], 2),
                                               r.get("tierBeforePopularityGuard")) for r in res
                                              if r.get("tier") in ("REVIEW", "HIGH_CONFIDENCE")]}

    # malicious samples held out from training: the TEST split rows, scored from local encrypted archives
    import pandas as pd
    te = pd.read_csv(SC / "data" / "clean" / "test_raw.csv", keep_default_na=False, na_values=[""], low_memory=False)
    mal = te[te.label == 1].sample(n=min(300, int((te.label == 1).sum())), random_state=1)
    out = []
    for _, r in mal.iterrows():
        path = SC / "data" / "raw" / r["file"]
        if not path.exists():
            continue
        out.append(runtime.score_package(scorer, r["name"], None, archive=path.read_bytes(),
                                         kind="zip" if path.suffix == ".zip" else "tgz"))
    flagged = sum(1 for r in out if r.get("tier") in ("REVIEW", "HIGH_CONFIDENCE", "KNOWN_MALICIOUS"))
    model_only = [r for r in out if r.get("tier") != "KNOWN_MALICIOUS"]
    report["malicious_test_samples"] = {
        "n": len(out), "tiers": tally(out),
        "detected_any_alert": flagged / max(len(out), 1),
        "note": "KNOWN_MALICIOUS comes from the OSSF list (these names are public); the model-only line is below",
        "model_only_alert_rate": sum(1 for r in model_only if r.get("tier") in ("REVIEW", "HIGH_CONFIDENCE")) / max(len(model_only), 1),
        "model_only_n": len(model_only),
    }
    Path(args.out).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({k: {kk: vv for kk, vv in v.items() if kk != "flagged"} for k, v in report.items()}, indent=2, ensure_ascii=False))
    for k in ("project_210_dependencies", "random_unseen", "large_frameworks"):
        if report[k]["flagged"]:
            print(f"\n{k} - flagged:")
            for f in report[k]["flagged"]:
                print("  ", f)


if __name__ == "__main__":
    sys.exit(main())
