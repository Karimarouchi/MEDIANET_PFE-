#!/usr/bin/env python3
"""
Improvement C for PyPI - LARGE legitimate source distributions, STREAMED (only the numbers are kept).

The first PyPI collection capped sdists at 5 MB, so big projects (numpy, pandas, django, scipy...) were never
seen by the model and are reported TOO_LARGE at scan time. This adds sdists of 2 MB - 80 MB.

Stage 1 (many threads, one small JSON request each): is the sdist large enough?
Stage 2 (worker processes): download into memory, compute the feature row, discard the archive.

Output: data/clean_pypi/features_large.jsonl  (label 0, kind "large", or "hard_negative" if setup.py runs code)
Usage (from ml/):  python supplychain/collect_large_pypi.py --target 1500
"""
import argparse
import json
import random
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote

warnings.filterwarnings("ignore")

import collect as c  # noqa: E402
import features_pypi as P  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "data" / "clean_pypi" / "features_large.jsonl"
MIN_SIZE = 2 * 1024 * 1024
MAX_SIZE = 80 * 1024 * 1024
SIMPLE = "https://pypi.org/simple/"


def meta(name):
    r = c.get(f"https://pypi.org/pypi/{quote(name)}/json")
    if r is None or not r.ok:
        return None
    doc = r.json()
    sdists = [u for u in doc.get("urls", []) if u.get("packagetype") == "sdist"]
    if not sdists:
        return None
    u = sdists[0]
    if not (MIN_SIZE <= (u.get("size") or 0) <= MAX_SIZE):
        return None
    return name, u["url"], u["filename"], doc["info"].get("version")


def build(name, url, filename, version):
    t = c.get(url, stream=True)
    if t is None or not t.ok:
        return None
    data = bytearray()
    for chunk in t.iter_content(65536):
        data += chunk
        if len(data) > MAX_SIZE:
            return None
    norm = P.normalize_name(name)
    out = {"name": norm, "label": 0, "kind": "large", "file": f"large:{name}", "archive_readable": 0}
    out.update(P.F.name_features(norm, top_names=P.TOP_NAMES_PYPI))
    try:
        out.update(P.content_features(bytes(data), ".zip" if filename.endswith(".zip") else ".tgz", version))
        if out.get("has_install_script") == 1:
            out["kind"] = "hard_negative"
    except Exception as exc:
        out["error"] = type(exc).__name__
    out["_download_bytes"] = len(data)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=1500)
    ap.add_argument("--workers", type=int, default=6)
    args = ap.parse_args()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    seen = {json.loads(l)["name"] for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()} if OUT.exists() else set()
    existing = {P.normalize_name(json.loads(l)["name"]) for l in
                (c.RAW / "manifest_benign_pypi.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    forbidden = set()
    for f in (c.RAW / "ossf_pypi.jsonl", c.RAW / "manifest_malicious_pypi.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                forbidden.add(P.normalize_name(json.loads(line)["name"]))

    top = [P.normalize_name(n) for n in P.TOP_NAMES_PYPI]
    idx = c.get(SIMPLE, headers={"Accept": "application/vnd.pypi.simple.v1+json"})
    rest = [p["name"] for p in idx.json()["projects"]] if idx is not None and idx.ok else []
    random.Random(c.SEED + 5).shuffle(rest)
    # popular first (what real projects depend on), then a random sample of the whole index
    # (packages already collected are re-checked: they may have been skipped for size)
    todo = [n for n in list(dict.fromkeys(top)) + rest[:60000] if P.normalize_name(n) not in seen and P.normalize_name(n) not in forbidden]
    c.log(f"[large-pypi] {len(todo)} candidates; target {args.target}; {len(seen)} already done")

    kept, total_bytes, scanned, pending = len(seen), 0, 0, []

    def harvest(fh, block=False):
        nonlocal kept, total_bytes, pending
        still = []
        for pf in pending:
            if block or pf.done():
                try:
                    row = pf.result()
                except Exception:
                    row = None
                if row:
                    total_bytes += row.pop("_download_bytes", 0)
                    fh.write(json.dumps(row, default=str) + chr(10))
                    fh.flush()
                    kept += 1
            else:
                still.append(pf)
        pending = still

    with ThreadPoolExecutor(max_workers=20) as meta_pool, ProcessPoolExecutor(max_workers=args.workers) as build_pool, \
            OUT.open("a", encoding="utf-8") as fh:
        futs = [meta_pool.submit(meta, n) for n in todo]
        for f in as_completed(futs):
            scanned += 1
            try:
                res = f.result()
            except Exception:
                res = None
            if res and kept + len(pending) < args.target:
                pending.append(build_pool.submit(build, *res))
            harvest(fh)
            if scanned % 500 == 0:
                c.log(f"  {scanned}/{len(todo)} checked, {kept} large kept, {len(pending)} downloading, "
                      f"{total_bytes / 1e9:.2f} GB downloaded")
            if kept >= args.target:
                break
        for fu in futs:
            fu.cancel()
        harvest(fh, block=True)
    c.log(f"[large-pypi] {kept} large legitimate sdists, {total_bytes / 1e9:.2f} GB downloaded this run")
    c.log("done")


if __name__ == "__main__":
    sys.exit(main())
