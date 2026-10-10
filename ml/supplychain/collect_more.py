#!/usr/bin/env python3
"""
Improvement 1 - MORE and HARDER benign packages.

The first dataset had ~5,300 normal packages, mostly "easy" ones. For a detector that will run on
real dependency trees (where danger is rare) the cost that matters is FALSE ALARMS on normal
packages that merely look unusual. So we add:

  * the rest of the top-5000 popular packages
  * many more random long-tail packages
  * HARD NEGATIVES: legitimate packages that run an install script (native add-ons, binary
    downloaders, postinstall helpers). They look like malware to a naive rule, and teach the
    model the real difference. They are tagged kind="hard_negative" so the evaluation can report
    the false-alarm rate on them separately.

Existing packages are skipped; the manifest is appended. Resumable.

Usage (from ml/):  python supplychain/collect_more.py --random 15000 --popular-upto 5000 --hard 2500
"""
import argparse
import hashlib
import json
import random
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import collect as c  # reuse registry helpers (get, RAW, popular_names, random_names, ...)

HARD_QUERIES = ["postinstall", "node-gyp", "native addon", "prebuild", "binary", "electron", "puppeteer",
                "download binary", "install script", "n-api", "cmake", "wasm", "playwright", "sqlite native",
                "husky", "patch-package", "cypress", "chromedriver"]


def search_names(query, pages=4, size=250):
    names = []
    for i in range(pages):
        r = c.get("https://registry.npmjs.org/-/v1/search",
                  params={"text": query, "size": size, "from": i * size})
        if r is None or not r.ok:
            break
        objs = r.json().get("objects", [])
        names += [o["package"]["name"] for o in objs]
        if len(objs) < size:
            break
    return names


def fetch(name, source, dest_dir):
    """Like collect.fetch_benign, but also records whether the package runs an install script."""
    r = c.get(c.REGISTRY + urllib.parse.quote(name, safe="@"),
              headers={"Accept": "application/vnd.npm.install-v1+json"})
    if r is None or not r.ok:
        return None
    doc = r.json()
    versions = doc.get("versions") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    if not latest or latest not in versions or all("security" in v for v in versions):
        return None
    meta = versions[latest]
    has_script = bool(meta.get("hasInstallScript"))
    if source == "hard_negative" and not has_script:
        return None
    dist = meta.get("dist") or {}
    if (dist.get("unpackedSize") or 0) > 3 * c.MAX_TARBALL_BYTES:
        return None
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{name}__{latest}")
    if len(safe) > 90:  # Windows path limit: keep names short but unique
        safe = safe[:70] + "_" + hashlib.sha1(safe.encode()).hexdigest()[:12]
    dest = dest_dir / f"{safe}.tgz"
    if not (dest.exists() and dest.stat().st_size > 0):
        t = c.get(dist.get("tarball", ""))
        if t is None or not t.ok or len(t.content) > c.MAX_TARBALL_BYTES:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(t.content)
    kind = "hard_negative" if has_script else source
    return {"name": name, "version": latest, "source": kind, "n_versions": len(versions),
            "file": str(dest.relative_to(c.RAW)), "label": 0, "has_install_script_meta": has_script}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--random", type=int, default=15000)
    ap.add_argument("--popular-upto", type=int, default=5000)
    ap.add_argument("--hard", type=int, default=2500)
    args = ap.parse_args()

    manifest = c.RAW / "manifest_benign.jsonl"
    existing = {json.loads(l)["name"].lower() for l in manifest.read_text(encoding="utf-8").splitlines() if l.strip()}
    forbidden = set()
    for f in (c.RAW / "ossf_npm.jsonl", c.RAW / "manifest_malicious.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                forbidden.add(json.loads(line)["name"].lower())
    for z in c.list_datadog_npm_zips():
        forbidden.add(z["name"].lower())
    skip = existing | forbidden

    rng = random.Random(c.SEED + 1)
    plan = [(n, "popular") for n in c.popular_names(args.popular_upto)]
    plan += [(n, "random") for n in c.random_names(int(args.random * 1.3), rng)]
    c.log("[hard] searching registry for packages that run install scripts...")
    hard = []
    for q in HARD_QUERIES:
        hard += search_names(q)
    hard = list(dict.fromkeys(hard))
    rng.shuffle(hard)
    plan += [(n, "hard_negative") for n in hard[: int(args.hard * 1.6)]]
    seen, todo = set(), []
    for n, s in plan:
        k = n.lower()
        if k in skip or k in seen:
            continue
        seen.add(k)
        todo.append((n, s))
    c.log(f"[more] {len(todo)} new candidates ({len(existing)} already collected)")

    new_rows, kept = [], 0
    with ThreadPoolExecutor(max_workers=14) as pool:
        futures = [pool.submit(fetch, n, s, c.RAW / "benign_npm") for n, s in todo]
        for i, f in enumerate(as_completed(futures), 1):
            try:
                row = f.result()
            except Exception as exc:  # one bad package must not kill a 25k-package run
                c.log(f"  skipped one package: {type(exc).__name__}")
                row = None
            if row:
                new_rows.append(row)
                kept += 1
            if i % 1000 == 0:
                c.log(f"  {i}/{len(todo)} ({kept} kept)")
                with manifest.open("a", encoding="utf-8") as fh:  # checkpoint
                    fh.write("\n".join(json.dumps(r) for r in new_rows) + "\n")
                new_rows = []
    if new_rows:
        with manifest.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(r) for r in new_rows) + "\n")
    c.log(f"[more] +{kept} benign packages")
    c.log("done")


if __name__ == "__main__":
    sys.exit(main())
