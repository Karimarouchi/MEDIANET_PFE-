#!/usr/bin/env python3
"""
Step 1 - COLLECT (raw, unmodified) the npm supply-chain dataset.

Malicious (label 1)
  * DataDog malicious-software-packages-dataset: encrypted ZIPs (password "infected").
    We only DOWNLOAD them here. They are never extracted to disk and never executed;
    features.py reads them in memory as plain bytes.
  * OSSF malicious-packages: OSV reports (MAL-*). Metadata only (names, dates) - used as a
    second label source and to make sure no "benign" sample is actually a known malicious name.

Benign (label 0)
  * popular : top npm packages (wooorm/npm-high-impact list)
  * random  : random long-tail names sampled from the registry's _all_docs index
  Registry tarball of the latest version, size-capped.

Everything is resumable. Raw data lives in data/raw (git-ignored).

Usage (from ml/):  python supplychain/collect.py --malicious 4000 --compromised 300 --popular 2000 --random 2000
"""
import argparse
import json
import random
import re
import shutil
import string
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
RAW = HERE / "data" / "raw"
DD_REPO = "DataDog/malicious-software-packages-dataset"
DD_RAW = f"https://raw.githubusercontent.com/{DD_REPO}/main/"
OSSF_URL = "https://github.com/ossf/malicious-packages.git"
TOP_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
REGISTRY = "https://registry.npmjs.org/"
ALL_DOCS = "https://replicate.npmjs.com/_all_docs"
MAX_TARBALL_BYTES = 5 * 1024 * 1024
SEED = 42

session = requests.Session()
session.headers["User-Agent"] = "medianet-pfe-research/1.0 (defensive supply-chain study)"


def log(msg):
    print(msg, flush=True)


def get(url, **kw):
    for attempt in range(4):
        try:
            r = session.get(url, timeout=40, **kw)
            if r.status_code in (429, 502, 503):
                time.sleep(2 * (attempt + 1))
                continue
            return r
        except requests.RequestException:
            time.sleep(1 + attempt)
    return None


# ----------------------------------------------------------------------------- OSSF
def collect_ossf():
    out = RAW / "ossf_npm.jsonl"
    if out.exists():
        log(f"[ossf] already collected: {out}")
        return
    repo = RAW / "ossf_malicious.git"
    if repo.exists():
        shutil.rmtree(repo, ignore_errors=True)
    log("[ossf] cloning OSV reports (no checkout: Windows-safe, read through git objects)...")
    subprocess.run(["git", "clone", "--depth", "1", "--no-checkout", "-q", OSSF_URL, str(repo)], check=True)
    ls = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD", "--", "osv/malicious/npm"],
                        capture_output=True, text=True, check=True).stdout.splitlines()
    entries = []
    for line in ls:
        meta, path = line.split("\t", 1)
        if path.endswith(".json"):
            entries.append((meta.split()[2], path))
    log(f"[ossf] {len(entries)} npm reports")
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    rows = []
    for sha, path in entries:
        proc.stdin.write((sha + "\n").encode())
        proc.stdin.flush()
        header = proc.stdout.readline().split()
        size = int(header[2])
        body = proc.stdout.read(size)
        proc.stdout.read(1)
        try:
            doc = json.loads(body)
        except ValueError:
            continue
        for aff in doc.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem", "").lower() != "npm":
                continue
            rows.append({
                "id": doc.get("id"), "name": pkg.get("name"), "versions": aff.get("versions"),
                "published": doc.get("published"), "modified": doc.get("modified"),
                "summary": (doc.get("summary") or "")[:200], "path": path,
            })
    proc.stdin.close()
    proc.wait()
    shutil.rmtree(repo, ignore_errors=True)
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    log(f"[ossf] wrote {len(rows)} rows -> {out}")


# ----------------------------------------------------------------------------- DataDog
def list_datadog_npm_zips():
    r = get(f"https://api.github.com/repos/{DD_REPO}/git/trees/main?recursive=1")
    tree = r.json().get("tree", []) if r is not None and r.ok else []
    cache = RAW / "dd_tree.json"
    if tree:
        cache.write_text(json.dumps(tree), encoding="utf-8")
    elif cache.exists():
        tree = json.loads(cache.read_text(encoding="utf-8"))
    zips = []
    for t in tree:
        p = t["path"]
        m = re.match(r"samples/npm/(malicious_intent|compromised_lib)/(.+)/([^/]+)/[^/]+\.zip$", p)
        if m:
            zips.append({"kind": m.group(1), "name": m.group(2), "version": m.group(3), "path": p})
    return zips


def download_one(item, dest_dir):
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{item['name']}__{item['version']}")
    dest = dest_dir / item["kind"] / f"{safe}.zip"
    if dest.exists() and dest.stat().st_size > 0:
        return item, dest, True
    r = get(DD_RAW + urllib.parse.quote(item["path"]))
    if r is None or not r.ok or len(r.content) > 20 * 1024 * 1024:
        return item, None, False
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(r.content)
    return item, dest, True


def collect_datadog(n_malicious, n_compromised):
    manifest = RAW / "manifest_malicious.jsonl"
    zips = list_datadog_npm_zips()
    log(f"[datadog] {len(zips)} npm samples listed")
    rng = random.Random(SEED)
    chosen = []
    for kind, n in (("malicious_intent", n_malicious), ("compromised_lib", n_compromised)):
        by_pkg = {}
        for z in zips:
            if z["kind"] == kind:
                by_pkg.setdefault(z["name"], z)  # one version per package
        pool = sorted(by_pkg.values(), key=lambda z: z["name"])
        rng.shuffle(pool)
        chosen.extend(pool[:n])
    log(f"[datadog] downloading {len(chosen)} encrypted ZIPs (kept encrypted on disk)")
    rows = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(download_one, z, RAW / "datadog_npm") for z in chosen]
        for i, f in enumerate(as_completed(futures), 1):
            item, dest, ok = f.result()
            if ok:
                rows.append({**item, "file": str(dest.relative_to(RAW)), "label": 1})
            if i % 500 == 0:
                log(f"  {i}/{len(chosen)}")
    manifest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    log(f"[datadog] {len(rows)} samples downloaded -> {manifest}")


# ----------------------------------------------------------------------------- benign
def popular_names(n):
    r = get(TOP_URL)
    names = re.findall(r"^\s*'([^']+)',?\s*$", r.text, flags=re.M) if r is not None else []
    return names[:n]


def random_names(n, rng):
    """Random long-tail names: parallel _all_docs probes at random start keys."""
    alphabet = string.ascii_lowercase + string.digits

    def probe(key):
        r = get(ALL_DOCS, params={"limit": 5, "startkey": json.dumps(key)})
        if r is None or not r.ok:
            return []
        return [row["id"] for row in r.json().get("rows", [])]

    names, seen = [], set()
    while len(names) < n:
        keys = ["".join(rng.choice(alphabet) for _ in range(rng.randint(2, 5))) for _ in range(160)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            for batch in pool.map(probe, keys):
                for nm in batch:
                    if nm not in seen:
                        seen.add(nm)
                        names.append(nm)
        log(f"  random names: {len(names)}/{n}")
    return names[:n]


def fetch_benign(name, source, dest_dir):
    r = get(REGISTRY + urllib.parse.quote(name, safe="@"),
            headers={"Accept": "application/vnd.npm.install-v1+json"})
    if r is None or not r.ok:
        return None
    doc = r.json()
    versions = doc.get("versions") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    if not latest or latest not in versions:
        return None
    if all("security" in v for v in versions):  # npm's takedown placeholder, not a real package
        return None
    dist = versions[latest].get("dist") or {}
    if (dist.get("unpackedSize") or 0) > 3 * MAX_TARBALL_BYTES:
        return None
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{name}__{latest}")
    dest = dest_dir / f"{safe}.tgz"
    if not (dest.exists() and dest.stat().st_size > 0):
        t = get(dist.get("tarball", ""))
        if t is None or not t.ok or len(t.content) > MAX_TARBALL_BYTES:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(t.content)
    return {"name": name, "version": latest, "source": source, "n_versions": len(versions),
            "file": str(dest.relative_to(RAW)), "label": 0}


def collect_benign(n_popular, n_random, forbidden):
    manifest = RAW / "manifest_benign.jsonl"
    rng = random.Random(SEED)
    plan = [(n, "popular") for n in popular_names(n_popular + 200)]
    plan = plan[:n_popular]
    plan += [(n, "random") for n in random_names(int(n_random * 1.4), rng)]
    plan = [(n, s) for n, s in plan if n.lower() not in forbidden]
    log(f"[benign] fetching up to {len(plan)} registry tarballs")
    rows = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(fetch_benign, n, s, RAW / "benign_npm") for n, s in plan]
        for i, f in enumerate(as_completed(futures), 1):
            res = f.result()
            if res:
                rows.append(res)
            if i % 500 == 0:
                log(f"  {i}/{len(plan)} ({len(rows)} kept)")
    manifest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    log(f"[benign] {len(rows)} packages -> {manifest}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", type=int, default=4000)
    ap.add_argument("--compromised", type=int, default=300)
    ap.add_argument("--popular", type=int, default=2000)
    ap.add_argument("--random", type=int, default=2500)
    ap.add_argument("--skip", nargs="*", default=[], choices=["ossf", "datadog", "benign"])
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)

    if "ossf" not in args.skip:
        collect_ossf()
    if "datadog" not in args.skip:
        collect_datadog(args.malicious, args.compromised)

    forbidden = set()
    for f in (RAW / "ossf_npm.jsonl", RAW / "manifest_malicious.jsonl"):
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    forbidden.add(json.loads(line)["name"].lower())
    for z in list_datadog_npm_zips():
        forbidden.add(z["name"].lower())
    log(f"[benign] {len(forbidden)} known-malicious names excluded from the benign pool")
    if "benign" not in args.skip:
        collect_benign(args.popular, args.random, forbidden)
    log("done")


if __name__ == "__main__":
    sys.exit(main())
