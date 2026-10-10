#!/usr/bin/env python3
"""
Improvement 5 - second ecosystem: PyPI (same method as npm).

Malicious (label 1)  DataDog samples/pypi (encrypted ZIPs, never extracted) + OSSF pypi reports (names)
Benign (label 0)     top-downloaded PyPI projects + a random sample of the whole index.
                     Only SOURCE distributions (sdist) are used: they contain setup.py, the file where
                     install-time attacks live, exactly like the malicious samples.

Usage (from ml/):  python supplychain/collect_pypi.py --malicious 4000 --popular 3000 --random 9000
"""
import argparse
import hashlib
import json
import random
import re
import shutil
import subprocess
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import collect as c

RAW = c.RAW
DD_URL = f"https://github.com/{c.DD_REPO}.git"
TOP_PYPI = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
SIMPLE = "https://pypi.org/simple/"
MAX_BYTES = 5 * 1024 * 1024


def clone_tree(url, workdir):
    if workdir.exists():
        shutil.rmtree(workdir, ignore_errors=True)
    subprocess.run(["git", "clone", "--depth", "1", "--no-checkout", "--filter=blob:none", "-q", url, str(workdir)],
                   check=True)


def collect_ossf_pypi():
    out = RAW / "ossf_pypi.jsonl"
    if out.exists():
        c.log("[ossf-pypi] already collected")
        return
    repo = RAW / "ossf_pypi.git"
    subprocess.run(["git", "clone", "--depth", "1", "--no-checkout", "-q", c.OSSF_URL, str(repo)], check=True)
    ls = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD", "--", "osv/malicious/pypi"],
                        capture_output=True, text=True, check=True).stdout.splitlines()
    entries = [(m.split()[2], p) for m, p in (l.split("\t", 1) for l in ls) if p.endswith(".json")]
    proc = subprocess.Popen(["git", "-C", str(repo), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    rows = []
    for sha, path in entries:
        proc.stdin.write((sha + "\n").encode())
        proc.stdin.flush()
        size = int(proc.stdout.readline().split()[2])
        body = proc.stdout.read(size)
        proc.stdout.read(1)
        try:
            doc = json.loads(body)
        except ValueError:
            continue
        for aff in doc.get("affected", []):
            pkg = aff.get("package", {})
            if pkg.get("ecosystem", "").lower() == "pypi":
                rows.append({"id": doc.get("id"), "name": pkg.get("name"), "versions": aff.get("versions"),
                             "published": doc.get("published")})
    proc.stdin.close()
    proc.wait()
    shutil.rmtree(repo, ignore_errors=True)
    out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    c.log(f"[ossf-pypi] {len(rows)} reports")


def list_datadog_pypi():
    repo = RAW / "dd_blobless.git"
    clone_tree(DD_URL, repo)
    ls = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD", "--name-only", "--", "samples/pypi"],
                        capture_output=True, text=True, check=True).stdout.splitlines()
    shutil.rmtree(repo, ignore_errors=True)
    zips = []
    for p in ls:
        m = re.match(r"samples/pypi/(malicious_intent|compromised_lib)/(.+)/([^/]+)/[^/]+\.zip$", p)
        if m:
            zips.append({"kind": m.group(1), "name": m.group(2), "version": m.group(3), "path": p})
    return zips


def collect_malicious(n):
    manifest = RAW / "manifest_malicious_pypi.jsonl"
    zips = list_datadog_pypi()
    c.log(f"[datadog-pypi] {len(zips)} samples listed")
    rng = random.Random(c.SEED)
    by_pkg = {}
    for z in zips:
        by_pkg.setdefault(z["name"], z)
    pool = sorted(by_pkg.values(), key=lambda z: z["name"])
    rng.shuffle(pool)
    chosen = pool[:n]
    rows = []
    with ThreadPoolExecutor(max_workers=16) as ex:
        futs = [ex.submit(c.download_one, z, RAW / "datadog_pypi") for z in chosen]
        for i, f in enumerate(as_completed(futs), 1):
            item, dest, ok = f.result()
            if ok:
                rows.append({**item, "file": str(dest.relative_to(RAW)), "label": 1})
            if i % 500 == 0:
                c.log(f"  {i}/{len(chosen)}")
    manifest.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    c.log(f"[datadog-pypi] {len(rows)} downloaded")


def pypi_names(n_popular, n_random, rng):
    top = c.get(TOP_PYPI)
    popular = [r["project"] for r in top.json()["rows"]][:n_popular] if top is not None and top.ok else []
    idx = c.get(SIMPLE, headers={"Accept": "application/vnd.pypi.simple.v1+json"})
    allnames = [p["name"] for p in idx.json()["projects"]] if idx is not None and idx.ok else []
    rng.shuffle(allnames)
    return [(n, "popular") for n in popular], [(n, "random") for n in allnames[: int(n_random * 1.5)]]


def fetch_benign(name, source, dest_dir):
    r = c.get(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if r is None or not r.ok:
        return None
    doc = r.json()
    sdists = [u for u in doc.get("urls", []) if u.get("packagetype") == "sdist" and (u.get("size") or 0) <= MAX_BYTES]
    if not sdists:
        return None
    u = sdists[0]
    ext = ".zip" if u["filename"].endswith(".zip") else ".tgz"
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{name}__{doc['info']['version']}")
    if len(safe) > 90:
        safe = safe[:70] + "_" + hashlib.sha1(safe.encode()).hexdigest()[:12]
    dest = dest_dir / f"{safe}{ext}"
    if not (dest.exists() and dest.stat().st_size > 0):
        t = c.get(u["url"])
        if t is None or not t.ok or len(t.content) > MAX_BYTES:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(t.content)
    return {"name": name, "version": doc["info"]["version"], "source": source, "n_versions": len(doc.get("releases", {})),
            "file": str(dest.relative_to(RAW)), "label": 0}


def collect_benign(n_popular, n_random, forbidden):
    manifest = RAW / "manifest_benign_pypi.jsonl"
    rng = random.Random(c.SEED)
    pop, rnd = pypi_names(n_popular, n_random, rng)
    todo = [(n, s) for n, s in pop + rnd if n.lower() not in forbidden]
    c.log(f"[benign-pypi] fetching up to {len(todo)} sdists")
    rows, kept = [], 0
    with ThreadPoolExecutor(max_workers=14) as ex:
        futs = [ex.submit(fetch_benign, n, s, RAW / "benign_pypi") for n, s in todo]
        for i, f in enumerate(as_completed(futs), 1):
            try:
                row = f.result()
            except Exception:
                row = None
            if row:
                rows.append(row)
                kept += 1
            if i % 1000 == 0:
                c.log(f"  {i}/{len(todo)} ({kept} kept)")
                with manifest.open("a", encoding="utf-8") as fh:
                    fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
                rows = []
                if kept >= n_popular + n_random:
                    break
    if rows:
        with manifest.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
    c.log(f"[benign-pypi] {kept} kept")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", type=int, default=4000)
    ap.add_argument("--popular", type=int, default=3000)
    ap.add_argument("--random", type=int, default=9000)
    args = ap.parse_args()
    RAW.mkdir(parents=True, exist_ok=True)
    collect_ossf_pypi()
    collect_malicious(args.malicious)
    forbidden = set()
    for f in (RAW / "ossf_pypi.jsonl", RAW / "manifest_malicious_pypi.jsonl"):
        if f.exists():
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    forbidden.add(json.loads(line)["name"].lower())
    (RAW / "manifest_benign_pypi.jsonl").unlink(missing_ok=True)
    collect_benign(args.popular, args.random, forbidden)
    c.log("done")


if __name__ == "__main__":
    sys.exit(main())
