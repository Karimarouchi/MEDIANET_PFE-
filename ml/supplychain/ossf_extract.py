#!/usr/bin/env python3
"""
Extract the OSSF malicious-packages reports (OSV format) with BOTH ways OSV states the affected versions:

  * affected[].versions : an explicit list of versions
  * affected[].ranges   : intervals of events  (introduced / fixed / last_affected)

The first version of this extraction kept only the explicit list. A report that states its scope with a
RANGE (for example fsevents: every version below 1.2.11 downloaded a malicious binary) then looked like
"every version is malicious", so a perfectly safe fsevents 2.3.3 was reported as KNOWN_MALICIOUS. A false alert at
the strictest tier is the worst kind, so the scope is now kept exactly as the report states it.

Scope semantics stored per package in known_malicious_<eco>.json:
    {"id":..., "all": true,  "versions": [], "ranges": []}              every version (no scope given)
    {"id":..., "all": false, "versions": [...], "ranges": [[events]]}   only those versions / intervals

Usage (from ml/):  python supplychain/ossf_extract.py            # npm and pypi
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "data" / "raw"
ART = {"npm": HERE / "artifacts", "pypi": HERE / "artifacts_pypi"}
OSSF_URL = "https://github.com/ossf/malicious-packages.git"


def extract(eco: str) -> list[dict]:
    # clone on the system disk: Git refuses repositories owned by another user (the external disk), exit 128
    import tempfile
    repo = Path(tempfile.mkdtemp(prefix=f"ossf_{eco}_")) / "clone.git"
    subprocess.run(["git", "clone", "--depth", "1", "--no-checkout", "-q", OSSF_URL, str(repo)], check=True)
    ls = subprocess.run(["git", "-C", str(repo), "ls-tree", "-r", "HEAD", "--", f"osv/malicious/{eco}"],
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
            if pkg.get("ecosystem", "").lower() != eco:
                continue
            ranges = []
            for rg in aff.get("ranges") or []:
                if rg.get("type") in ("SEMVER", "ECOSYSTEM"):  # GIT ranges are commit hashes: not usable here
                    events = [e for e in rg.get("events", []) if any(k in e for k in ("introduced", "fixed", "last_affected"))]
                    if events:
                        ranges.append(events)
            rows.append({"id": doc.get("id"), "name": pkg.get("name"), "versions": aff.get("versions") or None,
                         "ranges": ranges or None, "published": doc.get("published"),
                         "git_only": bool(aff.get("ranges")) and not ranges})
    proc.stdin.close()
    proc.wait()
    shutil.rmtree(repo.parent, ignore_errors=True)
    return rows


def normalize(eco: str, name: str) -> str:
    import re
    return re.sub(r"[-_.]+", "-", name.strip()).lower() if eco == "pypi" else _npm_norm(name)


def _npm_norm(name: str) -> str:
    import re
    m = re.match(r"^(@[^@/]+)@(.+)$", name or "")
    return (f"{m.group(1)}/{m.group(2)}" if m else name).lower()


def build_known(rows: list[dict], eco: str) -> dict:
    known: dict = {}
    for r in rows:
        key = normalize(eco, r["name"])
        if r["git_only"] and not r["versions"]:
            continue  # scope given only as commits: cannot be matched to a release, so never claim "malicious"
        # OSV states "every version" either with no scope, or with the open interval "introduced 0, never fixed"
        open_interval = any(len(ev) == 1 and ev[0].get("introduced") in ("0", "0.0.0") for ev in (r["ranges"] or []))
        if (not r["versions"] and not r["ranges"]) or open_interval:
            known[key] = {"id": r["id"], "all": True, "versions": [], "ranges": []}  # whole package is malicious
            continue
        if key in known and known[key]["all"]:
            continue  # already "all versions"
        e = known.get(key) or {"id": r["id"], "all": False, "versions": [], "ranges": []}
        e["versions"] = sorted(set(e["versions"]) | set(r["versions"] or []))
        e["ranges"] = e["ranges"] + (r["ranges"] or [])
        known[key] = e
    return known


def main():
    for eco in ("npm", "pypi"):
        rows = extract(eco)
        out = RAW / f"ossf_{eco}.jsonl"
        out.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
        known = build_known(rows, eco)
        ART[eco].mkdir(exist_ok=True)
        (ART[eco] / f"known_malicious_{eco}.json").write_text(json.dumps(known, separators=(",", ":")), encoding="utf-8")
        whole = sum(1 for v in known.values() if v["all"])
        scoped = len(known) - whole
        print(f"{eco}: {len(rows)} reports -> {len(known)} packages | {whole} entirely malicious | {scoped} with a version scope")


if __name__ == "__main__":
    sys.exit(main())
