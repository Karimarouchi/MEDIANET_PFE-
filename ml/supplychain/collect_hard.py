#!/usr/bin/env python3
"""
Improvement 1b - thousands of HARD NEGATIVES.

A hard negative is a LEGITIMATE package that runs an install script (native add-ons, binary
downloaders, git hooks, build helpers). This is exactly what produces false alarms in the wild,
and we only had ~600 of them (17 in the test split) - far too few to measure or to learn from.

We query the npm search endpoint with many topics that tend to need install-time work, keep the
names, fetch the (small) registry metadata, and keep only packages whose latest version has
`hasInstallScript`. Known-malicious names are excluded. Resumable.

Usage (from ml/):  python supplychain/collect_hard.py --target 6000
"""
import argparse
import hashlib
import json
import random
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

import collect as c

TOPICS = """postinstall node-gyp native addon prebuild prebuild-install node-pre-gyp node-gyp-build binding.gyp n-api napi
cmake-js electron electron-rebuild puppeteer playwright chromedriver geckodriver phantomjs cypress husky patch-package
opencollective core-js sharp canvas sqlite3 better-sqlite3 bcrypt argon2 node-sass sass-embedded grpc protobuf
leveldown rocksdb fsevents esbuild swc rollup-native lightningcss parcel watchman serialport usb node-hid noble bluetooth
robotjs nodegit libxmljs sodium libsodium zeromq nanomsg ffi ref napi-rs neon rust wasm emscripten cpp c++ binary
download-binary install-script setup postbuild preinstall gyp python-build tensorflow onnx opencv ffmpeg imagemagick
sqlite postgres native-driver oracledb odbc ibm_db snowflake kerberos mongodb-native bson-ext snappy lz4 zstd brotli
node-canvas pdf-lib pdfkit tesseract ocr speech audio midi gpio raspberry arduino johnny-five firmata
fibers re2 farmhash xxhash blake3 crc32 murmurhash bufferutil utf-8-validate ws-native iconv uuid-native
git-hooks lefthook simple-git-hooks pre-commit lint-staged commitizen cz-conventional-changelog semantic-release
playwright-core chromium-bidi webdriver selenium protractor appium wdio nightwatch testcafe jest-puppeteer
postinstall-postinstall rimraf-postinstall nodemon-native sentry-cli sentry-cli-binary datadog-native gyp-next
node-addon-api nan node-api-headers bindings prebuildify cross-env patch fix-esm ts-patch tsc-alias
ngrok localtunnel cloudflared terraform kubectl helm docker-compose aws-cli gcloud az-cli firebase-tools
dotenv-vault doppler infisical vault-cli keytar credential-manager node-keytar libsecret
@swc/core @esbuild @parcel @napi-rs @rollup @next/swc @biomejs @oxc @farmfe @ast-grep""".split()
EXTRA = ["install script", "native module", "binary download", "compiles on install", "downloads on install",
         "node-gyp rebuild", "requires python", "requires make", "requires compiler", "prebuilt binaries"]


def search(query, pages=4, size=250):
    out = []
    for i in range(pages):
        r = c.get("https://registry.npmjs.org/-/v1/search", params={"text": query, "size": size, "from": i * size})
        if r is None or not r.ok:
            break
        objs = r.json().get("objects", [])
        out += [o["package"]["name"] for o in objs]
        if len(objs) < size:
            break
    return out


def fetch_hard(name, dest_dir):
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
    if not meta.get("hasInstallScript"):
        return None
    dist = meta.get("dist") or {}
    if (dist.get("unpackedSize") or 0) > 3 * c.MAX_TARBALL_BYTES:
        return None
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{name}__{latest}")
    if len(safe) > 90:
        safe = safe[:70] + "_" + hashlib.sha1(safe.encode()).hexdigest()[:12]
    dest = dest_dir / f"{safe}.tgz"
    if not (dest.exists() and dest.stat().st_size > 0):
        t = c.get(dist.get("tarball", ""))
        if t is None or not t.ok or len(t.content) > c.MAX_TARBALL_BYTES:
            return None
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(t.content)
    return {"name": name, "version": latest, "source": "hard_negative", "n_versions": len(versions),
            "file": str(dest.relative_to(c.RAW)), "label": 0, "has_install_script_meta": True}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=6000)
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
    n_existing_hard = sum(1 for l in manifest.read_text(encoding="utf-8").splitlines()
                          if l.strip() and json.loads(l)["source"] == "hard_negative")
    c.log(f"[hard] already have {n_existing_hard} hard negatives; target total {args.target}")

    queries = list(dict.fromkeys(TOPICS + EXTRA))
    names = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for batch in pool.map(search, queries):
            names += batch
    names = list(dict.fromkeys(names))
    random.Random(c.SEED + 7).shuffle(names)
    todo = [n for n in names if n.lower() not in existing and n.lower() not in forbidden]
    c.log(f"[hard] {len(names)} names from search, {len(todo)} new candidates")

    kept, rows = 0, []
    need = args.target - n_existing_hard
    with ThreadPoolExecutor(max_workers=14) as pool:
        futures = [pool.submit(fetch_hard, n, c.RAW / "benign_npm") for n in todo]
        for i, f in enumerate(as_completed(futures), 1):
            try:
                row = f.result()
            except Exception as exc:
                row = None
            if row:
                rows.append(row)
                kept += 1
            if i % 500 == 0:
                c.log(f"  {i}/{len(todo)} ({kept} hard negatives kept)")
                with manifest.open("a", encoding="utf-8") as fh:
                    fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
                rows = []
                if kept >= need:
                    for fu in futures:
                        fu.cancel()
                    break
    if rows:
        with manifest.open("a", encoding="utf-8") as fh:
            fh.write("\n".join(json.dumps(r) for r in rows) + "\n")
    c.log(f"[hard] +{kept} hard negatives")
    c.log("done")


if __name__ == "__main__":
    sys.exit(main())
