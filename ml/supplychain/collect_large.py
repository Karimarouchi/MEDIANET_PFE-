#!/usr/bin/env python3
"""
Improvement C - LARGE legitimate packages, STREAMED (nothing is stored but the numbers).

A real scan of a Node project showed that the detector flags big, well-known frameworks (react-router,
nodemailer): the first collection capped tarballs at 5 MB and kept mostly small packages, so the model read
"many files" as "unusual".  This adds the missing population: packages with >= 2.5 MB of unpacked code, up to a
25 MB tarball.

Each worker downloads a tarball into memory, computes its feature row, throws the archive away and returns the
row. Disk use stays tiny (a few KB per package); the real cost is network time.

Sources: (1) the top-5000 packages that were skipped for size, (2) big scoped families and framework searches.
Known-malicious names are excluded. Resumable (names already in the output are skipped).
Output: data/clean/features_large.jsonl   (one JSON feature row per line, label 0, kind "large")

Usage (from ml/):  python supplychain/collect_large.py --target 3000
"""
import argparse
import json
import random
import sys
import urllib.parse
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

warnings.filterwarnings("ignore")

import collect as c  # noqa: E402
import features as F  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = HERE / "data" / "clean" / "features_large.jsonl"
MAX_LARGE_TARBALL = 25 * 1024 * 1024
MIN_UNPACKED = int(2.5 * 1024 * 1024)
MAX_UNPACKED = 150 * 1024 * 1024

QUERIES = """@aws-sdk @azure @google-cloud @angular @babel @nestjs @mui @storybook @fortawesome @ant-design @tensorflow
@apollo @sentry @opentelemetry @prisma @nrwl @nx @vue @nuxt @remix-run @tanstack @reduxjs @emotion @mantine @chakra-ui
@swc @esbuild @rollup @vitejs @typescript-eslint @jest @testing-library @playwright @cypress @firebase @supabase @stripe
@octokit @slack @microsoft @salesforce @shopify @strapi @directus @ckeditor @tiptap @fullcalendar @syncfusion @devexpress
webpack typescript react vue angular next nuxt svelte electron aws-cdk firebase three monaco-editor chart d3 pdfjs
moment lodash rxjs express koa fastify nest graphql apollo prisma sequelize typeorm mongoose knex puppeteer playwright
jest mocha cypress eslint prettier babel rollup vite parcel esbuild swc tailwind bootstrap material-ui antd
codemirror quill tinymce ckeditor leaflet mapbox cesium openlayers echarts highcharts plotly fabric konva pixi
socket.io ws redis kafka rabbitmq amqplib bull agenda nodemailer winston pino bunyan passport jsonwebtoken
sharp jimp canvas ffmpeg imagemagick tesseract opencv onnx brain.js aws-sdk googleapis azure-storage twilio
paypal braintree sendgrid mailgun core-js regenerator polyfill zone.js tslib react-router react-dom react-native
expo ionic cordova capacitor nativescript phaser babylonjs aframe""".split()


def search(query, pages=3, size=250):
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


def meta(name):
    """Stage 1 (many threads, tiny requests): is this package large enough? Returns (name, tarball_url, size)."""
    r = c.get(c.REGISTRY + urllib.parse.quote(name, safe="@"), headers={"Accept": "application/vnd.npm.install-v1+json"})
    if r is None or not r.ok:
        return None
    doc = r.json()
    versions = doc.get("versions") or {}
    latest = (doc.get("dist-tags") or {}).get("latest")
    if not latest or latest not in versions or all("security" in v for v in versions):
        return None
    dist = versions[latest].get("dist") or {}
    unpacked = dist.get("unpackedSize") or 0
    if not (MIN_UNPACKED <= unpacked <= MAX_UNPACKED) or not dist.get("tarball"):
        return None
    return name, dist["tarball"], unpacked


def build(name, url):
    """Stage 2 (worker process): download into memory, compute the feature row, discard the archive."""
    t = c.get(url, stream=True)
    if t is None or not t.ok:
        return None
    data = bytearray()
    for chunk in t.iter_content(65536):
        data += chunk
        if len(data) > MAX_LARGE_TARBALL:
            return None
    row = F.normalize_name(name)
    out = {"name": row, "label": 0, "kind": "large", "file": f"large:{name}", "archive_readable": 0}
    out.update(F.name_features(row))
    try:
        out.update(F.content_features(bytes(data), "tgz"))
    except Exception as exc:
        out["error"] = type(exc).__name__
    out["_download_bytes"] = len(data)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", type=int, default=3000)
    ap.add_argument("--workers", type=int, default=8)
    args = ap.parse_args()
    OUT.parent.mkdir(parents=True, exist_ok=True)

    seen = {json.loads(l)["name"].lower() for l in OUT.read_text(encoding="utf-8").splitlines() if l.strip()} \
        if OUT.exists() else set()
    existing = {json.loads(l)["name"].lower() for l in (c.RAW / "manifest_benign.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()}
    forbidden = set()
    for f in (c.RAW / "ossf_npm.jsonl", c.RAW / "manifest_malicious.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                forbidden.add(json.loads(line)["name"].lower())
    for z in c.list_datadog_npm_zips():
        forbidden.add(z["name"].lower())

    top = (c.RAW / "top_npm.txt").read_text(encoding="utf-8").splitlines()
    names = []
    with ProcessPoolExecutor(max_workers=4) as pool:
        for batch in pool.map(search, list(dict.fromkeys(QUERIES))):
            names += batch
    rest = list(dict.fromkeys(names))
    random.Random(c.SEED + 11).shuffle(rest)
    # popular first: these are the packages real projects actually depend on
    todo = [n for n in list(dict.fromkeys(top)) + rest
            if n.lower() not in seen and n.lower() not in forbidden]
    # packages already collected are only skipped when they were NOT dropped for size: re-check the popular ones
    c.log(f"[large] {len(todo)} candidates; target {args.target} large packages; {len(seen)} already done")

    from concurrent.futures import ThreadPoolExecutor
    kept, total_bytes, scanned = len(seen), 0, 0
    pending = []

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

    with ThreadPoolExecutor(max_workers=24) as meta_pool, ProcessPoolExecutor(max_workers=args.workers) as build_pool,             OUT.open("a", encoding="utf-8") as fh:
        meta_futs = [meta_pool.submit(meta, n) for n in todo]
        for f in as_completed(meta_futs):          # O(1) per candidate: no re-scan of the 100k-future set
            scanned += 1
            try:
                res = f.result()
            except Exception:
                res = None
            if res and kept + len(pending) < args.target:
                pending.append(build_pool.submit(build, res[0], res[1]))
            harvest(fh)
            if scanned % 500 == 0:
                c.log(f"  {scanned}/{len(todo)} checked, {kept} large kept, {len(pending)} downloading, "
                      f"{total_bytes / 1e9:.2f} GB downloaded")
            if kept >= args.target:
                break
        for fu in meta_futs:
            fu.cancel()
        harvest(fh, block=True)
    c.log(f"[large] {kept} large legitimate packages, {total_bytes / 1e9:.2f} GB downloaded this run")
    c.log("done")


if __name__ == "__main__":
    sys.exit(main())
