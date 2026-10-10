#!/usr/bin/env python3
"""
Command-line sidecar used by the Medianet backend (same pattern as ml/predict.py).

  stdin  : JSON array  [{"name": "lodash", "version": "4.17.21", "ecosystem": "npm"}, ...]
  stdout : JSON array, one object per input, in the same order (never raises for a single bad package)

Packages are downloaded from the registry into memory, analysed as text and discarded: nothing is
installed, extracted to disk or executed. Network and size limits are enforced per package.

Local test without network:  python score.py --archive sample.zip --name some-pkg
"""
import argparse
import json
import sys
import warnings
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

warnings.filterwarnings("ignore")
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")  # the backend reads UTF-8 (accents in the reasons)

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import runtime  # noqa: E402

MAX_PACKAGES = 500
WORKERS = 8


_scorers = {}
SUPPORTED = ("npm", "pypi")


def scorer_for(eco):
    """One model per ecosystem, loaded lazily (a scan of a JavaScript-only project never loads the PyPI one)."""
    if eco not in _scorers:
        try:
            _scorers[eco] = runtime.Scorer(eco)
        except (FileNotFoundError, OSError):
            _scorers[eco] = None  # model of this ecosystem not installed: report it, never crash the batch
    return _scorers[eco]


def score_one(_unused, item):
    name = (item.get("name") or "").strip()
    version = (item.get("version") or "").strip() or None
    eco = (item.get("ecosystem") or "npm").lower()
    if not name:
        return {"name": name, "version": version, "ecosystem": eco, "status": "INVALID", "tier": None,
                "suspicionProba": None, "reasons": []}
    if eco not in SUPPORTED:
        return {"name": name, "version": version, "ecosystem": eco, "status": "UNSUPPORTED_ECOSYSTEM",
                "tier": None, "suspicionProba": None, "reasons": []}
    scorer = scorer_for(eco)
    if scorer is None:
        return {"name": name, "version": version, "ecosystem": eco, "status": "MODEL_UNAVAILABLE",
                "tier": None, "suspicionProba": None, "reasons": []}
    try:
        return runtime.score_package(scorer, name, version)
    except Exception as exc:  # last-resort guard: one package must never break the batch
        return {"name": name, "version": version, "ecosystem": eco, "status": f"ERROR_{type(exc).__name__}",
                "tier": None, "suspicionProba": None, "reasons": []}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--archive", help="score a local archive instead of downloading (testing)")
    ap.add_argument("--name", help="package name for --archive")
    ap.add_argument("--eco", default="npm", choices=SUPPORTED, help="ecosystem for --archive")
    args = ap.parse_args()

    if args.archive:
        path = Path(args.archive)
        kind = "zip" if path.suffix == ".zip" else "tgz"
        out = runtime.score_package(scorer_for(args.eco), args.name or path.stem, None,
                                    archive=path.read_bytes(), kind=kind)
        print(json.dumps(out, ensure_ascii=False))
        return 0

    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({"error": "empty input"}), file=sys.stderr)
        return 2
    items = json.loads(raw)
    if not isinstance(items, list):
        print(json.dumps({"error": "input must be a JSON array"}), file=sys.stderr)
        return 2
    items = items[:MAX_PACKAGES]
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for eco in {(it.get("ecosystem") or "npm").lower() for it in items} & set(SUPPORTED):
            scorer_for(eco)  # load models once, before the worker threads start
        results = list(pool.map(lambda it: score_one(None, it), items))
    print(json.dumps(results, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
