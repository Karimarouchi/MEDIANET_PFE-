# Supply-chain screening of npm dependencies

Detects npm packages that **look like malicious packages** (dependency confusion, credential stealers,
droppers, spam farms, empty name-squats), even when they have no CVE. It is an **indicator for review**,
never a release gate (the CI decision stays in `CiScanService`).

## How it works in Medianet

1. A scan finishes → the backend reads `sbom.json` (Syft) and collects the **npm** components.
2. `SupplyChainService` sends them in batches of 40 to `ml/supplychain/score.py` (Python sidecar).
3. For each package the sidecar downloads the tarball **into memory** (5 MB cap, never extracted/installed/
   executed), extracts features, and applies the trained pipeline. Names listed by OSSF malicious-packages are
   reported as `KNOWN_MALICIOUS` without any model.
4. Results are cached in `supply_chain_scores` (30 days, per model version) and shown in the scan page,
   tab **Supply chain**: `GET /api/scans/{id}/supply-chain`, `POST /api/scans/{id}/supply-chain/analyze`.

Tiers: `KNOWN_MALICIOUS` (OSSF list) · `HIGH_CONFIDENCE` (~0.1 % false alarms measured) · `REVIEW` (~1 %) · `LOW`.

## What must be on the server

| Ship | Do NOT ship |
|---|---|
| `supplychain/*.py`, `artifacts/runtime_bundle.joblib` (30 MB), `known_malicious_npm.json`, `top_npm.txt` | `data/raw` (≈1.5 GB of training packages, incl. encrypted malware samples) |
| Python 3.11+ with `requirements-lock.txt` (joblib files are version-sensitive) | `data/clean`, training logs |

Backend properties (all optional): `ml.dir`, `ml.python`, `supplychain.enabled`, `supplychain.auto-analyze`,
`supplychain.model-version` (bump it after re-training: it invalidates the cache), `supplychain.cache-days`,
`supplychain.max-components`, `supplychain.batch-timeout-seconds`.

> The current `Backend/Dockerfile` image contains neither Python nor `ml/`. Without them the screening
> (and the existing remediation model) reports `modelAvailable: false` and the rest of the app is unaffected.

## Re-train / rebuild

```
python supplychain/collect.py && python supplychain/collect_more.py && python supplychain/collect_hard.py
python supplychain/features.py && python supplychain/clean.py && python supplychain/repair.py
python supplychain/train.py            # metrics_supplychain.json (V1..V3 kept for comparison)
python supplychain/export_runtime.py   # runtime_bundle.joblib + parity proof on 400 held-out rows
python -m unittest discover -s tests
```

## Known limits

* Only packages present in the SBOM are screened: a repo without lockfile / `node_modules` yields few npm
  components. npm only (PyPI later).
* Packages above 5 MB are skipped (`TOO_LARGE`, ≈4 % of random packages).
* Training data = public campaigns (DataDog, OSSF); targeted attacks are likely harder. At a real prevalence
  of 1 malicious package in 1,000, expect ≈35 % of `HIGH_CONFIDENCE` alerts to be real.
