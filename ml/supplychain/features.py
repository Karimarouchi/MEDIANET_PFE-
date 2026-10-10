#!/usr/bin/env python3
"""
Step 5 (raw part) - turn every package archive into one row of numbers.

Deterministic per package: nothing here is learned from the dataset, so running it before
the train/val/test split cannot leak information.

Safety: archives are read IN MEMORY as bytes/text. Nothing is extracted to disk, installed,
imported or executed.

Design rule - SYMMETRIC features only. Malicious packages are removed from the registry, so
registry metadata (downloads, account age, version history, publish date) exists only for the
benign class. Using it would let the model learn "metadata exists -> benign", an artefact of how
the data was collected. Every feature below comes from the package CONTENT or its NAME, which we
have for both classes. Version number / number of versions are deliberately NOT used (benign =
latest version, malicious = the single reported version).

Usage (from ml/):  python supplychain/features.py
"""
import hashlib
import io
import json
import math
import re
import sys
import tarfile
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd
import requests
from rapidfuzz import process
from rapidfuzz.distance import Levenshtein

import astfeat

HERE = Path(__file__).resolve().parent
RAW = HERE / "data" / "raw"
OUT = HERE / "data" / "clean" / "features_raw.csv"
_ART_TOP = HERE / "artifacts" / "top_npm.txt"
TOP_FILE = _ART_TOP if _ART_TOP.exists() else RAW / "top_npm.txt"  # artifacts/ ships with the model
TOP_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"
ZIP_PASSWORD = b"infected"
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 3000
TEXT_EXT = (".js", ".cjs", ".mjs", ".ts", ".json", ".sh", ".bat", ".cmd", ".ps1", ".py", ".node")

INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
SUSPICIOUS_SCRIPT = re.compile(r"\b(curl|wget|powershell|bash|sh -c|node -e|eval|base64|http://|https://)\b", re.I)

# name -> compiled regex counted over all JS-like source
CODE_PATTERNS = {
    "n_eval": r"\beval\s*\(",
    "n_new_function": r"\bnew\s+Function\s*\(",
    "n_child_process": r"child_process|\bexecSync\b|\bspawnSync\b|\.exec\s*\(|\.spawn\s*\(",
    "n_network_module": r"require\(\s*['\"](?:https?|net|dgram|tls|dns)['\"]\s*\)|\bfetch\s*\(|XMLHttpRequest|axios|node-fetch",
    "n_env_access": r"process\.env",
    "n_host_recon": r"os\.(?:homedir|userInfo|hostname|networkInterfaces|platform)\s*\(",
    "n_sensitive_path": r"\.ssh|\.npmrc|\.aws|\.env\b|id_rsa|wallet|passwd|\.git-credentials|Login Data|Local Storage",
    "n_base64": r"base64|\batob\s*\(|\bbtoa\s*\(",
    "n_charcode": r"fromCharCode|\\x[0-9a-fA-F]{2}",
    "n_obfuscator_ident": r"\b_0x[0-9a-fA-F]{3,}\b",
    "n_exfil_domain": r"discord(?:app)?\.com/api/webhooks|pastebin\.com|ngrok|webhook\.site|requestbin|interact\.sh|oast\.|burpcollaborator|pipedream|telegram\.org/bot|transfer\.sh|\.onion",
    "n_ip_literal": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "n_url_literal": r"https?://[^\s'\"`)]+",
    "n_fs_write": r"writeFile(?:Sync)?\s*\(|appendFile",
    "n_download_exec": r"(?:curl|wget)[^\n]{0,80}\|\s*(?:sh|bash)|chmod\s+\+x",
}
COMPILED = {k: re.compile(v) for k, v in CODE_PATTERNS.items()}


def load_top_names(n=5000):
    if not TOP_FILE.exists():
        text = requests.get(TOP_URL, timeout=40).text
        names = re.findall(r"^\s*'([^']+)',?\s*$", text, flags=re.M)
        TOP_FILE.write_text("\n".join(names), encoding="utf-8")
    return TOP_FILE.read_text(encoding="utf-8").splitlines()[:n]


TOP_NAMES = load_top_names()


SCOPE_AT_RX = re.compile(r"^(@[^@/]+)@(.+)$")


def normalize_name(name: str) -> str:
    """DataDog stores scoped packages as '@scope@pkg' while the npm registry (our benign side) writes
    '@scope/pkg'. Left alone, the model would learn the spelling instead of the danger."""
    m = SCOPE_AT_RX.match(name or "")
    return f"{m.group(1)}/{m.group(2)}" if m else name


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


VOWELS = set("aeiou")
SPAM_SHAPE = re.compile(r"^[a-z]+-[a-z]+\d+-[a-z]+$")  # word-wordNN-word (generated names)
TOKEN_SPLIT = re.compile(r"[-_.]+")
DIGIT_INSIDE = re.compile(r"[a-z]\d+[a-z]")
TRAILING_DIGITS = re.compile(r"\d+$")


def name_shape_features(bare: str) -> dict:
    """How the name is BUILT, independent of what it resembles: generated / spam-farm names
    ('ade-klanting44-sukiwir') have a recognisable shape that human-chosen names rarely have."""
    low = bare.lower()
    tokens = [t for t in TOKEN_SPLIT.split(low) if t]
    letters = [ch for ch in low if ch.isalpha()]
    vowel_ratio = (sum(ch in VOWELS for ch in letters) / len(letters)) if letters else 0.0
    run = longest = 0
    for ch in low:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            longest = max(longest, run)
        else:
            run = 0
    counts = {}
    for ch in low:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = -sum(c / len(low) * math.log2(c / len(low)) for c in counts.values()) if low else 0.0
    return {
        "name_n_tokens": len(tokens),
        "name_max_token_len": max((len(t) for t in tokens), default=0),
        "name_tokens_with_digits": sum(any(ch.isdigit() for ch in t) for t in tokens),
        "name_digit_inside_token": int(bool(DIGIT_INSIDE.search(low))),
        "name_trailing_digits": int(bool(TRAILING_DIGITS.search(low))),
        "name_vowel_ratio": vowel_ratio,
        "name_longest_consonant_run": longest,
        "name_char_entropy": entropy,
        "name_spam_shape": int(bool(SPAM_SHAPE.match(low))),
        "name_all_lowercase_alpha": int(low.replace("-", "").replace("_", "").isalpha()),
    }


def name_features(name: str, top_names=None) -> dict:
    bare = name.split("/", 1)[1] if name.startswith("@") and "/" in name else name
    others = [t for t in (top_names or TOP_NAMES) if t.lower() != name.lower()]  # never compare a package with itself
    best = process.extractOne(bare.lower(), [o.lower() for o in others], scorer=Levenshtein.distance)
    dist = best[1] if best else None
    return {
        **name_shape_features(bare),
        "name_len": len(bare),
        "name_digits": sum(c.isdigit() for c in bare),
        "name_hyphens": bare.count("-") + bare.count("_") + bare.count("."),
        "name_has_scope": int(name.startswith("@")),
        "name_min_edit_dist": dist,
        "name_edit_dist_norm": None if dist is None else dist / max(len(bare), 1),
        "name_near_popular": int(dist is not None and dist <= 2 and len(bare) >= 4),
    }


def read_members(blob: bytes, kind: str):
    """Yield (path, bytes) of text-like members, in memory only."""
    total = 0
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for i, info in enumerate(zf.infolist()):
                if info.is_dir() or i > MAX_MEMBERS:
                    continue
                if not info.filename.lower().endswith(TEXT_EXT) and "readme" not in info.filename.lower():
                    continue
                if info.file_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    continue
                try:
                    data = zf.read(info, pwd=ZIP_PASSWORD)
                except Exception:
                    continue
                total += len(data)
                yield info.filename, data
    else:
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for i, m in enumerate(tf):
                if not m.isfile() or i > MAX_MEMBERS:
                    continue
                if not m.name.lower().endswith(TEXT_EXT) and "readme" not in m.name.lower():
                    continue
                if m.size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                data = f.read()
                total += len(data)
                yield m.name, data


KNOWN_BUILD_TOOL = re.compile(
    r"node-gyp|prebuild-install|node-pre-gyp|prebuildify|cmake-js|node-gyp-build|electron-rebuild|husky|"
    r"patch-package|opencollective|lefthook|simple-git-hooks|napi|node-addon|\btsc\b|esbuild|rimraf|gulp|webpack|"
    r"npm run|yarn run|pnpm|is-ci|ts-node|rollup|babel|lerna|prisma|cross-env|\bmake\b|cmake|opencollective", re.I)
KNOWN_HOST = re.compile(
    r"github\.com|githubusercontent\.com|nodejs\.org|npmjs\.(?:org|com)|registry\.npmjs|storage\.googleapis\.com|"
    r"cdn\.jsdelivr|unpkg\.com|electronjs\.org|googleapis|s3\.amazonaws\.com|azureedge|gitlab\.com|bitbucket", re.I)
URL_RX = re.compile(r"https?://([A-Za-z0-9.-]+)[^\s'\"`)]*")
LOCAL_FILE_RX = re.compile(r"[\w./@-]+\.(?:c?js|mjs|sh|bat|cmd|ps1|py)\b", re.I)
NET_RX = re.compile(r"require\(\s*['\"](?:https?|net|dgram|tls|dns)['\"]\s*\)|\bfetch\s*\(|XMLHttpRequest|axios|https?\.get|https?\.request")
ENV_RX = re.compile(r"process\.env|os\.(?:homedir|userInfo|hostname|networkInterfaces)")
SENSITIVE_RX = re.compile(r"\.ssh|\.npmrc|\.aws|id_rsa|wallet|passwd|\.git-credentials|Login Data|Local Storage")
EXFIL_RX = re.compile(r"discord(?:app)?\.com/api/webhooks|pastebin|ngrok|webhook\.site|requestbin|interact\.sh|oast\.|pipedream|telegram\.org/bot|\.onion")
CHILD_RX = re.compile(r"child_process|execSync|spawnSync|\.exec\s*\(|\.spawn\s*\(")
NATIVE_SRC = (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".rs", ".go", ".zig")
BINARY_EXT = (".node", ".so", ".dll", ".dylib", ".exe", ".bin", ".a", ".wasm")


def list_names(blob: bytes, kind: str):
    """Names of EVERY member (not only text ones). Names only - nothing is read or extracted."""
    try:
        if kind == "zip":
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                return [i.filename for i in zf.infolist() if not i.is_dir()][:20000]
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            return [m.name for m in tf if m.isfile()][:20000]
    except Exception:
        return []


def install_semantics(hooks, files):
    """WHAT does the install script do? A legitimate native build calls known build tools and
    downloads from well-known hosts; a malicious one talks to unknown hosts, pipes into a shell,
    reads secrets or phones home. We read the hook text and the local file it launches."""
    text = "\n".join(hooks)
    urls = URL_RX.findall(text)
    by_name = {p.split("/", 1)[-1].lower(): d for p, d in files}  # drop the top directory
    by_tail = {p.lower(): d for p, d in files}
    target_text = ""
    targets = []
    found = 0
    for ref in LOCAL_FILE_RX.findall(text):
        key = ref.lstrip("./").lower()
        data = by_name.get(key) or next((d for p, d in by_tail.items() if p.endswith("/" + key)), None)
        if data is not None:
            found = 1
            targets.append(data)
            target_text += data.decode("utf-8", "replace")
    return {
        "_targets": [d.decode("utf-8", "replace") for d in targets],
        "hook_known_build_tool": int(bool(KNOWN_BUILD_TOOL.search(text))),
        "hook_n_urls": len(urls),
        "hook_url_unknown_host": sum(1 for h in urls if not KNOWN_HOST.search(h)),
        "hook_pipe_to_shell": int(bool(re.search(r"\|\s*(?:sh|bash|zsh|node)\b", text))),
        "hook_inline_node": int(bool(re.search(r"node\s+-e|node\s+--eval|python\s+-c", text))),
        "hook_has_base64": int("base64" in text.lower()),
        "hook_target_found": found,
        "hook_target_len": len(target_text),
        "hook_target_network": len(NET_RX.findall(target_text)),
        "hook_target_env": len(ENV_RX.findall(target_text)),
        "hook_target_sensitive": len(SENSITIVE_RX.findall(target_text)),
        "hook_target_exfil_domain": len(EXFIL_RX.findall(target_text)),
        "hook_target_child_process": len(CHILD_RX.findall(target_text)),
    }


def archive_structure(names):
    low = [n.lower() for n in names]
    return {
        "n_files_total": len(names),
        "has_binding_gyp": int(any(n.endswith("binding.gyp") for n in low)),
        "n_native_sources": sum(n.endswith(NATIVE_SRC) for n in low),
        "n_binary_files": sum(n.endswith(BINARY_EXT) for n in low),
        "has_prebuilds": int(any("/prebuilds/" in n or "/build/release/" in n for n in low)),
        "has_license_file": int(any(re.search(r"(^|/)(license|licence|copying)", n) for n in low)),
        "has_tests_dir": int(any(re.search(r"(^|/)(tests?|__tests__|spec)/", n) for n in low)),
        "has_ci_config": int(any(".github/" in n or ".travis" in n or ".circleci" in n for n in low)),
        "has_changelog": int(any("changelog" in n or "history.md" in n for n in low)),
        "has_typescript_types": int(any(n.endswith(".d.ts") for n in low)),
    }


VERSION_RX = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


def version_features(version):
    """Dependency-confusion attackers pick absurdly high versions (999.9.9, 99.99.99) so that the
    package manager prefers theirs. Year/date versions (2023.1.0, 20220311.0.0) are legitimate and
    excluded. Only flags are used (not the raw number): they describe attacker behaviour, they do not
    depend on which version we happened to sample."""
    m = VERSION_RX.match(version) if isinstance(version, str) else None
    if not m:
        return {"version_absurd_high": 0, "version_all_nines": 0, "version_zero_zero": 0}
    major, minor, patch = (int(g) for g in m.groups())
    year_like = 1900 <= major <= 2100 or major >= 10_000_000
    all_nines = bool(re.fullmatch(r"9{2,}", m.group(1))) and (str(minor).startswith("9") or minor == 0)
    return {
        "version_absurd_high": int(major >= 90 and not year_like),
        "version_all_nines": int(all_nines),
        "version_zero_zero": int(major == 0 and minor == 0),
    }


def pick_entry_texts(files, pkg, target_texts):
    """Hook target files first, then the package entry point / small root-level scripts."""
    wanted = []
    main = (pkg or {}).get("main") if isinstance((pkg or {}).get("main"), str) else None
    for path, data in sorted(files, key=lambda pd_: (pd_[0].count("/"), len(pd_[1]))):
        low = path.lower()
        if not low.endswith((".js", ".cjs", ".mjs")) or "node_modules" in low or ".min." in low:
            continue
        if len(data) > astfeat.MAX_FILE_BYTES:
            continue
        if (main and low.endswith(main.lstrip("./").lower())) or low.count("/") <= 2:
            wanted.append(data.decode("utf-8", "replace"))
        if len(wanted) >= 5:
            break
    return list(target_texts) + wanted


def find_package_json(files):
    candidates = [(p, d) for p, d in files if p.lower().endswith("package.json")]
    candidates.sort(key=lambda pd_: pd_[0].count("/"))
    for path, data in candidates:
        if "node_modules" in path:
            continue
        try:
            return json.loads(data.decode("utf-8", "replace"))
        except ValueError:
            continue
    return None


def content_features(blob: bytes, kind: str) -> dict:
    files = list(read_members(blob, kind))
    pkg = find_package_json(files)
    feats = {"archive_readable": 1, "n_text_files": len(files)}
    target_texts = []
    digests = sorted(hashlib.sha1(d).hexdigest() for _, d in files)
    feats["content_hash"] = hashlib.sha1("".join(digests).encode()).hexdigest() if digests else None

    # ---- package.json (None when absent/unparseable: a genuine missing value, imputed later)
    if pkg is None:
        feats["has_package_json"] = 0
    else:
        scripts = pkg.get("scripts") if isinstance(pkg.get("scripts"), dict) else {}
        hooks = [scripts[k] for k in INSTALL_HOOKS if isinstance(scripts.get(k), str)]
        deps = pkg.get("dependencies") if isinstance(pkg.get("dependencies"), dict) else {}
        dev = pkg.get("devDependencies") if isinstance(pkg.get("devDependencies"), dict) else {}
        desc = pkg.get("description") if isinstance(pkg.get("description"), str) else ""
        feats.update({
            "has_package_json": 1,
            "has_install_script": int(bool(hooks)),
            "install_script_len": sum(len(h) for h in hooks),
            "install_script_suspicious": int(any(SUSPICIOUS_SCRIPT.search(h) for h in hooks)),
            "install_script_runs_node": int(any(re.search(r"\bnode\b", h) for h in hooks)),
            "n_dependencies": len(deps),
            "n_dev_dependencies": len(dev),
            "has_repository": int(bool(pkg.get("repository"))),
            "has_homepage": int(bool(pkg.get("homepage"))),
            "has_description": int(bool(desc.strip())),
            "description_len": len(desc),
            "has_license": int(bool(pkg.get("license"))),
            "has_author": int(bool(pkg.get("author"))),
            "n_keywords": len(pkg.get("keywords") or []) if isinstance(pkg.get("keywords"), list) else 0,
            "has_main": int(bool(pkg.get("main"))),
            "has_bin": int(bool(pkg.get("bin"))),
            "n_scripts": len(scripts),
        })
        sem = install_semantics(hooks, files)
        target_texts = sem.pop("_targets", [])
        feats.update(sem)
        feats.update(version_features(pkg.get("version")))
        kw = pkg.get("keywords") if isinstance(pkg.get("keywords"), list) else []
        author = pkg.get("author")
        author = author.get("name", "") if isinstance(author, dict) else (author if isinstance(author, str) else "")
        feats["meta_text"] = " ".join([desc[:300], " ".join(str(k) for k in kw[:15]), str(author)[:60]]).strip()

    # ---- source code
    js = [(p, d) for p, d in files if p.lower().endswith((".js", ".cjs", ".mjs", ".ts", ".sh", ".bat", ".ps1", ".py"))]
    text = "\n".join(d.decode("utf-8", "replace") for _, d in js)
    raw_js = b"\n".join(d for _, d in js)
    feats["code_hash"] = (hashlib.sha1("".join(sorted(hashlib.sha1(d).hexdigest() for _, d in js)).encode()).hexdigest()
                          if js else None)
    feats["has_readme"] = int(any("readme" in p.lower() for p, _ in files))
    feats.update(archive_structure(list_names(blob, kind)))
    feats["n_code_files"] = len(js)
    feats["code_bytes"] = len(raw_js)
    if js:
        lines = text.split("\n")
        long_lines = [len(l) for l in lines]
        feats["max_line_len"] = max(long_lines)
        feats["pct_long_lines"] = sum(1 for n in long_lines if n > 500) / max(len(long_lines), 1)
        feats["code_entropy"] = shannon_entropy(raw_js[:400_000])
        kb = max(len(raw_js) / 1024, 1.0)
        for key, rx in COMPILED.items():
            n = len(rx.findall(text))
            feats[key] = n
            feats[key + "_per_kb"] = n / kb
    try:
        feats.update(astfeat.ast_features(pick_entry_texts(files, pkg, target_texts if pkg is not None else [])))
    except Exception:
        feats["ast_parse_ok"] = 0
    return feats


def extract_row(row: dict) -> dict:
    path = RAW / row["file"]
    name = normalize_name(row["name"])
    out = {"name": name, "label": row["label"], "kind": row.get("kind", row.get("source")),
           "file": row["file"], "archive_readable": 0}
    out.update(name_features(name))
    try:
        blob = path.read_bytes()
        out.update(content_features(blob, "zip" if path.suffix == ".zip" else "tgz"))
    except Exception as exc:  # corrupt archive, wrong password, ...
        out["error"] = type(exc).__name__
    return out


def load_manifests():
    rows = []
    for name in ("manifest_malicious.jsonl", "manifest_benign.jsonl"):
        p = RAW / name
        if p.exists():
            rows += [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return rows


def main():
    rows = load_manifests()
    print(f"extracting features for {len(rows)} packages ({sum(r['label'] for r in rows)} malicious)...", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with ProcessPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(extract_row, rows, chunksize=40))
    df = pd.DataFrame(results)
    df.to_csv(OUT, index=False)
    print(f"wrote {len(df)} rows x {df.shape[1]} columns -> {OUT}")
    print(df.groupby("label")["archive_readable"].agg(["count", "sum"]))


if __name__ == "__main__":
    sys.exit(main())
