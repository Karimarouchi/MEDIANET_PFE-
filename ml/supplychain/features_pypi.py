#!/usr/bin/env python3
"""
PyPI version of features.py: one row of numbers per Python source distribution.

Same safety rules as npm: archives are read IN MEMORY as text; nothing is extracted, installed, imported
or executed. Same symmetry rule: only features that exist for BOTH classes (content and name).

Column names deliberately mirror the npm ones (hook_*, ast_*, n_*, has_install_script, ...) so that the
shared cleaning / repair / training / type-rule code works unchanged. "Install-time code" for Python is
setup.py (it runs on `pip install` of a source distribution), the counterpart of npm install scripts.
"""
import ast
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

import warnings

import pandas as pd

warnings.simplefilter("ignore")  # hostile source often has invalid escapes

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import features as F  # noqa: E402  (shared helpers: entropy, name features, archive structure, versions)

RAW = F.RAW
OUT = HERE / "data" / "clean_pypi" / "features_raw.csv"
ART_PYPI = HERE / "artifacts_pypi"
TOP_PYPI_FILE = ART_PYPI / "top_pypi.txt"
RAW_TOP_PYPI = RAW / "top_pypi.txt"
TOP_PYPI_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
ZIP_PASSWORD = b"infected"
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_MEMBERS = 3000
TEXT_EXT = (".py", ".pyx", ".cfg", ".toml", ".txt", ".in", ".sh", ".bat", ".ps1", ".js", ".json", ".md", ".rst")


def normalize_name(name: str) -> str:
    """PEP 503 normalisation: case-insensitive, runs of - _ . are equal."""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def load_top_pypi(n=8000):
    for p in (TOP_PYPI_FILE, RAW_TOP_PYPI):
        if p.exists():
            return p.read_text(encoding="utf-8").splitlines()[:n]
    import requests
    rows = requests.get(TOP_PYPI_URL, timeout=40).json()["rows"]
    names = [normalize_name(r["project"]) for r in rows][:n]
    RAW_TOP_PYPI.write_text("\n".join(names), encoding="utf-8")
    return names


TOP_NAMES_PYPI = load_top_pypi()

# ------------------------------------------------------------------ patterns (names mirror the npm ones)
PY_PATTERNS = {
    "n_eval": r"\beval\s*\(",
    "n_new_function": r"\bexec\s*\(|\bcompile\s*\(",
    "n_child_process": r"\bsubprocess\b|os\.system|os\.popen|pty\.spawn|commands\.getoutput|os\.exec[lv]p?",
    "n_network_module": r"\b(?:import|from)\s+(?:requests|urllib|socket|http\.client|httpx|aiohttp|ftplib|smtplib|paramiko|telnetlib)|urlopen|socket\.socket",
    "n_env_access": r"os\.environ|os\.getenv|getpass\.getuser|gethostname|platform\.node",
    "n_host_recon": r"gethostname|getuser|platform\.(?:node|system|uname|platform)|os\.getlogin|netifaces|uuid\.getnode|getpass",
    "n_sensitive_path": r"\.ssh|\.aws|\.npmrc|\.pypirc|id_rsa|/etc/passwd|\.git-credentials|wallet|Login Data|Local Storage|\.kube|\.docker/config|keychain|\.bash_history|Cookies",
    "n_base64": r"base64|b64decode|a2b_base64|zlib\.decompress|marshal\.loads|codecs\.decode|bz2\.decompress|lzma\.decompress",
    "n_charcode": r"\bchr\s*\(|\\x[0-9a-fA-F]{2}|bytes\.fromhex|fromhex",
    "n_obfuscator_ident": r"\b_0x[0-9a-fA-F]{3,}\b|\b[Il1O0]{9,}\b|\b_{3,}[A-Za-z0-9]{1,3}_{0,}\b",
    "n_exfil_domain": r"discord(?:app)?\.com/api/webhooks|pastebin\.com|ngrok|webhook\.site|requestbin|interact\.sh|oast\.|burpcollaborator|pipedream|telegram\.org/bot|transfer\.sh|\.onion|api\.telegram|oastify",
    "n_ip_literal": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "n_url_literal": r"https?://[^\s'\"`)]+",
    "n_fs_write": r"open\s*\([^)]*['\"][wa]b?['\"]|\.write_(?:text|bytes)\s*\(|shutil\.copy",
    "n_download_exec": r"(?:curl|wget)[^\n]{0,80}\|\s*(?:sh|bash)|chmod\s*\+x|os\.chmod|urlretrieve",
    "n_pickle_ctypes": r"pickle\.loads?|ctypes\.|cffi",
}
COMPILED = {k: re.compile(v) for k, v in PY_PATTERNS.items()}
SETUP_TIME_CODE = re.compile(
    r"cmdclass|exec\s*\(|eval\s*\(|subprocess|os\.system|os\.popen|urlopen|urlretrieve|"
    r"(?:import|from)\s+(?:requests|socket|urllib|http\.client|ftplib|smtplib|paramiko)|requests\.(?:get|post)|"
    r"socket\.socket|base64|__import__|importlib|open\s*\([^)]*['\"]w")
SETUP_SUSPICIOUS = re.compile(r"curl|wget|powershell|bash\s+-c|\bexec\s*\(|\beval\s*\(|base64|subprocess|os\.system|__import__")
BUILD_TOOL = re.compile(r"\bExtension\s*\(|cythonize|build_ext|pybind11|setuptools_rust|cmake|numpy\.distutils|scikit-build|"
                        r"maturin|Cython|cffi_modules|pkgconfig")
URL_RX = F.URL_RX
KNOWN_HOST = F.KNOWN_HOST
URL_META_LINE = re.compile(r"(?:^|[\s,(])(?:url|download_url|home_?page|project_urls|bugtrack_url|documentation|source_?code)\s*=|project_urls|Home-page", re.I)
SENSITIVE_SOURCES = {"environ", "getenv", "getuser", "gethostname", "getlogin", "node", "uname", "getnode"}
NET_CALLS = {"urlopen", "urlretrieve", "request", "get", "post", "put", "socket", "create_connection", "connect",
             "send", "sendall", "sendto", "getaddrinfo", "gethostbyname", "Session", "urlencode"}
NET_MODULES = {"requests", "urllib", "urllib2", "urllib3", "socket", "http", "httpx", "aiohttp", "ftplib", "smtplib",
               "paramiko", "telnetlib", "websocket", "websockets"}
EXEC_CALLS = {"system", "popen", "Popen", "call", "run", "check_output", "check_call", "spawn", "execv", "execl", "execvp"}
DECODERS = {"b64decode", "decodebytes", "a2b_base64", "decompress", "loads", "fromhex", "decode", "unhexlify"}
SECRET_STR = re.compile(r"\.ssh|\.aws|id_rsa|/etc/passwd|\.git-credentials|wallet|\.pypirc|\.npmrc|\.kube|Login Data", re.I)
HEXISH = re.compile(r"^(?:_0x[0-9a-fA-F]{3,}|[Il1O0]{9,})$")


# ------------------------------------------------------------------ archive reading (in memory)
def read_members(blob: bytes, suffix: str):
    total = 0
    if suffix == ".zip":
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            for i, info in enumerate(zf.infolist()):
                low = info.filename.lower()
                if info.is_dir() or i > MAX_MEMBERS or not (low.endswith(TEXT_EXT) or "readme" in low or low.endswith("pkg-info")):
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
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            for i, m in enumerate(tf):
                low = m.name.lower()
                if not m.isfile() or i > MAX_MEMBERS or not (low.endswith(TEXT_EXT) or "readme" in low or low.endswith("pkg-info")):
                    continue
                if m.size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    continue
                f = tf.extractfile(m)
                if f is None:
                    continue
                data = f.read()
                total += len(data)
                yield m.name, data


def list_names(blob: bytes, suffix: str):
    try:
        if suffix == ".zip":
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                return [i.filename for i in zf.infolist() if not i.is_dir()][:20000]
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:*") as tf:
            return [m.name for m in tf if m.isfile()][:20000]
    except Exception:
        return []


def _shallow(files, basename):
    """Shallowest file with this base name (sdists wrap everything in <name>-<version>/)."""
    best = None
    for path, data in files:
        if path.lower().rstrip("/").split("/")[-1] == basename and "test" not in path.lower().split("/")[:-1]:
            if best is None or path.count("/") < best[0].count("/"):
                best = (path, data)
    return best[1].decode("utf-8", "replace") if best else None


# ------------------------------------------------------------------ Python AST features
class _Walker(ast.NodeVisitor):
    def __init__(self):
        self.n_nodes = 0
        self.depth = 0
        self.max_depth = 0
        self.idents = []
        self.hex_idents = 0
        self.strings_total = 0
        self.max_string = 0
        self.concat = 0
        self.dynamic_import = 0
        self.dynamic_eval = 0
        self.computed_calls = 0
        self.network = 0
        self.exec_calls = 0
        self.secret = 0
        self.decoded_exec = 0
        self.modules = set()
        self.functions = 0
        self.fn_source_sink = 0
        self.flags = {"secret": 0, "network": 0}

    def generic_visit(self, node):
        self.n_nodes += 1
        self.depth += 1
        self.max_depth = max(self.max_depth, self.depth)
        super().generic_visit(node)
        self.depth -= 1

    @staticmethod
    def _callee(node):
        f = node.func
        if isinstance(f, ast.Name):
            return f.id, None
        if isinstance(f, ast.Attribute):
            base = f.value.id if isinstance(f.value, ast.Name) else None
            return f.attr, base
        return None, None

    def _flag(self, kind, fn):
        self.flags[kind] += 1
        if fn is not None:
            fn[kind] += 1

    def run(self, tree):
        self._visit(tree, None)

    def _visit(self, node, fn):
        self.n_nodes += 1
        t = type(node)
        if t in (ast.FunctionDef, ast.AsyncFunctionDef):
            self.functions += 1
            own = {"secret": 0, "network": 0}
            for child in ast.iter_child_nodes(node):
                self._visit(child, own)
            if own["secret"] and own["network"]:
                self.fn_source_sink += 1
            if fn is not None:
                fn["secret"] += own["secret"]
                fn["network"] += own["network"]
            return
        if t is ast.Name:
            self.idents.append(node.id)
            if HEXISH.match(node.id):
                self.hex_idents += 1
            if node.id in SENSITIVE_SOURCES:
                self.secret += 1
                self._flag("secret", fn)
        elif t is ast.Attribute:
            if node.attr in SENSITIVE_SOURCES:
                self.secret += 1
                self._flag("secret", fn)
        elif t is ast.Constant and isinstance(node.value, str):
            self.strings_total += len(node.value)
            self.max_string = max(self.max_string, len(node.value))
            if SECRET_STR.search(node.value):
                self.secret += 1
                self._flag("secret", fn)
        elif t is ast.BinOp and isinstance(node.op, ast.Add):
            if any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in (node.left, node.right)):
                self.concat += 1
        elif t is ast.Import:
            for a in node.names:
                mod = a.name.split(".")[0]
                self.modules.add(mod)
                if mod in NET_MODULES:
                    self._flag("network", fn)
        elif t is ast.ImportFrom:
            mod = (node.module or "").split(".")[0]
            self.modules.add(mod)
            if mod in NET_MODULES:
                self._flag("network", fn)
        elif t is ast.Call:
            name, base = self._callee(node)
            first = node.args[0] if node.args else None
            literal_first = isinstance(first, ast.Constant)
            if name in ("exec", "eval") and first is not None and not literal_first:
                self.dynamic_eval += 1
                for sub in ast.walk(first):
                    if isinstance(sub, ast.Call) and self._callee(sub)[0] in DECODERS:
                        self.decoded_exec += 1
                        break
            if name in ("__import__", "import_module") and first is not None and not literal_first:
                self.dynamic_import += 1
            if name == "getattr" and len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                self.computed_calls += 1
            if name in NET_CALLS and (base in NET_MODULES or base is None or base in ("session", "s")) and name != "get" or \
                    (name in ("get", "post") and base in NET_MODULES):
                self.network += 1
                self._flag("network", fn)
            if name in EXEC_CALLS and base in (None, "os", "subprocess", "pty"):
                self.exec_calls += 1
        for child in ast.iter_child_nodes(node):
            self._visit(child, fn)


def python_ast_features(texts):
    w = _Walker()
    tried = parsed = 0
    total = 0
    for src in texts:
        if not src or len(src) > 120_000 or total + len(src) > 250_000:
            continue
        total += len(src)
        tried += 1
        try:
            tree = ast.parse(src)
        except Exception:
            continue
        parsed += 1
        w.run(tree)
    feats = {"ast_files_tried": tried, "ast_files_parsed": parsed, "ast_parse_ok": int(parsed > 0)}
    if not parsed:
        return feats
    n_idents = max(len(w.idents), 1)
    counts = {}
    for i in w.idents:
        counts[i] = counts.get(i, 0) + 1
    entropy = -sum(c / n_idents * math.log2(c / n_idents) for c in counts.values())
    feats.update({
        "ast_n_nodes": w.n_nodes, "ast_max_depth": w.max_depth, "ast_hex_ident_ratio": w.hex_idents / n_idents,
        "ast_ident_entropy": entropy, "ast_dynamic_require": w.dynamic_import, "ast_dynamic_eval": w.dynamic_eval,
        "ast_computed_calls": w.computed_calls, "ast_string_total_len": w.strings_total,
        "ast_max_string_len": w.max_string, "ast_string_concat": w.concat, "ast_network_calls": w.network,
        "ast_exec_calls": w.exec_calls, "ast_secret_reads": w.secret, "ast_n_modules": len(w.modules),
        "ast_source_and_sink_in_file": int(w.flags["secret"] > 0 and w.flags["network"] > 0),
        "ast_source_and_sink_in_function": w.fn_source_sink, "ast_n_functions": w.functions,
        "ast_exec_decoded_payload": w.decoded_exec,
    })
    return feats


# ------------------------------------------------------------------ package-level features
def metadata_features(files, setup_text):
    pkg_info = _shallow(files, "pkg-info")
    cfg = _shallow(files, "setup.cfg")
    pyproject = _shallow(files, "pyproject.toml")
    blob = "\n".join(x for x in (pkg_info, cfg, setup_text) if x)

    def field(name):
        m = re.search(rf"^{name}:\s*(.+)$", pkg_info or "", re.M | re.I)
        return m.group(1).strip() if m else None

    def kw(name):
        m = re.search(rf"\b{name}\s*=\s*['\"]([^'\"]*)['\"]", blob)
        return m.group(1).strip() if m else None

    summary = field("Summary") or kw("description") or ""
    author = field("Author") or kw("author") or ""
    keywords = (field("Keywords") or kw("keywords") or "")
    n_req = len(re.findall(r"^Requires-Dist:", pkg_info or "", re.M)) or \
        len(re.findall(r"['\"][A-Za-z0-9_.-]+(?:[<>=!~].*?)?['\"]", (re.search(r"install_requires\s*=\s*\[(.*?)\]", blob, re.S) or [None, ""])[1]))
    return {
        "md_has_pkg_info": int(pkg_info is not None), "md_has_setup_py": int(setup_text is not None),
        "md_has_pyproject": int(pyproject is not None), "md_has_setup_cfg": int(cfg is not None),
        "md_summary_len": len(summary), "md_has_author": int(bool(author.strip())),
        "md_has_license": int(bool(field("License") or kw("license") or (re.search(r"^License", blob, re.M)))),
        "md_has_homepage": int(bool(field("Home-page") or kw("url") or re.search(r"Project-URL", pkg_info or ""))),
        "md_n_classifiers": len(re.findall(r"^Classifier:", pkg_info or "", re.M)) or len(re.findall(r"Programming Language ::", blob)),
        "md_n_requires": n_req, "md_n_keywords": len([k for k in re.split(r"[,\s]+", keywords) if k]),
        "meta_text": " ".join([summary[:300], keywords[:120], author[:60]]).strip(),
    }


def setup_semantics(setup_text):
    t = setup_text or ""
    code_lines = [ln for ln in t.splitlines() if not URL_META_LINE.search(ln)]
    urls = [u for ln in code_lines for u in URL_RX.findall(ln)]
    has_code = bool(SETUP_TIME_CODE.search(t)) if setup_text is not None else False
    return {
        "has_install_script": int(has_code),
        "install_script_len": len(t),
        "install_script_suspicious": int(bool(SETUP_SUSPICIOUS.search(t))),
        "install_script_runs_node": 0,
        "hook_known_build_tool": int(bool(BUILD_TOOL.search(t))),
        "hook_n_urls": len(urls),
        "hook_url_unknown_host": sum(1 for h in urls if not KNOWN_HOST.search(h)),
        "hook_pipe_to_shell": int(bool(re.search(r"\|\s*(?:sh|bash|zsh|python)\b", t))),
        "hook_inline_node": int(bool(re.search(r"python\d?\s+-c|exec\s*\(\s*(?:base64|zlib)", t))),
        "hook_has_base64": int("base64" in t.lower()),
        "hook_target_found": int(setup_text is not None),
        "hook_target_len": len(t),
        "hook_target_network": len(re.findall(PY_PATTERNS["n_network_module"], t)),
        "hook_target_env": len(re.findall(PY_PATTERNS["n_env_access"], t)),
        "hook_target_sensitive": len(re.findall(PY_PATTERNS["n_sensitive_path"], t)),
        "hook_target_exfil_domain": len(re.findall(PY_PATTERNS["n_exfil_domain"], t)),
        "hook_target_child_process": len(re.findall(PY_PATTERNS["n_child_process"], t)),
    }


def content_features(blob: bytes, suffix: str, version) -> dict:
    files = list(read_members(blob, suffix))
    feats = {"archive_readable": 1, "n_text_files": len(files)}
    digests = sorted(hashlib.sha1(d).hexdigest() for _, d in files)
    feats["content_hash"] = hashlib.sha1("".join(digests).encode()).hexdigest() if digests else None
    setup_text = _shallow(files, "setup.py")
    feats.update(setup_semantics(setup_text))
    feats.update(metadata_features(files, setup_text))
    feats.update(F.version_features(version))
    names = list_names(blob, suffix)
    feats.update(F.archive_structure(names))
    feats["has_readme"] = int(any("readme" in p.lower() for p, _ in files))

    py = [(p, d) for p, d in files if p.lower().endswith((".py", ".pyx", ".sh", ".bat", ".ps1"))]
    text = "\n".join(d.decode("utf-8", "replace") for _, d in py)
    raw = b"\n".join(d for _, d in py)
    feats["code_hash"] = (hashlib.sha1("".join(sorted(hashlib.sha1(d).hexdigest() for _, d in py)).encode()).hexdigest()
                          if py else None)
    feats["n_code_files"] = len(py)
    feats["code_bytes"] = len(raw)
    if py:
        lines = text.split("\n")
        lens = [len(l) for l in lines]
        feats["max_line_len"] = max(lens)
        feats["pct_long_lines"] = sum(1 for n in lens if n > 500) / max(len(lens), 1)
        feats["code_entropy"] = F.shannon_entropy(raw[:400_000])
        kb = max(len(raw) / 1024, 1.0)
        for key, rx in COMPILED.items():
            n = len(rx.findall(text))
            feats[key] = n
            feats[key + "_per_kb"] = n / kb

    # AST: setup.py first (runs at install time), then package entry points / small root scripts
    texts = [setup_text] if setup_text else []
    for path, data in sorted(py, key=lambda pd_: (pd_[0].count("/"), len(pd_[1]))):
        low = path.lower()
        if low.endswith("setup.py") or "/test" in low or len(data) > 120_000:
            continue
        if low.endswith("__init__.py") or low.count("/") <= 2:
            texts.append(data.decode("utf-8", "replace"))
        if len(texts) >= 6:
            break
    try:
        feats.update(python_ast_features(texts))
    except Exception:
        feats["ast_parse_ok"] = 0
    return feats


def extract_row(row: dict) -> dict:
    name = normalize_name(row["name"])
    path = RAW / row["file"]
    out = {"name": name, "label": row["label"], "kind": row.get("kind", row.get("source")),
           "file": row["file"], "archive_readable": 0}
    out.update(F.name_features(name, top_names=TOP_NAMES_PYPI))
    try:
        blob = path.read_bytes()
        out.update(content_features(blob, ".zip" if path.suffix == ".zip" else ".tgz", row.get("version")))
    except Exception as exc:
        out["error"] = type(exc).__name__
    # legitimate packages that run code at install time are the hard negatives of this ecosystem
    if out["label"] == 0 and out.get("has_install_script") == 1:
        out["kind"] = "hard_negative"
    return out


def load_manifests():
    rows = []
    for name in ("manifest_malicious_pypi.jsonl", "manifest_benign_pypi.jsonl"):
        p = RAW / name
        if p.exists():
            rows += [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()]
    return rows


def main():
    rows = load_manifests()
    print(f"extracting PyPI features for {len(rows)} packages ({sum(r['label'] for r in rows)} malicious)...", flush=True)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with ProcessPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(extract_row, rows, chunksize=40))
    df = pd.DataFrame(results)
    df.to_csv(OUT, index=False)
    print(f"wrote {len(df)} rows x {df.shape[1]} columns -> {OUT}")
    print(df.groupby("label")["archive_readable"].agg(["count", "sum"]))


if __name__ == "__main__":
    sys.exit(main())
