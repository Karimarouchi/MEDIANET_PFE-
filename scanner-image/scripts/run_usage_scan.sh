#!/usr/bin/env bash
# Which third-party packages does the project's own code actually import?
# Written to package-usage.json; Medianet uses it to tell, per vulnerable dependency, "imported by your code" /
# "only imported by tests" / "no import found" (probably unused: removing it is the best fix). It is a usage signal
# from import statements, not a call-graph reachability proof. Never fails the scan.

run_usage_scan() {
  local repo_dir="$1"
  local results_dir="$2"

  log "  usage — imports de paquets dans le code du projet..."
  python3 - "${repo_dir}" "${results_dir}/package-usage.json" > "${results_dir}/package-usage.log" 2>&1 <<'PY' || true
import json, os, re, sys

root, out = sys.argv[1], sys.argv[2]
SKIP_DIRS = {"node_modules", ".git", "vendor", "target", "dist", "build", ".venv", "venv", "__pycache__", ".next",
             "coverage", "bower_components", ".gradle", ".idea", "site-packages"}
TEST_MARKERS = ("/test/", "/tests/", "/__tests__/", "/spec/", "/e2e/", "/cypress/", "/__mocks__/", "/mocks/", "/fixtures/")
TEST_NAME = re.compile(r"(\.test\.|\.spec\.|_test\.|_spec\.|^test_|Test\.java$|Tests\.java$)")
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue"}
JAVA_EXT = {".java", ".kt", ".scala", ".groovy"}
JS_RE = re.compile(r"""(?:require\(\s*|import\(\s*|from\s+|import\s+)['"]([^'"./][^'"]*)['"]""")
PY_RE = re.compile(r"^\s*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w., ]*))", re.M)
JAVA_RE = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)
GO_RE = re.compile(r'^\s*(?:import\s+)?(?:[\w.]+\s+)?"([\w.\-]+\.[\w.\-]+/[^"]+)"', re.M)
NODE_BUILTINS = {"fs", "path", "os", "http", "https", "crypto", "util", "stream", "events", "url", "zlib", "child_process",
                 "net", "tls", "dns", "assert", "buffer", "cluster", "readline", "querystring", "string_decoder", "timers",
                 "vm", "worker_threads", "perf_hooks", "process", "module", "constants", "punycode", "tty", "v8"}

data = {"npm": {}, "pypi": {}, "java": {}, "go": {}}
scanned = 0


def add(eco, name, rel, is_test):
    e = data[eco].setdefault(name, {"files": [], "prod": False, "count": 0})
    e["count"] += 1
    if not is_test:
        e["prod"] = True
    if rel not in e["files"] and len(e["files"]) < 3:
        e["files"].append(rel)


for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
    for fn in filenames:
        ext = os.path.splitext(fn)[1].lower()
        if ext not in JS_EXT | JAVA_EXT | {".py", ".go"}:
            continue
        path = os.path.join(dirpath, fn)
        try:
            if os.path.getsize(path) > 1_500_000:
                continue
            text = open(path, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        scanned += 1
        rel = os.path.relpath(path, root).replace("\\", "/")
        is_test = any(m in "/" + rel.lower() for m in TEST_MARKERS) or bool(TEST_NAME.search(fn))
        if ext in JS_EXT:
            for spec in JS_RE.findall(text):
                if spec.startswith("node:") or spec in NODE_BUILTINS:
                    continue
                parts = spec.split("/")
                name = "/".join(parts[:2]) if spec.startswith("@") and len(parts) > 1 else parts[0]
                add("npm", name.lower(), rel, is_test)
        elif ext == ".py":
            for a, b in PY_RE.findall(text):
                for mod in ([a] if a else [x.strip().split(" as ")[0] for x in b.split(",")]):
                    if mod:
                        add("pypi", mod.split(".")[0].lower(), rel, is_test)
        elif ext in JAVA_EXT:
            for imp in JAVA_RE.findall(text):
                pkg = ".".join(imp.split(".")[:4])
                add("java", pkg, rel, is_test)
        elif ext == ".go":
            for imp in GO_RE.findall(text):
                add("go", imp, rel, is_test)

data["filesScanned"] = scanned
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f)
print("usage: %d files scanned, npm=%d pypi=%d java=%d go=%d" % (scanned, len(data["npm"]), len(data["pypi"]), len(data["java"]), len(data["go"])))
PY
  if [ ! -s "${results_dir}/package-usage.json" ]; then echo '{}' > "${results_dir}/package-usage.json"; fi
  record_tool "usage-scan"
  record_file_if_exists "${results_dir}/package-usage.json"
}
