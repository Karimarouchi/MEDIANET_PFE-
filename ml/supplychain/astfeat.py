"""
Improvement 4 - read the code as a TREE (JavaScript AST), not as a bag of words.

A regex can count the word "env" or "https". A syntax tree knows HOW they are used:
  * a secret is READ (process.env, ~/.ssh, hostname...) and, in the SAME function, SENT over the
    network  -> classic information stealer
  * require() / eval() called with a computed (non-literal) argument -> code hidden from readers
  * obj[expr](...) calls and hex-named identifiers (_0x1a2b) -> obfuscators
Only a few small files are parsed (the install-hook target + entry-like files) to stay fast.
Parsing never executes anything. Files that do not parse (ES modules, TypeScript, minified
monsters) simply give ast_parse_ok = 0 for that file.
"""
import math
import re

import esprima

HEX_IDENT = re.compile(r"^_0x[0-9a-fA-F]{3,}$")
NETWORK_NAMES = {"fetch", "XMLHttpRequest", "WebSocket", "request", "get", "post", "connect", "createConnection",
                 "send", "sendBeacon", "lookup", "resolve4", "resolveTxt"}
NETWORK_MODULES = {"http", "https", "net", "dgram", "tls", "dns", "axios", "node-fetch", "request", "got", "superagent"}
EXEC_NAMES = {"exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"}
SECRET_MEMBERS = {"env", "homedir", "userInfo", "hostname", "networkInterfaces"}
SECRET_STRINGS = re.compile(r"\.ssh|\.npmrc|\.aws|id_rsa|passwd|\.git-credentials|wallet|Login Data|Local Storage", re.I)

MAX_FILE_BYTES = 60_000
MAX_TOTAL_BYTES = 150_000
MAX_NODES = 120_000


def _entropy(items):
    if not items:
        return 0.0
    counts = {}
    for it in items:
        counts[it] = counts.get(it, 0) + 1
    n = len(items)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _name_of(node):
    if not isinstance(node, dict):
        return None
    if node.get("type") == "Identifier":
        return node.get("name")
    if node.get("type") == "MemberExpression" and not node.get("computed"):
        return _name_of(node.get("property"))
    return None


class _Walker:
    def __init__(self):
        self.n_nodes = 0
        self.max_depth = 0
        self.idents = []
        self.hex_idents = 0
        self.dynamic_require = 0
        self.dynamic_eval = 0
        self.computed_calls = 0
        self.string_len = 0
        self.max_string = 0
        self.concat_strings = 0
        self.network_calls = 0
        self.exec_calls = 0
        self.secret_reads = 0
        self.module_imports = set()
        self.fn_source_sink = 0
        self.fn_count = 0
        self.global_flags = {"secret": 0, "network": 0, "exec": 0}

    def visit(self, node, depth, fn_flags):
        if self.n_nodes > MAX_NODES:
            return
        if isinstance(node, list):
            for child in node:
                self.visit(child, depth, fn_flags)
            return
        if not isinstance(node, dict):
            return
        t = node.get("type")
        if t is None:
            return
        self.n_nodes += 1
        self.max_depth = max(self.max_depth, depth)

        if t in ("FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"):
            own = {"secret": 0, "network": 0, "exec": 0}
            self.fn_count += 1
            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    self.visit(child, depth + 1, own)
            if own["secret"] and own["network"]:
                self.fn_source_sink += 1
            for k in own:  # a function also counts for its parent (nested helpers)
                if fn_flags is not None:
                    fn_flags[k] += own[k]
            return

        if t == "Identifier":
            name = node.get("name", "")
            self.idents.append(name)
            if HEX_IDENT.match(name):
                self.hex_idents += 1
        elif t == "Literal":
            v = node.get("value")
            if isinstance(v, str):
                self.string_len += len(v)
                self.max_string = max(self.max_string, len(v))
                if SECRET_STRINGS.search(v):
                    self._flag(fn_flags, "secret")
        elif t == "BinaryExpression" and node.get("operator") == "+":
            if any(isinstance(node.get(s), dict) and node[s].get("type") == "Literal"
                   and isinstance(node[s].get("value"), str) for s in ("left", "right")):
                self.concat_strings += 1
        elif t == "MemberExpression":
            prop = _name_of(node)
            if prop in SECRET_MEMBERS and not node.get("computed"):
                self.secret_reads += 1
                self._flag(fn_flags, "secret")
            if node.get("computed") and not (isinstance(node.get("property"), dict)
                                             and node["property"].get("type") == "Literal"):
                pass  # computed access alone is common; computed CALLS are counted below
        elif t == "CallExpression" or t == "NewExpression":
            callee = node.get("callee")
            cname = _name_of(callee)
            args = node.get("arguments") or []
            first = args[0] if args else None
            literal_first = isinstance(first, dict) and first.get("type") == "Literal"
            if cname == "require":
                if first is not None and not literal_first:
                    self.dynamic_require += 1
                elif literal_first and isinstance(first.get("value"), str):
                    mod = first["value"].split("/")[0]
                    self.module_imports.add(mod)
                    if mod == "child_process":
                        self.exec_calls += 1
                        self._flag(fn_flags, "exec")
                    if mod in NETWORK_MODULES:
                        self._flag(fn_flags, "network")
            if cname in ("eval", "Function") and first is not None and not literal_first:
                self.dynamic_eval += 1
            if cname in EXEC_NAMES:
                self.exec_calls += 1
                self._flag(fn_flags, "exec")
            if cname in NETWORK_NAMES:
                self.network_calls += 1
                self._flag(fn_flags, "network")
            if isinstance(callee, dict) and callee.get("type") == "MemberExpression" and callee.get("computed") \
                    and not (isinstance(callee.get("property"), dict) and callee["property"].get("type") == "Literal"):
                self.computed_calls += 1

        for key, child in node.items():
            if isinstance(child, (dict, list)):
                self.visit(child, depth + 1, fn_flags)

    def _flag(self, fn_flags, kind):
        self.global_flags[kind] += 1
        if fn_flags is not None:
            fn_flags[kind] += 1


def _parse(src):
    for fn in (esprima.parseScript, esprima.parseModule):
        try:
            return fn(src, {"tolerant": True}).toDict()
        except Exception:
            continue
    return None


def ast_features(texts):
    """texts: list of JS source strings (hook target first, then entry-like files)."""
    w = _Walker()
    parsed = tried = 0
    total = 0
    for src in texts:
        if not src or len(src) > MAX_FILE_BYTES or total + len(src) > MAX_TOTAL_BYTES:
            continue
        total += len(src)
        tried += 1
        tree = _parse(src)
        if tree is None:
            continue
        parsed += 1
        w.visit(tree, 0, None)
    feats = {"ast_files_tried": tried, "ast_files_parsed": parsed, "ast_parse_ok": int(parsed > 0)}
    if parsed == 0:
        return feats
    n_idents = max(len(w.idents), 1)
    feats.update({
        "ast_n_nodes": w.n_nodes,
        "ast_max_depth": w.max_depth,
        "ast_hex_ident_ratio": w.hex_idents / n_idents,
        "ast_ident_entropy": _entropy(w.idents),
        "ast_dynamic_require": w.dynamic_require,
        "ast_dynamic_eval": w.dynamic_eval,
        "ast_computed_calls": w.computed_calls,
        "ast_string_total_len": w.string_len,
        "ast_max_string_len": w.max_string,
        "ast_string_concat": w.concat_strings,
        "ast_network_calls": w.network_calls,
        "ast_exec_calls": w.exec_calls,
        "ast_secret_reads": w.secret_reads,
        "ast_n_modules": len(w.module_imports),
        "ast_source_and_sink_in_file": int(w.global_flags["secret"] > 0 and w.global_flags["network"] > 0),
        "ast_source_and_sink_in_function": w.fn_source_sink,
        "ast_n_functions": w.fn_count,
    })
    return feats
