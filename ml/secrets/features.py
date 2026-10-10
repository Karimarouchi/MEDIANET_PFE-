"""Hand-made features of a secret candidate. Everything is computed from what a scanner such as Gitleaks also gives
(the matched value, its line, the surrounding lines, the file path, the rule), so the same code runs at inference.
Pure functions: no I/O, easy to unit-test."""
from __future__ import annotations

import base64
import math
import re
from collections import Counter

import numpy as np
import pandas as pd

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")
PLACEHOLDER_RE = re.compile(
    r"(x{3,}|\*{3,}|\.{3,}|<[^>]{1,40}>|\{\{.*?\}\}|\$\{.*?\}|%\(.*?\)s|%[A-Za-z_]+%|your[_\- ]?|changeme|change[_\- ]?me|"
    r"example|dummy|sample|fake|placeholder|replace|insert|todo|redacted|secret_?here|password_?here|null|none|undefined)",
    re.I)
VAR_REF_RE = re.compile(r"^(\$|%|@|#\{|\{\{|<)")
KNOWN_PREFIXES = ("AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "github_pat_", "xoxb-", "xoxp-", "xoxa-", "sk_live_",
                  "sk-", "pk_live_", "AIza", "-----BEGIN", "eyJ", "glpat-", "npm_", "SG.", "shpat_", "rk_live_")
KEYWORDS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key", "access_key", "private_key",
            "credential", "auth", "bearer", "key")
PATH_FLAGS = {
    "p_test": ("/test", "test/", "tests/", "_test", "spec/", "__tests__"),
    "p_example": ("example", "sample", "demo", "tutorial"),
    "p_doc": ("doc", "readme", "/man/", "wiki"),
    "p_fixture": ("fixture", "mock", "stub", "testdata", "dummy"),
    "p_config": ("config", "conf/", ".env", "settings", "secrets", "credentials"),
    "p_vendor": ("vendor", "node_modules", "third_party", "site-packages", "dist/"),
    "p_i18n": ("locale", "i18n", "lang/", "translation"),
    "p_ci": (".github", ".gitlab", "ci/", "travis", "jenkins", "docker"),
}
LANG_CODE = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php", ".c", ".cpp", ".cs", ".rs", ".kt", ".swift", ".m", ".scala"}
LANG_CONF = {".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env", ".xml", ".tf"}
LANG_DOC = {".md", ".rst", ".txt", ".adoc", ".html"}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _b64_text_ratio(s: str) -> float:
    """Share of printable ASCII once decoded as base64 (a base64 of readable text is rarely a secret)."""
    t = s.strip().rstrip("=")
    if len(t) < 8 or not B64_RE.match(s.strip()):
        return -1.0
    try:
        raw = base64.b64decode(t + "=" * (-len(t) % 4), altchars=b"-_" if ("-" in t or "_" in t) else None)
    except Exception:
        return -1.0
    if not raw:
        return -1.0
    return sum(32 <= b < 127 or b in (9, 10, 13) for b in raw) / len(raw)


def _strip_quotes(value: str) -> str:
    v = value.strip()
    while v and v[0] in "\"'`" and v[-1:] == v[0] and len(v) > 1:
        v = v[1:-1].strip()
    return v


def value_features(value: str) -> dict:
    v = _strip_quotes(value)
    n = len(v)
    letters = sum(c.isalpha() for c in v)
    digits = sum(c.isdigit() for c in v)
    upper = sum(c.isupper() for c in v)
    lower = sum(c.islower() for c in v)
    special = n - letters - digits
    uniq = len(set(v))
    vowels = sum(c.lower() in "aeiou" for c in v if c.isalpha())
    max_run = 0
    run = 0
    prev = ""
    for c in v:
        run = run + 1 if c == prev else 1
        max_run = max(max_run, run)
        prev = c
    return {
        "v_len": n,
        "v_log_len": math.log1p(n),
        "v_entropy": shannon_entropy(v),
        "v_entropy_norm": shannon_entropy(v) / math.log2(max(uniq, 2)) if n else 0.0,
        "v_frac_digit": digits / n if n else 0.0,
        "v_frac_upper": upper / n if n else 0.0,
        "v_frac_lower": lower / n if n else 0.0,
        "v_frac_special": special / n if n else 0.0,
        "v_uniq_ratio": uniq / n if n else 0.0,
        "v_vowel_ratio": vowels / letters if letters else 0.0,
        "v_max_run": max_run,
        "v_has_space": int(" " in v),
        "v_is_hex": int(bool(v) and bool(HEX_RE.match(v))),
        "v_hexlen_hash": int(bool(v) and bool(HEX_RE.match(v)) and n in (32, 40, 56, 64, 96, 128)),
        "v_is_uuid": int(bool(UUID_RE.match(v))),
        "v_b64_text": _b64_text_ratio(v),
        "v_is_b64": int(bool(v) and bool(B64_RE.match(v)) and n >= 16),
        "v_placeholder": int(bool(PLACEHOLDER_RE.search(v))),
        "v_var_ref": int(bool(VAR_REF_RE.match(v))),
        "v_is_url": int(v.lower().startswith(("http://", "https://", "ftp://"))),
        "v_has_at": int("@" in v),
        "v_known_prefix": int(v.startswith(KNOWN_PREFIXES)),
        "v_is_pem": int("-----BEGIN" in value),
        "v_has_newline": int("\n" in value),
        "v_all_same": int(n > 1 and uniq == 1),
        "v_looks_word": int(bool(v) and v.isalpha() and v.islower() and 3 <= n <= 20),
        "v_has_dot_or_slash": int("." in v or "/" in v),
    }


def line_features(line: str, value: str) -> dict:
    ln = line.strip()
    low = ln.lower()
    v = _strip_quotes(value)
    idx = ln.find(v) if v else -1
    left = low[:idx] if idx > 0 else low
    kw_left = [k for k in KEYWORDS if k in left]
    return {
        "l_len": len(ln),
        "l_is_comment": int(ln.startswith(("#", "//", "/*", "*", "--", ";", "<!--", "%"))),
        "l_has_assign": int("=" in ln or ":" in ln),
        "l_has_quote_around": int(bool(value) and value.strip()[:1] in "\"'`"),
        "l_kw_left_count": len(kw_left),
        "l_kw_password": int(any(k in left for k in ("password", "passwd", "pwd"))),
        "l_kw_secret": int("secret" in left),
        "l_kw_token": int("token" in left),
        "l_kw_key": int("key" in left),
        "l_call_after": int(idx >= 0 and "(" in ln[idx + len(v):idx + len(v) + 3]),
        "l_call_before": int(bool(re.search(r"[A-Za-z_]\w*\(\s*$", ln[:idx] if idx > 0 else ""))),
        "l_is_json_key": int(bool(re.search(r"[\"'][\w\-.]+[\"']\s*:\s*[\"']", ln))),
        "l_has_example_word": int(bool(re.search(r"example|e\.g\.|sample|dummy|fake|your|todo|xxx", low))),
        "l_has_getenv": int(bool(re.search(r"getenv|environ|process\.env|os\.environ|ENV\[|System\.getProperty", ln))),
        "l_value_share": len(v) / len(ln) if ln else 0.0,
    }


def context_features(before: str, after: str) -> dict:
    ctx = (before + "\n" + after).lower()
    return {
        "c_example_word": int(bool(re.search(r"example|sample|dummy|fake|demo|placeholder|your_|todo|xxx", ctx))),
        "c_test_word": int(bool(re.search(r"\btest|mock|fixture|assert|expect\b", ctx))),
        "c_doc_word": int(bool(re.search(r"usage|install|readme|```|\$ |curl |export ", ctx))),
        "c_secret_word": int(bool(re.search(r"secret|password|token|credential|api[_-]?key", ctx))),
        "c_comment_density": sum(1 for l in (before + "\n" + after).splitlines() if l.strip().startswith(("#", "//", "*"))) / 6.0,
    }


def path_features(path: str, ext: str) -> dict:
    low = "/" + path.lower().replace("\\", "/")
    out = {k: int(any(tok in low for tok in toks)) for k, toks in PATH_FLAGS.items()}
    out["p_depth"] = low.count("/")
    out["p_ext_code"] = int(ext in LANG_CODE)
    out["p_ext_conf"] = int(ext in LANG_CONF)
    out["p_ext_doc"] = int(ext in LANG_DOC)
    out["p_ext_none"] = int(ext == "")
    out["p_is_lock"] = int("lock" in low or "package-lock" in low or "yarn" in low)
    return out


TOP_CATEGORIES = ["Password", "Key", "Secret", "Token", "UUID", "PEM Private Key", "Auth", "URL Credentials", "Credential",
                  "API", "Other"]


def category_features(category: str, predefined: str) -> dict:
    """The detector's own rule family (the CredSweeper category here, the Gitleaks RuleID at inference)."""
    cat = category or ""
    out = {f"r_{c.lower().replace(' ', '_')}": int(c in cat) for c in TOP_CATEGORIES}
    out["r_predefined"] = int(bool(predefined))
    out["r_n_rules"] = cat.count(":") + 1 if cat else 0
    return out


def featurize_row(rec: dict, use_rule: bool = True) -> dict:
    feats = {}
    feats.update(value_features(rec["value"]))
    feats.update(line_features(rec["line"], rec["value"]))
    feats.update(context_features(rec["before"], rec["after"]))
    feats.update(path_features(rec["path"], rec["ext"]))
    if use_rule:
        feats.update(category_features(rec["category"], rec["predefined"]))
    return feats


def featurize(df: pd.DataFrame, use_rule: bool = True) -> pd.DataFrame:
    rows = [featurize_row(r, use_rule) for r in df.to_dict("records")]
    return pd.DataFrame(rows).astype(float)


def masked_text(rec: dict) -> str:
    """Line with the secret replaced by a marker plus the path words: the text the n-gram model reads."""
    line = rec["line"]
    v = _strip_quotes(rec["value"])
    if v and v in line:
        line = line.replace(v, " <SECRET> ", 1)
    path_words = " ".join(re.split(r"[/_.\-]+", rec["path"].lower())[-6:])
    return f"{line} || {path_words}"
