"""Inference for the secret-triage model: takes Gitleaks findings, returns a verdict + reasons per finding.

Input per finding (the fields of a Gitleaks report): RuleID, File, StartLine, Match, Secret, Entropy.
Gitleaks gives no neighbouring lines, so the model uses only the value, the match, the path and the rule family.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import features as F  # noqa: E402

DEFAULT_BUNDLE = Path(__file__).resolve().parent / "artifacts" / "secret_triage.joblib"

VERDICT_LABEL = {
    "LIKELY_REAL": "Probablement réel",
    "REVIEW": "À vérifier",
    "LIKELY_FALSE_POSITIVE": "Probablement faux positif",
}


_MATCH_VALUE = re.compile(r"(?:=>|:=|==|=|:)\s*[\"'`]?(.+?)[\"'`]?\s*[;,)]*\s*$", re.S)


def value_from_match(match: str) -> str:
    """Best-effort secret value from a stored Gitleaks match (``KEY = 'value'``) when the raw value is unavailable,
    e.g. scans stored before the triage existed. PEM blocks and bare tokens are returned as they are."""
    m = (match or "").strip()
    if not m or m.startswith("-----BEGIN"):
        return m
    found = _MATCH_VALUE.search(m)
    return found.group(1) if found else m


def finding_to_record(f: dict) -> dict:
    """Gitleaks finding -> the record format the features expect."""
    path = (f.get("File") or f.get("file") or "").replace("\\", "/")
    ext = ""
    base = path.rsplit("/", 1)[-1]
    if "." in base:
        ext = "." + base.rsplit(".", 1)[-1].lower()
    secret = f.get("Secret") if f.get("Secret") is not None else f.get("secret")
    match = f.get("Match") if f.get("Match") is not None else f.get("match", "")
    if not secret:
        secret = value_from_match(match or "")
    return {
        "value": str(secret)[:400],
        "line": str(match or secret)[:600],
        "before": "",
        "after": "",
        "path": path,
        "ext": ext,
        "category": "",
        "predefined": "",
    }


def featurize_findings(findings: list[dict], columns: list[str]) -> pd.DataFrame:
    recs = [finding_to_record(f) for f in findings]
    X = F.featurize(pd.DataFrame(recs), use_rule=False)
    return X.reindex(columns=columns, fill_value=0.0)


REASON_TEXT = {
    # feature: (text when it pushes toward REAL, text when it pushes toward FALSE POSITIVE)
    "v_placeholder": ("", "la valeur ressemble à un placeholder (exemple, xxx, changeme…)"),
    "v_var_ref": ("", "c'est une référence à une variable, pas une valeur"),
    "v_hexlen_hash": ("", "la forme ressemble à un hash (md5 / sha)"),
    "v_is_uuid": ("format UUID typique d'un identifiant secret", "la valeur est un UUID (identifiant, pas un secret)"),
    "v_entropy": ("valeur très aléatoire (entropie élevée)", "valeur peu aléatoire (entropie faible)"),
    "v_entropy_norm": ("caractères bien répartis, comme une clé", "caractères peu variés"),
    "v_known_prefix": ("préfixe de clé connu (AKIA, ghp_, sk-, BEGIN PRIVATE KEY…)", ""),
    "v_is_pem": ("clé privée au format PEM", ""),
    "v_looks_word": ("", "ressemble à un mot courant"),
    "v_len": ("longueur typique d'un secret", "longueur atypique pour un secret"),
    "v_log_len": ("longueur typique d'un secret", "longueur atypique pour un secret"),
    "v_b64_text": ("", "décodé en base64, c'est du texte lisible"),
    "v_is_url": ("", "la valeur est une URL"),
    "p_test": ("", "fichier de test"),
    "p_example": ("", "fichier d'exemple ou de démonstration"),
    "p_doc": ("", "fichier de documentation"),
    "p_fixture": ("", "fichier de jeu de données de test (fixture / mock)"),
    "p_i18n": ("", "fichier de traduction"),
    "p_vendor": ("", "code tiers (vendor / node_modules)"),
    "p_config": ("fichier de configuration", ""),
    "p_ext_doc": ("", "extension de documentation"),
    "l_kw_password": ("nom de variable « password »", ""),
    "l_kw_secret": ("nom de variable « secret »", ""),
    "l_kw_token": ("nom de variable « token »", ""),
    "l_kw_key": ("nom de variable « key »", ""),
    "l_kw_left_count": ("plusieurs mots-clés de secret dans le nom", ""),
    "l_has_example_word": ("", "le texte contient « example / sample / dummy… »"),
    "l_has_getenv": ("", "la valeur vient d'une variable d'environnement"),
    "l_call_after": ("", "appel de fonction, pas une valeur littérale"),
    "v_frac_digit": ("", "valeur essentiellement numérique"),
    "v_vowel_ratio": ("", "répartition de voyelles proche d'un mot lisible"),
    "v_uniq_ratio": ("", "peu de caractères différents"),
}


# Continuous features may explain a verdict in either direction; every other feature is a 0/1 flag and is only
# worth quoting when it is actually set (a missing "test file" flag is not a reason).
CONTINUOUS_CONDITION = {
    "v_entropy": lambda v: True,
    "v_entropy_norm": lambda v: True,
    "v_len": lambda v: True,
    "v_log_len": lambda v: True,
    "l_kw_left_count": lambda v: v >= 1,
    "v_frac_digit": lambda v: v >= 0.7,
    "v_vowel_ratio": lambda v: 0.25 <= v <= 0.65,
    "v_uniq_ratio": lambda v: v <= 0.4,
    "v_b64_text": lambda v: v >= 0.9,
}


def explain(contribs: np.ndarray, columns: list[str], values: np.ndarray, top: int = 3) -> list[str]:
    """Top contributing features as short French reasons. contribs > 0 push toward 'real secret'."""
    order = np.argsort(-np.abs(contribs))
    out: list[str] = []
    for i in order:
        if len(out) >= top:
            break
        name = columns[i]
        if abs(contribs[i]) < 0.15:
            break
        cond = CONTINUOUS_CONDITION.get(name)
        if not (cond(values[i]) if cond else values[i] >= 0.5):
            continue
        real_txt, fp_txt = REASON_TEXT.get(name, ("", ""))
        txt = real_txt if contribs[i] > 0 else fp_txt
        if txt and txt not in out:
            out.append(txt)
    return out


# ───────────── deterministic noise rules (found on real repositories, see big_eval.py) ─────────────
# CredData labels most UUIDs and anything in a test folder as credentials; real scanners also surface project GUIDs,
# hashes and obvious dummies. These rules only fire on precise shapes, and each gives its reason.
NON_SECRET_EXT = {".sln", ".po", ".pot", ".svg", ".csproj", ".map"}
HASH_KEY = re.compile(r"(s3key|sha\d*|md5|checksum|digest|etag|integrity|build[_-]?id|commit)", re.I)
DUMMY_VALUE = re.compile(r"(abc123|123456|abcdef|qwerty|aaaaaa|000000|1234abcd)", re.I)
HASHED_PASSWORD = ("md5$", "sha1$", "pbkdf2_", "bcrypt$", "$2a$", "$2b$", "$2y$", "argon2", "{SSHA}", "{SHA}")
# Checked on CredData (27k labelled rows) before being added: none of these three fires on a real secret there.
PEOPLE_FILES = {"authors", "contributors", "maintainers", "credits"}
HASHED_FILE = re.compile(r"[0-9a-fA-F]{32,}\.(zip|tar|gz|tgz|jar|json|js|css|png|bin)")
SECRET_WORDS = ("password", "passwd", "pwd", "secret", "token", "api_key", "apikey", "api-key", "access_key", "private_key",
                "credential", "auth", "bearer", "key")


def noise_reason(rec: dict) -> str | None:
    """A reason why this candidate is certainly not a secret, or None (the model then decides)."""
    value = F._strip_quotes(rec["value"]).strip("{}")
    line = rec["line"]
    idx = line.find(rec["value"].strip()) if rec["value"].strip() else -1
    left = line[:idx].lower() if idx > 0 else ""
    if rec["ext"] in NON_SECRET_EXT:
        return "fichier de projet ou de traduction (" + rec["ext"] + "), pas un secret"
    if F.UUID_RE.match(value) and not any(w in left for w in SECRET_WORDS):
        return "identifiant UUID / GUID dont le nom n'évoque pas un secret"
    if HASH_KEY.search(left) and re.fullmatch(r"[0-9a-fA-F]{32,}", value or ""):
        return "empreinte (hash) et non un secret"
    if HASHED_FILE.fullmatch(value or ""):
        return "nom de fichier fait d'une empreinte (hash), pas un secret"
    if value.startswith(HASHED_PASSWORD):
        return "mot de passe déjà haché"
    if 0 < len(value) <= 24 and DUMMY_VALUE.search(value):
        return "valeur factice (suite évidente comme abc123)"
    base = rec["path"].rsplit("/", 1)[-1].lower()
    if "truststore" in base or base == "cacerts":
        return "magasin de certificats publics (truststore)"
    if base.split(".")[0] in PEOPLE_FILES:
        return "liste des auteurs du projet (noms et e-mails), pas un secret"
    raw = rec["value"].strip()
    # "name@domain.tld" but not "user:PASSWORD@host" (connection strings keep their password before the @)
    if raw and re.search(r"(?:^|[\s\"'<(,=])" + re.escape(raw) + r"@[\w-]+\.[\w.]+", line):
        return "partie d'une adresse e-mail, pas un secret"
    return None


def path_scope(path: str, ext: str) -> str:
    """TEST_OR_DOC when the file is a test, example, fixture, documentation or translation file."""
    f = F.path_features(path, ext)
    low = "/" + path.lower().replace("\\", "/")
    # naming conventions the model's own flags miss (found on real repos: *.spec.ts, e2e / cypress folders, mocks)
    extra = any(t in low for t in (".spec.", ".test.", "_spec.", "/e2e/", "/cypress/", "__mocks__", "/mocks/", "/testing/"))
    return "TEST_OR_DOC" if extra or any(f[k] for k in ("p_test", "p_example", "p_doc", "p_fixture", "p_i18n")) else "PRODUCTION"


def priority(verdict: str, scope: str) -> int:
    """1 = look at it first. A probable real secret in production code outranks one in a test/doc file."""
    if verdict == "LIKELY_REAL":
        return 1 if scope == "PRODUCTION" else 2
    return 3 if verdict == "REVIEW" else 4


class SecretTriage:
    def __init__(self, bundle_path: Path = DEFAULT_BUNDLE, use_rules: bool = True):
        b = joblib.load(bundle_path)
        self.model = b["model"]
        self.iso = b["isotonic"]
        self.columns = b["columns"]
        self.t_false = b["thresholds"]["likely_false_below"]
        self.t_real = b["thresholds"]["likely_real_from"]
        self.version = b["version"]
        self.use_rules = use_rules

    def score(self, findings: list[dict]) -> list[dict]:
        if not findings:
            return []
        import xgboost as xgb
        X = featurize_findings(findings, self.columns)
        raw = self.model.predict_proba(X)[:, 1]
        proba = self.iso.predict(raw)
        contribs = self.model.get_booster().predict(xgb.DMatrix(X, feature_names=self.columns), pred_contribs=True)
        out = []
        for i in range(len(findings)):
            p = float(proba[i])
            verdict = "LIKELY_FALSE_POSITIVE" if p < self.t_false else "LIKELY_REAL" if p >= self.t_real else "REVIEW"
            rec = finding_to_record(findings[i])
            scope = path_scope(rec["path"], rec["ext"])
            reasons = explain(contribs[i][:-1], self.columns, X.iloc[i].to_numpy())
            rule = noise_reason(rec) if self.use_rules else None
            if rule:
                verdict, p, reasons = "LIKELY_FALSE_POSITIVE", min(p, 0.03), [rule]
            if scope == "TEST_OR_DOC" and verdict != "LIKELY_FALSE_POSITIVE":
                reasons.append("dans un fichier de test, d'exemple ou de documentation (priorité plus basse)")
            out.append({
                "verdict": verdict,
                "label": VERDICT_LABEL[verdict],
                "probaReal": round(p, 4),
                "scope": scope,
                "priority": priority(verdict, scope),
                "reasons": reasons,
                "modelVersion": self.version,
            })
        return out


def main() -> int:
    """stdin: JSON list of Gitleaks findings -> stdout: JSON list of verdicts (same order)."""
    findings = json.load(sys.stdin)
    print(json.dumps(SecretTriage().score(findings), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
