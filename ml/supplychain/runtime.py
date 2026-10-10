"""
Runtime scoring of ONE npm or PyPI package for the Medianet application.

Pipeline (identical to training, in the same order):
    registry tarball (read in memory, never extracted or executed)
      -> raw features (features.py)            -> log transform + KNN imputation (fitted on train)
      -> anomaly scores (Isolation Forest, auto-encoder, trained on benign train packages)
      -> text scores (name letters, package description)   -> final classifier (XGBoost)
      -> two alert tiers, a probable type and human-readable reasons.

Plus a deterministic layer: names listed by OSSF malicious-packages are reported as KNOWN_MALICIOUS
without any model (exact name, and exact version when the report lists versions).
"""
import json
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import features as F  # noqa: E402
import repair as R  # noqa: E402
from types_rules import assign_type  # noqa: E402

ART_DIRS = {"npm": HERE / "artifacts", "pypi": HERE / "artifacts_pypi"}
ART = ART_DIRS["npm"]
BUNDLE = ART / "runtime_bundle.joblib"
KNOWN_MALICIOUS = ART / "known_malicious_npm.json"
REGISTRY = "https://registry.npmjs.org/"
PYPI_JSON = "https://pypi.org/pypi/"
MAX_TARBALL_BYTES = 5 * 1024 * 1024        # PyPI sdists: the PyPI model has not been trained on larger ones yet
MAX_NPM_TARBALL_BYTES = 25 * 1024 * 1024   # npm: the V5 model was trained on large packages up to this size
MAX_NPM_UNPACKED_BYTES = 150 * 1024 * 1024
HTTP_TIMEOUT = 25

session = requests.Session()
session.headers["User-Agent"] = "medianet-supplychain/1.0 (defensive dependency screening)"

TIER_HIGH, TIER_REVIEW, TIER_LOW = "HIGH_CONFIDENCE", "REVIEW", "LOW"
# Popularity guard: a top-5000 package is demoted from HIGH to REVIEW only when the model is NOT overwhelmingly
# sure. Real compromises of popular packages (e.g. elementary-data, mistralai) score 0.95-0.99 and stay HIGH;
# the false alarms seen on react-router / requests scored 0.64-0.73.
POPULAR_GUARD_MAX_PROBA = 0.90


def _text(value) -> str:
    """Missing text (None / NaN) is the empty string, exactly as in training (fillna(""))."""
    if value is None or (isinstance(value, float) and np.isnan(value)):
        return ""
    return str(value).lower()


def _vkey(version: str):
    """Sortable key for npm semver / PEP 440 versions (falls back to the numeric parts)."""
    try:
        from packaging.version import Version
        return (0, Version(version))
    except Exception:
        nums = [int(x) for x in re.findall(r"\d+", version or "")] or [0]
        return (1, tuple(nums))


def _cmp(a: str, b: str) -> int:
    ka, kb = _vkey(a), _vkey(b)
    if ka[0] != kb[0]:  # mixed key kinds: compare numeric parts only
        ka, kb = (1, tuple(int(x) for x in re.findall(r"\d+", a) or [0])), (1, tuple(int(x) for x in re.findall(r"\d+", b) or [0]))
    return (ka > kb) - (ka < kb)


def in_osv_range(version: str, events: list[dict]) -> bool:
    """OSV semantics: a version is affected from an `introduced` event until a `fixed` event (exclusive) or a
    `last_affected` event (inclusive)."""
    def when(e):
        v = e.get("introduced") or e.get("fixed") or e.get("last_affected") or "0"
        return v
    affected = False
    for e in sorted(events, key=lambda e: _vkey("0" if when(e) == "0" else when(e))):
        if "introduced" in e and _cmp(version, e["introduced"]) >= 0:
            affected = True
        elif "fixed" in e and _cmp(version, e["fixed"]) >= 0:
            affected = False
        elif "last_affected" in e and _cmp(version, e["last_affected"]) > 0:
            affected = False
    return affected


def version_in_scope(version: str | None, entry: dict) -> bool:
    if not version:
        return False  # cannot decide without a version: never claim "malicious"
    if version in (entry.get("versions") or []):
        return True
    return any(in_osv_range(version, events) for events in (entry.get("ranges") or []))


def normalize_for(eco: str, name: str) -> str:
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()  # PEP 503
    return F.normalize_name(name).lower()


class Scorer:
    def __init__(self, eco: str = "npm", bundle_path: Path | None = None, known_path: Path | None = None):
        self.eco = eco
        art = ART_DIRS[eco]
        bundle_path = bundle_path or art / "runtime_bundle.joblib"
        known_path = known_path or art / f"known_malicious_{eco}.json"
        self.bundle = joblib.load(bundle_path)
        self.cols = self.bundle["columns_numeric"]
        self.model_cols = self.bundle["model_columns"]
        self.tiers = self.bundle["tiers"]
        self.known = json.loads(known_path.read_text(encoding="utf-8")) if known_path.exists() else {}
        top_path = art / f"top_{eco}.txt"
        self.popular = ({normalize_for(eco, n) for n in top_path.read_text(encoding="utf-8").splitlines() if n.strip()}
                        if top_path.exists() else set())

    # ------------------------------------------------------------------ deterministic layer
    def known_malicious(self, name: str, version: str | None):
        """KNOWN_MALICIOUS only when the reported scope really covers THIS version (list or interval)."""
        entry = self.known.get(normalize_for(self.eco, name), "absent")
        if entry == "absent":
            return None
        if version and version.endswith("-security"):
            # npm replaces a removed malicious package by an empty "security holding" placeholder (x.y.z-security):
            # that placeholder is the registry's own fix, not malware.
            return None
        if entry is None:  # legacy file format: "every version"
            entry = {"id": None, "all": True, "versions": [], "ranges": []}
        if entry.get("all"):
            return {"id": entry.get("id"), "scope": "ALL_VERSIONS"}
        if version_in_scope(version, entry):
            return {"id": entry.get("id"), "scope": "THIS_VERSION"}
        return None  # the package had malicious versions, but not this one

    # ------------------------------------------------------------------ model layer
    def score_features(self, row: dict) -> dict:
        b = self.bundle
        x = pd.DataFrame([{c: row.get(c) for c in self.cols}], columns=self.cols).astype(float)
        x = R.log_transform(x, self.cols)
        filled = pd.DataFrame(b["imputer"].transform(x.to_numpy(dtype=float, copy=True)), columns=self.cols)
        iso = float(-b["isolation_forest"].score_samples(filled)[0])
        ae = float(R.reconstruction_error(b["autoencoder"], b["scaler"], filled)[0])
        name = pd.Series([_text(row.get("name"))])
        meta = pd.Series([_text(row.get("meta_text"))])
        values = filled.iloc[0].to_dict()
        values.update({
            "iforest_score": iso, "autoencoder_error": ae,
            "name_char_score": float(b["name_scorer"].predict_proba(name)[0, 1]),
            "meta_text_score": float(b["meta_scorer"].predict_proba(meta)[0, 1]),
        })
        frame = pd.DataFrame([{c: values[c] for c in self.model_cols}], columns=self.model_cols)
        proba = float(b["model"].predict_proba(frame)[0, 1])
        drivers = self._drivers(frame)
        tier = TIER_HIGH if proba >= self.tiers["high_confidence"] else TIER_REVIEW if proba >= self.tiers["review"] else TIER_LOW
        return {"suspicionProba": proba, "tier": tier, "anomalyScore": iso, "reconstructionError": ae,
                "drivers": drivers}

    def _drivers(self, frame, top: int = 10) -> list[dict]:
        """Per-feature contribution to THIS prediction (TreeSHAP built into XGBoost). Empty if unsupported."""
        model = self.bundle["model"]
        if not hasattr(model, "get_booster"):
            return []
        try:
            import xgboost as xgb
            contrib = model.get_booster().predict(xgb.DMatrix(frame), pred_contribs=True)[0][:-1]
        except Exception:
            return []
        items = [{"feature": c, "impact": float(v), "value": float(frame.iloc[0][c])}
                 for c, v in zip(self.model_cols, contrib)]
        return sorted(items, key=lambda d: -d["impact"])[:top]


# ---------------------------------------------------------------------- human-readable reasons
# Plain-language meaning of the model inputs. Prefix rules are checked after exact names.
FEATURE_LABELS = {
    "name_char_score": "Le nom ressemble à ceux de paquets malveillants connus",
    "meta_text_score": "La description et les mots-clés ressemblent à ceux de paquets malveillants",
    "iforest_score": "Contenu globalement inhabituel par rapport aux paquets normaux",
    "autoencoder_error": "Contenu globalement inhabituel par rapport aux paquets normaux",
    "hook_pipe_to_shell": "Le script d'installation télécharge puis exécute du code",
    "hook_url_unknown_host": "Le script d'installation contacte un serveur inconnu",
    "ast_source_and_sink_in_function": "Une même fonction lit des informations de la machine et fait une requête réseau",
    "ast_source_and_sink_in_file": "Le code lit des informations de la machine et fait des requêtes réseau",
    "ast_exec_decoded_payload": "Exécute du code décodé à la volée (base64, zlib, marshal)",
    "version_absurd_high": "Version anormalement élevée (typique d'une confusion de dépendances)",
    "version_all_nines": "Version anormalement élevée (typique d'une confusion de dépendances)",
    "install_script_suspicious": "Le script d'installation contient des commandes suspectes",
    "has_install_script": "Exécute un script au moment de l'installation",
    "install_script_len": "Exécute un script au moment de l'installation",
    "install_script_runs_node": "Exécute un script au moment de l'installation",
    "name_spam_shape": "Nom au motif généré (typique des campagnes de spam)",
    "has_repository": "Métadonnées incomplètes (dépôt de code absent)",
    "has_readme": "Métadonnées incomplètes (pas de README)",
    "has_license_file": "Métadonnées incomplètes (pas de licence)",
    "has_license": "Métadonnées incomplètes (pas de licence)",
    "has_tests_dir": "Pas de dossier de tests, contrairement aux paquets normaux",
}
FEATURE_PREFIX_LABELS = (
    ("hook_target_exfil", "Le script lancé à l'installation référence un service d'exfiltration"),
    ("hook_target_network", "Le script lancé à l'installation fait des requêtes réseau"),
    ("hook_target_env", "Le script lancé à l'installation lit l'environnement de la machine"),
    ("hook_target_sensitive", "Le script lancé à l'installation accède à des chemins sensibles"),
    ("hook_target_child", "Le script lancé à l'installation exécute des commandes système"),
    ("hook_", "Comportement du script d'installation inhabituel"),
    ("n_exfil_domain", "Références à des services d'exfiltration (webhook, ngrok, pastebin…)"),
    ("n_sensitive_path", "Références à des chemins sensibles (clés SSH, jetons, portefeuilles…)"),
    ("n_child_process", "Exécution de commandes système"),
    ("n_network_module", "Requêtes réseau dans le code"),
    ("ast_network", "Requêtes réseau dans le code"),
    ("n_env_access", "Lecture des variables d'environnement"),
    ("n_host_recon", "Collecte d'informations sur la machine (nom d'hôte, utilisateur)"),
    ("ast_secret", "Lecture d'informations sensibles de la machine"),
    ("n_base64", "Données encodées ou compressées dans le code (base64, zlib)"),
    ("n_charcode", "Chaînes construites caractère par caractère"),
    ("n_obfuscator", "Code obfusqué (identifiants illisibles)"),
    ("ast_hex_ident", "Code obfusqué (identifiants illisibles)"),
    ("ast_dynamic", "Code caché : exec/eval ou import dont l'argument est calculé"),
    ("n_eval", "Code évalué dynamiquement (eval/exec)"),
    ("n_new_function", "Code évalué dynamiquement (eval/exec)"),
    ("n_download_exec", "Télécharge puis exécute du code"),
    ("code_entropy", "Code très dense ou minifié"),
    ("pct_long_lines", "Code très dense ou minifié"),
    ("max_line_len", "Code très dense ou minifié"),
    ("name_", "Forme du nom atypique"),
    ("md_", "Métadonnées atypiques"),
    ("n_text_files", "Structure du paquet atypique (nombre de fichiers)"),
    ("n_files_total", "Structure du paquet atypique (nombre de fichiers)"),
    ("n_code_files", "Structure du paquet atypique (nombre de fichiers)"),
    ("code_bytes", "Structure du paquet atypique (taille du code)"),
    ("ast_files", "Structure du paquet atypique (fichiers analysables)"),
    ("ast_", "Structure du code atypique"),
)


def label_for(feature: str) -> str:
    if feature in FEATURE_LABELS:
        return FEATURE_LABELS[feature]
    for prefix, label in FEATURE_PREFIX_LABELS:
        if feature.startswith(prefix):
            return label
    return "Combinaison de signaux statistiques inhabituels"


def reasons_from_drivers(drivers: list[dict], limit: int = 4, min_impact: float = 0.25) -> list[str]:
    """Reasons = the model inputs that REALLY pushed the score up (XGBoost contributions, log-odds), grouped by
    meaning. Nothing is invented: a reason is shown only if it contributed to this very decision."""
    grouped: dict[str, float] = {}
    for d in drivers:
        if d["impact"] >= min_impact:
            lab = label_for(d["feature"])
            grouped[lab] = grouped.get(lab, 0.0) + d["impact"]
    ranked = sorted(grouped.items(), key=lambda kv: -kv[1])[:limit]
    return [lab for lab, _ in ranked]


def explain(row: dict) -> list[str]:
    g = lambda k: (row.get(k) if row.get(k) is not None and not (isinstance(row.get(k), float) and np.isnan(row.get(k))) else 0)
    reasons = []
    if g("version_absurd_high"):
        reasons.append("Version anormalement élevée (typique d'une attaque de confusion de dépendances)")
    if g("hook_pipe_to_shell") or g("n_download_exec"):
        reasons.append("Le script d'installation télécharge puis exécute du code (curl/wget vers un shell)")
    if g("hook_url_unknown_host") and not g("hook_known_build_tool"):
        reasons.append("Le script d'installation contacte un serveur inconnu")
    if g("ast_source_and_sink_in_function") or (g("hook_target_env") and g("hook_target_network")):
        reasons.append("Le code lit des secrets (variables d'environnement, fichiers sensibles) et fait une requête réseau")
    if g("hook_target_exfil_domain") or g("n_exfil_domain"):
        reasons.append("Références à des services d'exfiltration (webhook, ngrok, pastebin…)")
    if g("n_sensitive_path") or g("hook_target_sensitive"):
        reasons.append("Accède à des chemins sensibles (~/.ssh, .npmrc, portefeuilles…)")
    if g("ast_dynamic_require") or g("ast_dynamic_eval"):
        reasons.append("Code caché : require/eval avec un argument calculé")
    if g("n_obfuscator_ident") >= 5 or g("ast_hex_ident_ratio") > 0.05:
        reasons.append("Code obfusqué (identifiants hexadécimaux)")
    if g("code_bytes") < 300 and not g("has_install_script"):
        reasons.append("Paquet quasi vide : le nom est peut-être simplement squatté")
    if g("name_spam_shape"):
        reasons.append("Nom au motif généré (typique des campagnes de spam)")
    if g("has_install_script") and not g("hook_known_build_tool") and not g("has_binding_gyp"):
        reasons.append("Exécute un script à l'installation sans outil de compilation connu")
    return reasons[:6]


def explain_pypi(row: dict) -> list[str]:
    g = lambda k: (row.get(k) if row.get(k) is not None and not (isinstance(row.get(k), float) and np.isnan(row.get(k))) else 0)
    reasons = []
    if g("version_absurd_high"):
        reasons.append("Version anormalement élevée (typique d'une attaque de confusion de dépendances)")
    if g("hook_pipe_to_shell") or g("n_download_exec"):
        reasons.append("Télécharge puis exécute du code (curl/wget vers un shell, chmod +x)")
    if g("ast_exec_decoded_payload"):
        reasons.append("Exécute du code décodé à la volée (exec/eval sur du base64, zlib ou marshal)")
    elif g("ast_dynamic_eval"):
        reasons.append("Code caché : exec/eval avec un argument calculé")
    if g("ast_source_and_sink_in_function") or (g("hook_target_env") and g("hook_target_network")):
        reasons.append("Le code lit des informations de la machine (variables d'environnement, nom d'hôte, utilisateur) et fait une requête réseau")
    if g("hook_target_network") and g("has_install_script"):
        reasons.append("setup.py fait des requêtes réseau pendant l'installation")
    if g("hook_target_exfil_domain") or g("n_exfil_domain"):
        reasons.append("Références à des services d'exfiltration (webhook, ngrok, pastebin, Telegram…)")
    if g("n_sensitive_path") or g("hook_target_sensitive"):
        reasons.append("Accède à des chemins sensibles (~/.ssh, ~/.aws, portefeuilles, cookies…)")
    if g("ast_dynamic_require"):
        reasons.append("Import dynamique d'un module dont le nom est calculé")
    if g("n_obfuscator_ident") >= 5 or g("ast_hex_ident_ratio") > 0.05:
        reasons.append("Code obfusqué (identifiants illisibles)")
    if g("code_bytes") < 300 and not g("has_install_script"):
        reasons.append("Paquet quasi vide : le nom est peut-être simplement squatté")
    if g("name_spam_shape"):
        reasons.append("Nom au motif généré (typique des campagnes de spam)")
    if g("has_install_script") and not g("hook_known_build_tool"):
        reasons.append("setup.py exécute du code personnalisé à l'installation")
    return reasons[:6]


# ---------------------------------------------------------------------- registry access
def fetch_npm_archive(name: str, version: str | None):
    """Returns (bytes, resolved_version) or (None, reason). The archive is only kept in memory."""
    from urllib.parse import quote
    try:
        url = REGISTRY + quote(name, safe="@") + "/" + (quote(version) if version else "latest")
        r = session.get(url, timeout=HTTP_TIMEOUT)
        if r.status_code == 404 and version:  # unknown exact version: fall back to the latest one
            r = session.get(REGISTRY + quote(name, safe="@") + "/latest", timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            return None, "NOT_FOUND"
        if not r.ok:
            return None, f"REGISTRY_{r.status_code}"
        doc = r.json()
        dist = doc.get("dist") or {}
        if (dist.get("unpackedSize") or 0) > MAX_NPM_UNPACKED_BYTES:
            return None, "TOO_LARGE"
        t = session.get(dist.get("tarball", ""), timeout=HTTP_TIMEOUT, stream=True)
        if not t.ok:
            return None, f"TARBALL_{t.status_code}"
        data = bytearray()
        for chunk in t.iter_content(65536):
            data += chunk
            if len(data) > MAX_NPM_TARBALL_BYTES:
                return None, "TOO_LARGE"
        return bytes(data), doc.get("version") or version
    except requests.RequestException as exc:
        return None, f"NETWORK_{type(exc).__name__}"


def fetch_pypi_archive(name: str, version: str | None):
    """Source distribution (sdist) of a PyPI release, in memory. Returns (bytes, resolved_version, suffix)
    or (None, reason, None). Wheels are skipped: they carry no setup.py, the install-time attack surface."""
    from urllib.parse import quote
    try:
        base = PYPI_JSON + quote(name)
        r = session.get(f"{base}/{quote(version)}/json" if version else f"{base}/json", timeout=HTTP_TIMEOUT)
        if r.status_code == 404 and version:
            r = session.get(f"{base}/json", timeout=HTTP_TIMEOUT)
        if r.status_code == 404:
            return None, "NOT_FOUND", None
        if not r.ok:
            return None, f"REGISTRY_{r.status_code}", None
        doc = r.json()
        sdists = [u for u in doc.get("urls", []) if u.get("packagetype") == "sdist"]
        if not sdists:
            return None, "NO_SDIST", None
        u = sdists[0]
        if (u.get("size") or 0) > MAX_TARBALL_BYTES:
            return None, "TOO_LARGE", None
        t = session.get(u["url"], timeout=HTTP_TIMEOUT, stream=True)
        if not t.ok:
            return None, f"TARBALL_{t.status_code}", None
        data = bytearray()
        for chunk in t.iter_content(65536):
            data += chunk
            if len(data) > MAX_TARBALL_BYTES:
                return None, "TOO_LARGE", None
        return bytes(data), doc["info"].get("version") or version, (".zip" if u["filename"].endswith(".zip") else ".tgz")
    except requests.RequestException as exc:
        return None, f"NETWORK_{type(exc).__name__}", None


def extract_row_pypi(name: str, blob: bytes, suffix: str, version: str | None) -> dict:
    import features_pypi as P
    name = P.normalize_name(name)
    row = {"name": name}
    row.update(F.name_features(name, top_names=P.TOP_NAMES_PYPI))
    row.update(P.content_features(blob, suffix, version))
    return row


def extract_row(name: str, blob: bytes, kind: str = "tgz") -> dict:
    name = F.normalize_name(name)
    row = {"name": name}
    row.update(F.name_features(name))
    row.update(F.content_features(blob, kind))
    return row


def score_package(scorer: Scorer, name: str, version: str | None, archive: bytes | None = None,
                  kind: str = "tgz") -> dict:
    eco = scorer.eco
    out = {"name": name, "version": version, "ecosystem": eco}
    known = scorer.known_malicious(name, version)
    if known:
        out.update({"status": "SCORED", "tier": "KNOWN_MALICIOUS", "suspicionProba": 1.0,
                    "probableType": None, "knownMaliciousId": known["id"], "knownMaliciousScope": known["scope"],
                    "reasons": ["Listé comme malveillant par OSSF malicious-packages"]})
        return out
    resolved = version
    suffix = ".zip" if kind == "zip" else ".tgz"
    if archive is None:
        if eco == "pypi":
            archive, resolved, suffix = fetch_pypi_archive(name, version)
        else:
            archive, resolved = fetch_npm_archive(name, version)
        if archive is None:
            out.update({"status": resolved, "tier": None, "suspicionProba": None, "reasons": []})
            return out
    try:
        row = extract_row_pypi(name, archive, suffix, resolved) if eco == "pypi" else extract_row(name, archive, kind)
        res = scorer.score_features(row)
    except Exception as exc:  # corrupt archive etc.: report, never crash the whole scan
        out.update({"status": f"ERROR_{type(exc).__name__}", "tier": None, "suspicionProba": None, "reasons": []})
        return out
    popular = normalize_for(eco, name) in scorer.popular
    original_tier = res["tier"]
    if popular and original_tier == TIER_HIGH and res["suspicionProba"] < POPULAR_GUARD_MAX_PROBA:
        # Guard (A): a very popular package is never shown at the strictest tier by the statistical model alone.
        # A real compromise of such a package is caught by the OSSF list (above) once it is reported.
        res["tier"] = TIER_REVIEW
    flagged = res["tier"] != TIER_LOW
    drivers = res.pop("drivers", [])
    reasons = reasons_from_drivers(drivers) if flagged else []
    if flagged and not reasons:  # model without per-feature contributions: fall back to behaviour rules
        reasons = (explain_pypi(row) if eco == "pypi" else explain(row))
    if flagged and popular:
        reasons.insert(0, f"Paquet très populaire (top 5 000 {eco}) : probablement une fausse alerte, "
                          "à vérifier seulement si la version est récente ou inattendue")
    out.update({
        "status": "SCORED", "scoredVersion": resolved, **res,
        "popularPackage": popular,
        "tierBeforePopularityGuard": original_tier if original_tier != res["tier"] else None,
        "probableType": assign_type({**row, "label": 1}) if flagged else None,
        "reasons": reasons or (["Combinaison de signaux statistiques inhabituels"] if flagged else []),
        "drivers": [{"feature": d["feature"], "label": label_for(d["feature"]), "impact": round(d["impact"], 3)}
                    for d in drivers[:5] if d["impact"] > 0.05] if flagged else [],
    })
    return out
