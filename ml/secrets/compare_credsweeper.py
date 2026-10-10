"""Side-by-side of our triage model and CredSweeper's own ML filter on the same real Gitleaks findings.

Inputs (on E:\\MEDIANET ML\\secrets): gl_results/<repo>.json (gitleaks), cs_results/<repo>_ml.json (CredSweeper with
ML probabilities) and cs_results/<repo>_default.json (CredSweeper as shipped: what survives its ML filter).
Run from ml/:  python secrets/compare_credsweeper.py
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime as R  # noqa: E402

BASE = Path(r"E:\MEDIANET ML\secrets")
REPOS = ["pallets_flask", "cookiecutter_cookiecutter-django", "OWASP_NodeGoat", "juice-shop_juice-shop"]


def load(p):
    return json.load(open(BASE / p, encoding="utf-8"))


def index(results):
    """(path, line) -> best ml_probability (None when the rule bypasses the ML)."""
    idx = {}
    for r in results:
        for ld in r.get("line_data_list", []):
            key = (ld["path"], ld["line_num"])
            p = r.get("ml_probability")
            if key not in idx or (p is not None and (idx[key] is None or p > idx[key])):
                idx[key] = p
    return idx


def main() -> int:
    triage = R.SecretTriage()
    rows = []
    for repo in REPOS:
        gl = load(f"gl_results/{repo}.json")
        ours = triage.score(gl)
        ml_idx = index(load(f"cs_results/{repo}_ml.json"))
        kept_idx = index(load(f"cs_results/{repo}_default.json"))
        for f, o in zip(gl, ours):
            key = (f["File"], f["StartLine"])
            if key in kept_idx:
                cs = "garde"            # reported by CredSweeper as shipped
            elif key in ml_idx:
                cs = "filtre"           # found, then rejected by its ML filter
            else:
                cs = "non_detecte"      # its detector does not even propose this line
            rows.append({"repo": repo, "file": f["File"].replace(f"/out/eval_repos/{repo}/", ""),
                         "rule": f["RuleID"], "secret": (f["Secret"] or "")[:30].replace("\n", " "),
                         "ours": o["verdict"], "ours_p": o["probaReal"], "scope": o["scope"], "priority": o["priority"],
                         "cs": cs, "cs_p": ml_idx.get(key)})
    print(f"{len(rows)} secrets gitleaks sur {len(REPOS)} depots\n")
    print("Notre modele (priorite) x CredSweeper")
    tab = collections.Counter((r["priority"], r["cs"]) for r in rows)
    print(f"{'':<34}{'garde':>8}{'filtre':>8}{'non_detecte':>13}")
    names = {1: "1 reel, code de production", 2: "2 reel, fichier test/exemple/doc", 3: "3 a verifier", 4: "4 faux positif probable"}
    for p in (1, 2, 3, 4):
        print(f"{names[p]:<34}{tab[(p, 'garde')]:>8}{tab[(p, 'filtre')]:>8}{tab[(p, 'non_detecte')]:>13}")
    print("\nVisibles pour l'utilisateur :")
    print("  notre modele :", sum(1 for r in rows if r["priority"] in (1, 3)), "/", len(rows),
          "(les fichiers de test/exemple/doc sont replies)")
    print("  CredSweeper  :", sum(1 for r in rows if r["cs"] == "garde"), "/", len(rows),
          "(le reste est filtre ou non detecte)")
    print("\nDesaccords a examiner :")
    for r in rows:
        if (r["priority"] in (1, 3)) != (r["cs"] == "garde"):
            print(f"  nous=P{r['priority']} {r['ours_p']:.2f} | cs={r['cs']:<11} {r['repo'][:9]:<9} {r['file'][-40:]:<40} {r['secret'][:24]}")
    (BASE / "comparison_rows.json").write_text(json.dumps(rows, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
