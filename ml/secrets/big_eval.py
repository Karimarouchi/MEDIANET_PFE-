"""Real-world evaluation: gitleaks and CredSweeper on many public repositories, judged by our triage model.

Reads E:\\MEDIANET ML\\secrets\\big_eval\\{gl,cs,cs_ml}/<repo>.json (written by big_eval/run.sh).
  python secrets/big_eval.py build     -> pools every finding and scores it (big_eval/pool.json)
  python secrets/big_eval.py sample N  -> writes a stratified sample to label (big_eval/sample.json)
  python secrets/big_eval.py score     -> metrics from big_eval/labels.json (hand-made labels)
"""
from __future__ import annotations

import collections
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime as R  # noqa: E402

BASE = Path(r"E:\MEDIANET ML\secrets\big_eval")


def jl(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except Exception:
        return []


def rel(path: str) -> str:
    return path.replace("\\", "/").replace("/tmp/w/", "")


def build() -> None:
    pool: dict[tuple, dict] = {}
    for gl_file in sorted((BASE / "gl").glob("*.json")):
        repo = gl_file.stem
        for f in jl(gl_file):
            key = (repo, rel(f["File"]), int(f["StartLine"]))
            d = pool.setdefault(key, {"repo": repo, "file": rel(f["File"]), "line": int(f["StartLine"]), "by": set(),
                                      "rules": set(), "secret": f.get("Secret") or "", "match": f.get("Match") or ""})
            d["by"].add("gitleaks")
            d["rules"].add(f["RuleID"])
            d["secret"] = d["secret"] or f.get("Secret") or ""
        for r in jl(BASE / "cs" / f"{repo}.json"):
            ld = r["line_data_list"][0]
            key = (repo, rel(ld["path"]), int(ld["line_num"]))
            d = pool.setdefault(key, {"repo": repo, "file": rel(ld["path"]), "line": int(ld["line_num"]), "by": set(),
                                      "rules": set(), "secret": ld.get("value") or "", "match": ld["line"].strip()})
            d["by"].add("credsweeper")
            d["rules"].add("cs:" + r["rule"])
            d["cs_p"] = max(d.get("cs_p") or 0, r.get("ml_probability") or 0) or d.get("cs_p")
    items = list(pool.values())
    triage = R.SecretTriage()
    findings = [{"RuleID": sorted(i["rules"])[0], "File": "/" + i["file"], "Match": i["match"][:600], "Secret": i["secret"]}
                for i in items]
    out = []
    for k in range(0, len(findings), 400):
        out += triage.score(findings[k:k + 400])
    for i, o in zip(items, out):
        i["by"] = sorted(i["by"])
        i["rules"] = sorted(i["rules"])
        i["ours"] = o["verdict"]
        i["ours_p"] = o["probaReal"]
        i["scope"] = o["scope"]
        i["priority"] = o["priority"]
    (BASE / "pool.json").write_text(json.dumps(items), encoding="utf-8")
    both = sum(1 for i in items if len(i["by"]) == 2)
    print(f"{len(items)} candidats distincts : {sum(1 for i in items if 'gitleaks' in i['by'])} gitleaks, "
          f"{sum(1 for i in items if 'credsweeper' in i['by'])} CredSweeper, {both} par les deux")
    print(collections.Counter(i["repo"] for i in items).most_common())
    print(collections.Counter((i["by"][0] if len(i["by"]) == 1 else "les deux", i["priority"]) for i in items))


def sample(n: int) -> None:
    items = json.load(open(BASE / "pool.json", encoding="utf-8"))
    rng = random.Random(7)
    strata = collections.defaultdict(list)
    for idx, i in enumerate(items):
        strata[("+".join(i["by"]), i["priority"])].append(idx)
    chosen = []
    per = max(3, n // max(len(strata), 1))
    for k, idxs in sorted(strata.items()):
        rng.shuffle(idxs)
        chosen += idxs[:per]
    rng.shuffle(chosen)
    chosen = chosen[:n]
    rows = [{"id": c, "repo": items[c]["repo"][:14], "file": items[c]["file"][-52:], "line": items[c]["line"],
             "by": "+".join(items[c]["by"])[:12], "m": items[c]["match"][:80].replace("\n", " "),
             "v": items[c]["secret"][:40].replace("\n", " ")} for c in chosen]
    (BASE / "sample.json").write_text(json.dumps(rows, ensure_ascii=False), encoding="utf-8")
    print(len(rows), "a etiqueter")


def score() -> None:
    import numpy as np
    items = json.load(open(BASE / "pool.json", encoding="utf-8"))
    labels = {int(k): v for k, v in json.load(open(BASE / "labels.json")).items()}
    sample_ids = [i for i, v in labels.items() if v in ("R", "F")]
    key = lambda i: ("+".join(items[i]["by"]), items[i]["priority"])
    stratum_size = collections.Counter(key(i) for i in range(len(items)))
    n_in = collections.Counter(key(i) for i in sample_ids)
    w = {i: stratum_size[key(i)] / n_in[key(i)] for i in sample_ids}      # inverse inclusion probability
    y = {i: labels[i] == "R" for i in sample_ids}
    prod = {i: y[i] and R.path_scope("/" + items[i]["file"], "") == "PRODUCTION" for i in sample_ids}

    systems = {
        "gitleaks seul": lambda it: "gitleaks" in it["by"],
        "CredSweeper seul": lambda it: "credsweeper" in it["by"],
        "gitleaks + CredSweeper (tout)": lambda it: True,
        "notre modele sur gitleaks": lambda it: "gitleaks" in it["by"] and it["priority"] in (1, 3),
        "notre modele sur gitleaks + CredSweeper": lambda it: it["priority"] in (1, 3),
        "notre modele, sans repli test/doc": lambda it: it["priority"] in (1, 2, 3),
    }

    def metrics(ids, truth, shown):
        tp = sum(w[i] for i in ids if shown[i] and truth[i])
        fp = sum(w[i] for i in ids if shown[i] and not truth[i])
        fn = sum(w[i] for i in ids if not shown[i] and truth[i])
        tn = sum(w[i] for i in ids if not shown[i] and not truth[i])
        prec = tp / (tp + fp) if tp + fp else float("nan")
        rec = tp / (tp + fn) if tp + fn else float("nan")
        noise_cut = tn / (tn + fp) if tn + fp else float("nan")
        return prec, rec, noise_cut, tp + fp

    rng = np.random.default_rng(0)
    print(f"{len(sample_ids)} candidats etiquetes ({sum(y.values())} credentials, {len(y) - sum(y.values())} non-secrets), "
          f"{len(items)} dans le lot complet\n")
    for gt_name, truth in (("credential reel (n'importe ou)", y), ("credential en code de production", prod)):
        print(f"--- verite terrain : {gt_name}")
        print(f"{'systeme':<42}{'affiches':>9}{'precision':>11}{'rappel':>9}{'bruit ecarte':>14}   IC95% precision")
        for name, fn in systems.items():
            shown = {i: fn(items[i]) for i in sample_ids}
            prec, rec, cut, n_shown = metrics(sample_ids, truth, shown)
            boots = []
            by_stratum = collections.defaultdict(list)
            for i in sample_ids:
                by_stratum[key(i)].append(i)
            for _ in range(400):
                pick = [i for ids in by_stratum.values() for i in rng.choice(ids, size=len(ids))]
                pw = {i: w[i] for i in pick}
                tp = sum(pw[i] for i in pick if shown[i] and truth[i]); fp = sum(pw[i] for i in pick if shown[i] and not truth[i])
                if tp + fp:
                    boots.append(tp / (tp + fp))
            lo, hi = np.percentile(boots, [2.5, 97.5])
            print(f"{name:<42}{n_shown:>9.0f}{prec:>10.0%}{rec:>9.0%}{cut:>13.0%}    [{lo:.0%}-{hi:.0%}]")
        print()


def score_heldout() -> None:
    """Held-out check of the noise rules: sample2 was drawn and labelled before the rules were looked at in detail."""
    import numpy as np
    items = json.load(open(BASE / "pool.json", encoding="utf-8"))
    labels = {int(k): v for k, v in json.load(open(BASE / "labels2.json")).items() if v in ("R", "F")}
    ids = list(labels)
    key = lambda i: ("+".join(items[i]["by"]), items[i]["priority"])
    size = collections.Counter(key(i) for i in range(len(items)))
    n_in = collections.Counter(key(i) for i in ids)
    w = {i: size[key(i)] / n_in[key(i)] for i in ids}
    # priorities without the rules, for the same items
    t0 = R.SecretTriage(use_rules=False)
    base = t0.score([{"RuleID": items[i]["rules"][0], "File": "/" + items[i]["file"], "Match": items[i]["match"],
                      "Secret": items[i]["secret"]} for i in ids])
    p_off = {i: o["priority"] for i, o in zip(ids, base)}
    y = {i: labels[i] == "R" for i in ids}
    prod = {i: y[i] and R.path_scope("/" + items[i]["file"], "") == "PRODUCTION" for i in ids}
    systems = {
        "gitleaks seul": lambda i: "gitleaks" in items[i]["by"],
        "CredSweeper seul": lambda i: "credsweeper" in items[i]["by"],
        "gitleaks + CredSweeper (tout)": lambda i: True,
        "notre modele SANS regles de bruit": lambda i: p_off[i] in (1, 3),
        "notre modele AVEC regles de bruit": lambda i: items[i]["priority"] in (1, 3),
        "modele + regles, sans repli test/doc": lambda i: items[i]["priority"] in (1, 2, 3),
        "modele SANS regles, sans repli": lambda i: p_off[i] in (1, 2, 3),
    }
    print(f"{len(ids)} candidats etiquetes a l'aveugle ({sum(y.values())} credentials, {len(y)-sum(y.values())} non-secrets)\n")
    for gt_name, truth in (("credential reel (n'importe ou)", y), ("credential en code de production", prod)):
        print(f"--- verite terrain : {gt_name}")
        print(f"{'systeme':<42}{'affiches':>9}{'precision':>11}{'rappel':>9}{'bruit ecarte':>14}")
        for name, fn in systems.items():
            shown = {i: fn(i) for i in ids}
            tp = sum(w[i] for i in ids if shown[i] and truth[i]); fp = sum(w[i] for i in ids if shown[i] and not truth[i])
            fn_ = sum(w[i] for i in ids if not shown[i] and truth[i]); tn = sum(w[i] for i in ids if not shown[i] and not truth[i])
            prec = tp / (tp + fp) if tp + fp else float("nan"); rec = tp / (tp + fn_) if tp + fn_ else float("nan")
            cut = tn / (tn + fp) if tn + fp else float("nan")
            print(f"{name:<42}{tp+fp:>9.0f}{prec:>10.0%}{rec:>9.0%}{cut:>13.0%}")
        print()


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "build"
    if cmd == "build":
        build()
    elif cmd == "score":
        score()
    elif cmd == "heldout":
        score_heldout()
    elif cmd == "sample":
        sample(int(sys.argv[2]) if len(sys.argv) > 2 else 150)
    return 0


if __name__ == "__main__":
    sys.exit(main())
