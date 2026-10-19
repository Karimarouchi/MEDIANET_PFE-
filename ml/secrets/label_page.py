"""Builds a local labelling page for real gitleaks / CredSweeper candidates (big_eval pool on E:).

Picks N unlabelled candidates (more production files, every case the model hesitates on, several repositories,
no duplicate values), fetches a few lines of context from GitHub, and writes one self-contained HTML file. The page
saves answers in the browser as you go and exports them as labels3.json, same format as labels.json: {"<pool index>": "R"|"F"|"U"}.

  python label_page.py [N]               (default 200) new candidates
  python label_page.py --review FILE     re-open the candidates of a label file (e.g. labels3.json), answers pre-filled

The page is local on purpose: candidates come from public repositories but may still hold live secrets.
"""
from __future__ import annotations

import json
import random
import sys
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BIG = Path(r"E:\MEDIANET ML\secrets\big_eval")
CONTEXT = 3


def github_name(repo_key: str, known: list[str]) -> str | None:
    for full in known:
        if full.replace("/", "_") == repo_key:
            return full
    return None


def fetch_context(full: str, path: str, line: int) -> list[tuple[int, str]]:
    url = f"https://raw.githubusercontent.com/{full}/HEAD/{urllib.request.quote(path)}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "vulnix-labelling"}), timeout=15) as r:
            lines = r.read(2_000_000).decode("utf-8", "replace").splitlines()
    except Exception:
        return []
    lo, hi = max(1, line - CONTEXT), min(len(lines), line + CONTEXT)
    return [(n, lines[n - 1][:300]) for n in range(lo, hi + 1)]


def pick(pool: list[dict], labelled: set[str], n: int, seed: int = 7) -> list[int]:
    rnd = random.Random(seed)
    seen_values = set()
    candidates = []
    for i, c in enumerate(pool):
        if str(i) in labelled:
            continue
        key = (c["repo"], c["secret"])
        if key in seen_values:
            continue
        seen_values.add(key)
        candidates.append(i)
    # Every hesitation first, then production, then the rest; round-robin over repositories inside each bucket.
    def bucket(i):
        c = pool[i]
        if c["ours"] == "REVIEW":
            return 0
        return 1 if c["scope"] == "PRODUCTION" else 2
    chosen: list[int] = []
    quota = {0: n, 1: int(n * 0.55), 2: n}
    for b in (0, 1, 2):
        by_repo = defaultdict(list)
        for i in candidates:
            if bucket(i) == b and i not in chosen:
                by_repo[pool[i]["repo"]].append(i)
        for lst in by_repo.values():
            rnd.shuffle(lst)
        taken = 0
        while len(chosen) < n and taken < quota[b] and any(by_repo.values()):
            for repo in list(by_repo):
                if by_repo[repo] and len(chosen) < n and taken < quota[b]:
                    chosen.append(by_repo[repo].pop())
                    taken += 1
    rnd.shuffle(chosen)
    return chosen


PAGE = """<!doctype html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Étiquetage des secrets</title><style>
:root{--bg:#0f172a;--card:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--real:#f87171;--fp:#34d399;--unsure:#fbbf24;--line:#334155}
@media (prefers-color-scheme: light){:root:not([data-theme="dark"]){--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#475569;--line:#cbd5e1}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}
main{max-width:980px;margin:0 auto;padding:16px}h1{font-size:20px;margin:4px 0}
.bar{position:sticky;top:0;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--line);z-index:2}
.progress{height:8px;background:var(--line);border-radius:6px;overflow:hidden;margin:8px 0}.progress>div{height:100%;background:#38bdf8}
.rules{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin:12px 0;font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;margin:14px 0}
.card.cur{outline:2px solid #38bdf8}.meta{color:var(--muted);font-size:13px;word-break:break-all}
pre{background:#0b1220;color:#cbd5e1;border-radius:8px;padding:10px;overflow:auto;font-size:12.5px;margin:8px 0}
.hit{background:#7c2d12;color:#fde68a}.val{font-family:ui-monospace,monospace;background:#0b1220;color:#fde68a;padding:2px 6px;border-radius:6px;word-break:break-all}
.btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}button{border:0;border-radius:10px;padding:9px 14px;font-weight:600;cursor:pointer;font-size:14px}
.R{background:var(--real);color:#111}.F{background:var(--fp);color:#111}.U{background:var(--unsure);color:#111}.ghost{background:transparent;color:var(--text);border:1px solid var(--line)}
.done{opacity:.55}.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:700;margin-left:6px}
</style></head><body><main>
<div class="bar"><h1>Étiquetage des secrets — <span id="count">0</span> / __N__</h1>
<div class="progress"><div id="prog" style="width:0"></div></div>
<div class="btns"><button class="ghost" id="next">Aller au prochain sans réponse</button><button class="ghost" id="export">Exporter labels3.json</button>
<span class="meta" id="saved">Les réponses sont gardées dans ce navigateur au fur et à mesure.</span></div></div>
<div class="rules"><b>Une seule question : est-ce une vraie valeur secrète ?</b><br>
<b style="color:var(--real)">R — Réel</b> : clé privée, mot de passe, jeton, chaîne de connexion avec mot de passe… <b>même dans un dossier de test</b> (le dossier est jugé à part).<br>
<b style="color:var(--fp)">F — Faux positif</b> : exemple ou remplissage (changeme, xxx, &lt;password&gt;, ${VAR}), hash, identifiant public, nom de variable, URL sans mot de passe, texte.<br>
<b style="color:var(--unsure)">U — Incertain</b> : impossible de trancher.<br>
Clavier : <b>R</b> / <b>F</b> / <b>U</b> répond à la carte en surbrillance et passe à la suivante · <b>↑ ↓</b> change de carte.</div>
<div id="list"></div></main>
<script>
const DATA = __DATA__;
const KEY = "vulnix-secret-labels-v3";
const PRESET = __PRESET__;
let answers = Object.assign({}, PRESET); try { Object.assign(answers, JSON.parse(localStorage.getItem(KEY) || "{}")); } catch (e) {}
let cur = 0;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
function render() {
  const list = document.getElementById("list");
  list.innerHTML = DATA.map((c, k) => {
    const a = answers[c.id];
    const ctx = c.context.length ? c.context.map(([n, t]) => `<span class="${n === c.line ? "hit" : ""}">${String(n).padStart(4)}  ${esc(t)}</span>`).join("\\n")
                                  : esc(c.match);
    return `<div class="card ${k === cur ? "cur" : ""} ${a ? "done" : ""}" id="c${k}">
      <div class="meta">#${k + 1} · ${esc(c.repo)} · ${esc(c.file)} · ligne ${c.line} · ${esc(c.by)} ${c.scope === "PRODUCTION" ? '<span class="tag" style="background:#1d4ed8;color:#fff">production</span>' : '<span class="tag" style="background:#475569;color:#fff">test / doc</span>'}
      ${a ? `<span class="tag ${a}">réponse : ${a}</span>` : ""}</div>
      <div style="margin-top:6px">Valeur signalée : <span class="val">${esc(c.secret.slice(0, 160))}</span></div>
      <pre>${ctx}</pre>
      <div class="btns"><button class="R" data-k="${k}" data-v="R">R — Réel</button><button class="F" data-k="${k}" data-v="F">F — Faux positif</button><button class="U" data-k="${k}" data-v="U">U — Incertain</button></div></div>`;
  }).join("");
  const n = Object.keys(answers).filter((id) => DATA.some((c) => String(c.id) === id)).length;
  document.getElementById("count").textContent = n;
  document.getElementById("prog").style.width = (100 * n / DATA.length) + "%";
}
function answer(k, v) {
  answers[DATA[k].id] = v;
  try { localStorage.setItem(KEY, JSON.stringify(answers)); } catch (e) {}
  const nxt = DATA.findIndex((c, i) => i > k && !answers[c.id]);
  cur = nxt >= 0 ? nxt : k;
  render(); document.getElementById("c" + cur).scrollIntoView({ block: "center" });
}
document.addEventListener("click", (e) => { const b = e.target.closest("button[data-v]"); if (b) answer(+b.dataset.k, b.dataset.v); });
document.addEventListener("keydown", (e) => {
  const k = e.key.toUpperCase();
  if (["R", "F", "U"].includes(k)) answer(cur, k);
  if (e.key === "ArrowDown") { cur = Math.min(DATA.length - 1, cur + 1); render(); document.getElementById("c" + cur).scrollIntoView({ block: "center" }); e.preventDefault(); }
  if (e.key === "ArrowUp") { cur = Math.max(0, cur - 1); render(); document.getElementById("c" + cur).scrollIntoView({ block: "center" }); e.preventDefault(); }
});
document.getElementById("next").onclick = () => { const i = DATA.findIndex((c) => !answers[c.id]); if (i >= 0) { cur = i; render(); document.getElementById("c" + i).scrollIntoView({ block: "center" }); } };
document.getElementById("export").onclick = () => {
  const out = {}; DATA.forEach((c) => { if (answers[c.id]) out[String(c.id)] = answers[c.id]; });
  const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([JSON.stringify(out, null, 1)], { type: "application/json" }));
  a.download = "labels3.json"; a.click();
};
render();
</script></body></html>"""


def main() -> int:
    review = sys.argv[2] if len(sys.argv) > 2 and sys.argv[1] == "--review" else None
    n = int(sys.argv[1]) if len(sys.argv) > 1 and not review else 200
    pool = json.loads((BIG / "pool.json").read_text(encoding="utf-8"))
    labelled = set()
    for f in ("labels.json", "labels2.json", "labels3.json"):
        if (BIG / f).exists():
            labelled |= set(json.loads((BIG / f).read_text(encoding="utf-8")))
    known = [l.strip() for l in (BIG / "repos.txt").read_text(encoding="utf-8").splitlines() if l.strip()]
    preset = json.loads((BIG / review).read_text(encoding="utf-8")) if review else {}
    ids = [int(k) for k in preset] if review else pick(pool, labelled, n)

    def one(i):
        c = pool[i]
        full = github_name(c["repo"], known)
        line = int(c["line"]) if str(c["line"]).isdigit() else 0
        ctx = fetch_context(full, c["file"], line) if full and line else []
        by = c["by"] if isinstance(c["by"], str) else ",".join(c["by"])
        return {"id": i, "repo": full or c["repo"], "file": c["file"], "line": line, "by": by, "scope": c["scope"],
                "secret": c["secret"], "match": c["match"], "context": ctx}

    with ThreadPoolExecutor(8) as ex:
        data = list(ex.map(one, ids))
    out = BIG / "etiquetage.html"
    out.write_text(PAGE.replace("__N__", str(len(data))).replace("__PRESET__", json.dumps(preset))
                   .replace("__DATA__", json.dumps(data, ensure_ascii=False)), encoding="utf-8")
    with_ctx = sum(1 for d in data if d["context"])
    print(f"{len(data)} candidats ({sum(d['scope'] == 'PRODUCTION' for d in data)} production, "
          f"{sum(pool[d['id']]['ours'] == 'REVIEW' for d in data)} où le modèle hésite), contexte récupéré pour {with_ctx}")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
