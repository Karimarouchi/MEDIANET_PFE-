import React, { useEffect, useMemo, useRef, useState } from "react";
import {
  SOURCE_FILTERS,
  SOURCE_STYLE,
  computeProgress,
  formatIdle,
  type LogEntry,
  type Source,
} from "../utils/scanLog";

type Props = {
  entries: LogEntry[];
  title: string;
  /** the backend sent the completion marker: every model has finished, the results open right after */
  complete: boolean;
};

const Counter: React.FC<{ icon: string; label: string; value: number | null; tone?: string }> = ({ icon, label, value, tone }) => (
  <div className="rounded-xl border border-outline-variant/[0.15] bg-surface-container px-3 py-2">
    <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-widest text-outline">
      <span className="material-symbols-outlined text-sm">{icon}</span>
      {label}
    </div>
    <p className={`text-xl font-bold mt-0.5 ${tone ?? "text-on-surface"}`}>{value ?? "…"}</p>
  </div>
);

/** Live view of a running scan: pipeline with progress, colour-coded log, live counters and filters. */
const ScanLiveLog: React.FC<Props> = ({ entries, title, complete }) => {
  const [filter, setFilter] = useState<Source | "all">("all");
  const [query, setQuery] = useState("");
  const [follow, setFollow] = useState(true);
  const [now, setNow] = useState(Date.now());
  const box = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 5000);
    return () => window.clearInterval(t);
  }, []);

  const progress = useMemo(() => computeProgress(entries, complete, now), [entries, complete, now]);
  const idle = complete ? null : formatIdle(progress.lastActivityMs);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return entries.filter((e) => (filter === "all" || e.source === filter) && (!q || e.text.toLowerCase().includes(q)));
  }, [entries, filter, query]);

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [visible, follow]);

  const onScroll = () => {
    const el = box.current;
    if (!el) return;
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
  };

  const download = () => {
    const text = entries.map((e) => `${e.time} ${e.tag} ${e.text}`.replace(/\s+/g, " ")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = `${title}-scan.log`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <div className="glass-panel rounded-2xl border border-primary/[0.15] overflow-hidden shadow-2xl mb-6">
      {/* header + progress */}
      <div className="bg-surface-container-highest/50 px-6 py-4 border-b border-outline-variant/[0.1] space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-[10px] font-mono tracking-widest text-outline uppercase">Scan // {title}</span>
          <span className={`text-[11px] font-mono flex items-center gap-1.5 ${complete ? "text-emerald-300" : "text-primary"}`}>
            <span className={`w-1.5 h-1.5 rounded-full ${complete ? "bg-emerald-400" : "bg-primary animate-pulse"}`} />
            {complete ? "Terminé — ouverture des résultats…" : `En cours — ${progress.percent} %`}
          </span>
        </div>
        <div
          className="h-1.5 rounded-full bg-surface-container-high overflow-hidden"
          role="progressbar"
          aria-valuenow={progress.percent}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div
            className={`h-full rounded-full transition-all duration-500 ${complete ? "bg-emerald-400" : "bg-primary"}`}
            style={{ width: `${progress.percent}%` }}
          />
        </div>
        <ol className="flex flex-wrap gap-2">
          {progress.stages.map(({ def, state }) => (
            <li
              key={def.id}
              data-state={state}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] ${
                state === "done"
                  ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-300"
                  : state === "active"
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-outline-variant/[0.2] text-outline"
              }`}
            >
              <span className={`material-symbols-outlined text-sm ${state === "active" ? "animate-pulse" : ""}`}>
                {state === "done" ? "check_circle" : def.icon}
              </span>
              {def.label}
            </li>
          ))}
        </ol>
      </div>

      {/* counters */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 px-6 py-3 border-b border-outline-variant/[0.1]">
        <Counter icon="bug_report" label="CVE trouvées" value={progress.counters.cves} tone="text-cyan-300" />
        <Counter icon="key" label="Secrets" value={progress.counters.secrets} tone="text-rose-300" />
        <Counter icon="inventory_2" label="Paquets SBOM" value={progress.counters.packages} tone="text-sky-300" />
        <Counter icon="gpp_maybe" label="Paquets suspects" value={progress.counters.suspects} tone="text-pink-300" />
      </div>

      {/* filters */}
      <div className="flex flex-wrap items-center gap-2 px-6 py-3 border-b border-outline-variant/[0.1]">
        {SOURCE_FILTERS.map((f) => (
          <button
            key={f.key}
            onClick={() => setFilter(f.key)}
            className={`px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all ${
              filter === f.key ? "bg-primary/10 border-primary/40 text-primary" : "border-outline-variant/[0.2] text-outline hover:border-primary/30"
            }`}
          >
            {f.key !== "all" && <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${SOURCE_STYLE[f.key as Source].dot}`} />}
            {f.label}
          </button>
        ))}
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Rechercher dans le journal…"
          className="ml-auto min-w-[180px] rounded-lg border border-outline-variant/[0.2] bg-surface-container px-3 py-1 text-xs text-on-surface placeholder-outline"
        />
        <button
          onClick={download}
          className="px-2.5 py-1 rounded-lg text-[11px] text-outline border border-outline-variant/[0.2] hover:text-on-surface"
          title="Télécharger le journal"
        >
          <span className="material-symbols-outlined text-sm align-middle">download</span>
        </button>
      </div>

      {/* log */}
      <div className="relative">
        <div ref={box} onScroll={onScroll} className="p-4 font-mono text-xs leading-relaxed h-[420px] overflow-y-auto bg-surface-container-lowest/80 custom-scrollbar">
          {entries.length === 0 && (
            <div className="flex items-center gap-3 text-outline opacity-60">
              <span className="material-symbols-outlined text-base animate-spin">progress_activity</span>
              <span>Connexion au scan…</span>
            </div>
          )}
          {visible.map((e, i) => {
            const st = SOURCE_STYLE[e.source];
            return (
              <div key={i} className={`flex gap-3 mb-1 ${e.source === "error" ? "bg-red-500/10 rounded" : ""}`}>
                <span className="text-outline opacity-40 shrink-0">{e.time}</span>
                <span className={`shrink-0 w-[78px] text-center rounded border text-[9px] font-bold py-0.5 h-fit ${st.badge}`}>{st.label}</span>
                <span className={`${e.source === "other" ? "text-on-surface-variant" : st.text} break-all`}>{e.text}</span>
              </div>
            );
          })}
        </div>
        {!follow && (
          <button
            onClick={() => setFollow(true)}
            className="absolute right-4 bottom-3 rounded-lg bg-primary/20 border border-primary/40 px-3 py-1 text-[11px] text-primary"
          >
            Suivre le direct ↓
          </button>
        )}
      </div>
      {idle && (
        <div className="flex items-center gap-2 border-t border-amber-400/20 bg-amber-500/10 px-6 py-2 text-[11px] text-amber-200">
          <span className="material-symbols-outlined text-sm">hourglass_top</span>
          Aucune sortie depuis {idle} : l'étape en cours est longue, le scan n'est pas bloqué tant que le conteneur tourne.
        </div>
      )}
    </div>
  );
};

export default ScanLiveLog;
