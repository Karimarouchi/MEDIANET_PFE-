import React, { useCallback, useEffect, useRef, useState } from "react";
import {
  getServerVulnScan,
  startServerVulnScan,
  type ServerPortFinding,
  type ServerVulnRef,
  type ServerVulnScanView,
} from "../services/api";

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: "bg-error-container text-on-error-container",
  HIGH: "bg-secondary-container text-on-secondary-container",
  MEDIUM: "bg-surface-variant text-on-surface-variant",
  LOW: "bg-tertiary-container text-on-tertiary-container",
};

export const EXPOSURE_LABEL: Record<string, { text: string; tone: string }> = {
  EXTERNAL: { text: "Ouvert sur internet", tone: "text-error" },
  UNKNOWN: { text: "Non vérifié depuis l'extérieur", tone: "text-outline" },
  FIREWALLED: { text: "Écoute, bloqué de l'extérieur", tone: "text-tertiary" },
  LOCAL_ONLY: { text: "Interne seulement", tone: "text-tertiary" },
};

const PACKAGES_PAGE = 15;

const VulnChips: React.FC<{ vulns: ServerVulnRef[]; max?: number }> = ({ vulns, max = 4 }) => {
  if (vulns.length === 0) return <span className="text-xs text-tertiary">Aucune CVE connue</span>;
  const shown = vulns.slice(0, max);
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {shown.map((v) => (
        <span
          key={v.id}
          title={`${v.id}${v.cvss != null ? ` — CVSS ${v.cvss}` : ""}${v.fixedVersion ? ` — corrigé en ${v.fixedVersion}` : ""}`}
          className={`px-1.5 py-0.5 rounded-md text-[10px] font-mono font-bold ${SEVERITY_BADGE[v.severity] ?? SEVERITY_BADGE.MEDIUM}`}
        >
          {v.id}
          {v.kev && " · EXPLOITÉE"}
          {!v.kev && v.exploit && " · exploit"}
        </span>
      ))}
      {vulns.length > max && <span className="text-[10px] text-outline">+{vulns.length - max}</span>}
    </div>
  );
};

/** Vulnerability analysis of one server: open ports (service, version, CVE) and vulnerable system packages. */
const ServerVulnPanel: React.FC<{ serverId: number; hasSsh: boolean }> = ({ serverId, hasSsh }) => {
  const [scan, setScan] = useState<ServerVulnScanView | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [external, setExternal] = useState(true);
  const [internal, setInternal] = useState(hasSsh);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [pkgLimit, setPkgLimit] = useState(PACKAGES_PAGE);
  const timer = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await getServerVulnScan(serverId);
      setScan(res.data === "" || res.status === 204 ? null : (res.data as ServerVulnScanView));
      setError(null);
    } catch {
      setError("Impossible de charger l'analyse.");
    } finally {
      setLoaded(true);
    }
  }, [serverId]);

  useEffect(() => {
    void load();
    return () => {
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, [load]);

  useEffect(() => {
    if (timer.current) window.clearTimeout(timer.current);
    if (scan?.status === "RUNNING") timer.current = window.setTimeout(() => void load(), 5000);
  }, [scan, load]);

  const start = async () => {
    setStarting(true);
    setError(null);
    try {
      const res = await startServerVulnScan(serverId, { external, internal: internal && hasSsh });
      setScan(res.data);
      setPkgLimit(PACKAGES_PAGE);
    } catch (err: any) {
      const d = err?.response?.data;
      setError((typeof d === "string" && d) || d?.message || "Impossible de lancer l'analyse.");
    } finally {
      setStarting(false);
    }
  };

  const running = scan?.status === "RUNNING";
  const report = scan?.report ?? null;

  const ports: ServerPortFinding[] = report
    ? [...report.ports].sort(
        (a, b) =>
          (a.exposure === "EXTERNAL" ? 0 : 1) - (b.exposure === "EXTERNAL" ? 0 : 1) ||
          b.vulns.length - a.vulns.length ||
          a.port - b.port,
      )
    : [];

  return (
    <div className="mt-3 border-t border-outline-variant/[0.1] pt-3 space-y-3">
      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-1.5 text-[11px] text-on-surface-variant cursor-pointer">
          <input type="checkbox" checked={external} onChange={(e) => setExternal(e.target.checked)} />
          Depuis l'extérieur (ports ouverts)
        </label>
        <label
          className={`flex items-center gap-1.5 text-[11px] ${hasSsh ? "text-on-surface-variant cursor-pointer" : "text-outline"}`}
          title={hasSsh ? "" : "Aucun accès SSH configuré pour ce serveur"}
        >
          <input
            type="checkbox"
            disabled={!hasSsh}
            checked={internal && hasSsh}
            onChange={(e) => setInternal(e.target.checked)}
          />
          Depuis l'intérieur (SSH : paquets système)
        </label>
        <button
          onClick={start}
          disabled={starting || running || (!external && !(internal && hasSsh))}
          className="ml-auto px-3 py-1.5 rounded-lg text-xs font-medium bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 disabled:opacity-50"
        >
          {running ? "Analyse en cours…" : scan ? "Relancer l'analyse" : "Analyser les vulnérabilités"}
        </button>
      </div>

      {error && <p className="text-xs text-error">{error}</p>}

      {!loaded && <p className="text-xs text-outline">Chargement…</p>}
      {loaded && !scan && (
        <p className="text-xs text-outline">
          Pas encore d'analyse. Elle liste les ports ouverts, les services et leurs vulnérabilités connues.
        </p>
      )}

      {running && (
        <p className="text-xs text-on-surface-variant flex items-center gap-2">
          <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>
          Analyse en cours (1 à 3 minutes). Vous pouvez quitter la page.
        </p>
      )}

      {scan?.status === "FAILED" && (
        <p className="text-xs text-error">L'analyse a échoué : {scan.errorMessage || "erreur inconnue"}</p>
      )}

      {report && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-center">
            {[
              { label: "Ports ouverts sur internet", value: report.summary.exposedPorts, bad: report.summary.exposedPorts > 0 },
              { label: "CVE critiques", value: report.summary.critical, bad: report.summary.critical > 0 },
              { label: "CVE élevées", value: report.summary.high, bad: false },
              { label: "Exploitées (KEV)", value: report.summary.kev, bad: report.summary.kev > 0 },
            ].map((k) => (
              <div key={k.label} className="rounded-xl border border-outline-variant/[0.15] px-2 py-2">
                <p className={`text-xl font-bold ${k.bad ? "text-error" : "text-on-surface"}`}>{k.value}</p>
                <p className="text-[10px] text-outline">{k.label}</p>
              </div>
            ))}
          </div>

          {report.warnings.map((w) => (
            <p key={w} className="text-[11px] text-amber-300">
              {w}
            </p>
          ))}

          <div>
            <p className="text-[10px] uppercase tracking-widest text-outline font-bold mb-2">
              Ports ({ports.length})
            </p>
            {ports.length === 0 ? (
              <p className="text-xs text-outline">Aucun port ouvert détecté.</p>
            ) : (
              <div className="rounded-xl border border-outline-variant/[0.15] overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="bg-surface-container-low/30 text-[10px] uppercase tracking-widest text-outline">
                      <th className="px-3 py-2">Port</th>
                      <th className="px-3 py-2">Service</th>
                      <th className="px-3 py-2">Exposition</th>
                      <th className="px-3 py-2">Vulnérabilités</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ports.map((p) => {
                      const exp = EXPOSURE_LABEL[p.exposure] ?? EXPOSURE_LABEL.UNKNOWN;
                      return (
                        <tr key={`${p.protocol}-${p.port}`} className="border-t border-outline-variant/[0.08] align-top">
                          <td className="px-3 py-2 font-mono text-on-surface">
                            {p.port}/{p.protocol}
                          </td>
                          <td className="px-3 py-2 text-on-surface-variant">
                            {[p.product || p.service, p.version].filter(Boolean).join(" ") || "—"}
                          </td>
                          <td className={`px-3 py-2 ${exp.tone}`}>{exp.text}</td>
                          <td className="px-3 py-2">
                            {p.exposure === "EXTERNAL" || p.vulns.length > 0 ? (
                              <VulnChips vulns={p.vulns} />
                            ) : (
                              <span className="text-outline">—</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-[10px] text-outline mt-1">
              Les CVE d'un port viennent de la version annoncée par le service : une distribution peut avoir corrigé la
              faille sans changer ce numéro (fausse alerte possible).
            </p>
          </div>

          {report.internalScan && (
            <div>
              <p className="text-[10px] uppercase tracking-widest text-outline font-bold mb-2">
                Paquets système vulnérables ({report.packages.length})
                {report.os && <span className="normal-case tracking-normal font-normal"> — {report.os}</span>}
              </p>
              {report.packages.length === 0 ? (
                <p className="text-xs text-tertiary">Aucun paquet système vulnérable connu.</p>
              ) : (
                <div className="rounded-xl border border-outline-variant/[0.15] overflow-hidden">
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="bg-surface-container-low/30 text-[10px] uppercase tracking-widest text-outline">
                        <th className="px-3 py-2">Paquet</th>
                        <th className="px-3 py-2">Gravité</th>
                        <th className="px-3 py-2">Vulnérabilités</th>
                        <th className="px-3 py-2">Que faire</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.packages.slice(0, pkgLimit).map((p) => (
                        <tr key={`${p.name}@${p.version}`} className="border-t border-outline-variant/[0.08] align-top">
                          <td className="px-3 py-2">
                            <span className="text-on-surface">{p.name}</span>
                            <span className="block font-mono text-[10px] text-outline">{p.version}</span>
                          </td>
                          <td className="px-3 py-2">
                            <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${SEVERITY_BADGE[p.severity] ?? SEVERITY_BADGE.MEDIUM}`}>
                              {p.severity}
                            </span>
                          </td>
                          <td className="px-3 py-2">
                            <VulnChips vulns={p.vulns} max={3} />
                          </td>
                          <td className="px-3 py-2">
                            {p.fixedVersion ? (
                              <span className="text-tertiary font-bold">Mettre à jour vers {p.fixedVersion}</span>
                            ) : (
                              <span className="text-outline">Pas de correctif publié</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {report.packages.length > pkgLimit && (
                    <div className="flex justify-center py-2 border-t border-outline-variant/[0.1]">
                      <button
                        className="px-3 py-1.5 rounded-lg text-xs font-bold border border-primary/30 text-primary hover:bg-primary/10"
                        onClick={() => setPkgLimit((l) => l + PACKAGES_PAGE)}
                      >
                        Afficher {Math.min(PACKAGES_PAGE, report.packages.length - pkgLimit)} de plus (
                        {report.packages.length - pkgLimit} restants)
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          <p className="text-[10px] text-outline">
            Analyse du {scan?.finishedAt ? new Date(scan.finishedAt).toLocaleString("fr-FR") : "—"}.
          </p>
        </div>
      )}
    </div>
  );
};

export default ServerVulnPanel;
