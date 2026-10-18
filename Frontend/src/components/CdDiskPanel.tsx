import React, { useEffect, useState } from "react";
import { cleanDeploymentDisk, getDeploymentDisk, measureDeploymentDisk, type DiskReport } from "../services/api";
import { formatBytes } from "../utils/cd";

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

/** Disk of the deployment server: measured after each deploy; cleaning only after the user confirms what goes. */
const CdDiskPanel: React.FC<{ deploymentId: number; serverName: string }> = ({ deploymentId, serverName }) => {
  const [report, setReport] = useState<DiskReport | null>(null);
  const [busy, setBusy] = useState<"measure" | "clean" | null>(null);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getDeploymentDisk(deploymentId).then((r) => setReport(r.data || null)).catch(() => setReport(null));
  }, [deploymentId]);

  const measure = async () => {
    setBusy("measure");
    setError(null);
    try {
      setReport((await measureDeploymentDisk(deploymentId)).data);
    } catch (e) {
      setError(apiMessage(e, "Mesure impossible."));
    } finally {
      setBusy(null);
    }
  };

  const clean = async () => {
    setBusy("clean");
    setError(null);
    try {
      setReport((await cleanDeploymentDisk(deploymentId)).data);
      setConfirm(false);
    } catch (e) {
      setError(apiMessage(e, "Nettoyage impossible."));
    } finally {
      setBusy(null);
    }
  };

  const pct = report?.usedPercent ?? 0;
  const bar = pct >= 85 ? "bg-error" : pct >= 70 ? "bg-amber-400" : "bg-tertiary";

  return (
    <div className="mt-3 rounded-lg border border-outline-variant/[0.15] bg-black/20 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[11px] font-semibold text-on-surface">Espace disque · {serverName}</span>
        <button type="button" onClick={measure} disabled={busy !== null} className="text-[11px] font-semibold text-primary hover:underline disabled:opacity-60">
          {busy === "measure" ? "Mesure…" : report ? "Mesurer à nouveau" : "Mesurer"}
        </button>
      </div>

      {!report ? (
        <p className="mt-1 text-[11px] text-outline">Pas encore mesuré : la mesure se fait après chaque déploiement réussi, ou avec « Mesurer ».</p>
      ) : (
        <>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-surface-variant">
            <div className={`h-full ${bar}`} style={{ width: `${Math.min(100, pct)}%` }} />
          </div>
          <p className={`mt-1 text-[11px] ${report.alert ? "text-error" : "text-on-surface-variant"}`}>
            {pct} % utilisés · {formatBytes(report.diskFree)} libres sur {formatBytes(report.diskTotal)}
            {report.alert ? " · au-delà de 85 %, les déploiements risquent d'échouer" : ""}
          </p>
          <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[11px] text-on-surface-variant">
              Récupérable : <span className="font-semibold text-on-surface">{formatBytes(report.reclaimableBytes)}</span> ({report.oldImages} ancienne(s) image(s) · {formatBytes(report.oldImagesBytes)},
              cache de build au-delà de 2 Go · {formatBytes(report.buildCacheBytes)})
            </span>
            {report.reclaimableBytes > 0 && !confirm && (
              <button type="button" onClick={() => setConfirm(true)} disabled={busy !== null}
                className="rounded-lg border border-amber-500/40 px-3 py-1 text-[11px] font-semibold text-amber-300 hover:bg-amber-500/10">
                Nettoyer…
              </button>
            )}
          </div>
          {report.lastCleanupAt && (
            <p className="mt-1 text-[10px] text-outline">
              Dernier nettoyage : {new Date(report.lastCleanupAt).toLocaleString("fr-FR")} · {report.lastCleanupFreed} libérés
            </p>
          )}
          <p className="mt-1 text-[10px] text-outline">Mesuré le {new Date(report.measuredAt).toLocaleString("fr-FR")}</p>
        </>
      )}

      {confirm && report && (
        <div role="alertdialog" className="mt-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-[11px] text-on-surface">
          <p className="font-semibold">Supprimer environ {formatBytes(report.reclaimableBytes)} sur {serverName} ?</p>
          <ul className="mt-1 space-y-0.5 text-on-surface-variant">
            {report.images.slice(0, 8).map((i) => (
              <li key={i.id} className="font-mono">image {i.id} · {i.age} · {formatBytes(i.bytes)}</li>
            ))}
            {report.images.length > 8 && <li>… et {report.images.length - 8} autre(s)</li>}
            {report.buildCacheBytes > 0 && <li>cache de build au-delà de 2 Go · {formatBytes(report.buildCacheBytes)}</li>}
          </ul>
          <p className="mt-2 text-on-surface-variant">
            Seules les images sans nom qu'aucun conteneur n'utilise sont supprimées. L'application en cours, ses conteneurs et ses
            volumes (les données) ne sont jamais touchés. 2 Go de cache sont gardés pour que le prochain build reste rapide.
          </p>
          <div className="mt-2 flex gap-2">
            <button type="button" onClick={clean} disabled={busy !== null}
              className="rounded-lg border border-amber-500/40 bg-amber-500/20 px-3 py-1 font-semibold text-amber-200 disabled:opacity-60">
              {busy === "clean" ? "Nettoyage…" : "Oui, nettoyer"}
            </button>
            <button type="button" onClick={() => setConfirm(false)} className="px-3 py-1 text-on-surface-variant">Annuler</button>
          </div>
        </div>
      )}
      {error && <p className="mt-2 text-[11px] text-error">{error}</p>}
    </div>
  );
};

export default CdDiskPanel;
