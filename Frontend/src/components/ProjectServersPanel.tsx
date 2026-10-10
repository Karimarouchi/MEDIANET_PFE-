import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ServerVulnPanel from "./ServerVulnPanel";
import {
  createLightweightClientServer,
  getServerNodes,
  linkClientServer,
  unlinkClientServer,
  type ProjectServerDto,
  type ServerNodeDto,
} from "../services/api";

const errMsg = (err: any, fallback: string): string => {
  const d = err?.response?.data;
  return (typeof d === "string" && d) || d?.message || fallback;
};

/** Servers (VPS) of a project: a project can run on several; each one feeds the project's attack map. */
const ProjectServersPanel: React.FC<{
  clientId: number;
  servers: ProjectServerDto[];
  canLinkExisting: boolean;
  onChange: () => void;
}> = ({ clientId, servers, canLinkExisting, onChange }) => {
  const [options, setOptions] = useState<ServerNodeDto[]>([]);
  const [pick, setPick] = useState("");
  const [draft, setDraft] = useState({ name: "", host: "", environment: "TEST" as "TEST" | "PROD" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [openVulnId, setOpenVulnId] = useState<number | null>(null);

  useEffect(() => {
    if (!canLinkExisting) return;
    getServerNodes()
      .then((res) => setOptions(res.data))
      .catch(() => setOptions([]));
  }, [canLinkExisting, servers.length]);

  const linkedIds = new Set(servers.map((s) => s.id));
  const available = options.filter((o) => !linkedIds.has(o.id));

  const run = async (action: () => Promise<unknown>, fallback: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
      onChange();
    } catch (err: any) {
      setError(errMsg(err, fallback));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-4">
      <div>
        <h2 className="text-sm font-bold font-headline uppercase tracking-widest text-outline flex items-center gap-2">
          <span className="material-symbols-outlined text-base">dns</span>
          Serveurs du projet ({servers.length})
        </h2>
        <p className="text-xs text-on-surface-variant mt-1 max-w-2xl">
          Les machines (VPS) sur lesquelles ce projet tourne. Un projet peut en avoir plusieurs ; elles apparaissent
          dans la cartographie d'attaque.
        </p>
      </div>

      {servers.length === 0 ? (
        <p className="text-sm text-outline py-6 text-center">Aucun serveur lié à ce projet.</p>
      ) : (
        <div className="space-y-3">
          {servers.map((s) => (
            <div key={s.id} className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container p-4">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="font-headline font-bold text-on-surface truncate">{s.name}</p>
                  <p className="text-xs font-mono text-outline truncate">{s.host}</p>
                </div>
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                    (s.environment ?? "").toUpperCase().startsWith("PROD")
                      ? "bg-error-container text-on-error-container"
                      : "bg-surface-variant text-on-surface-variant"
                  }`}
                >
                  {s.environment || "—"}
                </span>
              </div>
              <div className="flex items-center justify-between mt-3 text-[11px]">
                <div className="flex items-center gap-4">
                  <Link to={`/server-config/${s.id}`} className="text-primary hover:underline">
                    Ouvrir la configuration
                  </Link>
                  {canLinkExisting && (
                    <button
                      onClick={() => setOpenVulnId(openVulnId === s.id ? null : s.id)}
                      className="flex items-center gap-1 text-primary hover:underline font-semibold"
                    >
                      <span className="material-symbols-outlined text-[14px]">shield</span>
                      {openVulnId === s.id ? "Masquer les vulnérabilités" : "Vulnérabilités du serveur"}
                    </button>
                  )}
                </div>
                <button
                  disabled={busy}
                  onClick={() => run(() => unlinkClientServer(clientId, s.id), "Retrait impossible.")}
                  className="text-error/70 hover:text-error font-semibold disabled:opacity-40"
                >
                  Retirer
                </button>
              </div>
              {canLinkExisting && openVulnId === s.id && <ServerVulnPanel serverId={s.id} hasSsh={s.sshConfigured} />}
            </div>
          ))}
        </div>
      )}

      <div className="rounded-2xl border border-outline-variant/[0.15] bg-surface-container-low p-4 space-y-3">
        {canLinkExisting && (
          <div className="flex gap-2">
            <select
              value={pick}
              onChange={(e) => setPick(e.target.value)}
              className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface [color-scheme:dark]"
            >
              <option value="">Lier un serveur existant…</option>
              {available.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.name} ({o.host})
                </option>
              ))}
            </select>
            <button
              disabled={!pick || busy}
              onClick={() =>
                run(async () => {
                  await linkClientServer(clientId, Number(pick));
                  setPick("");
                }, "Liaison impossible (serveur déjà pris par un autre projet ?).")
              }
              className="px-3 rounded-xl border border-outline-variant/[0.2] text-xs font-semibold text-on-surface hover:border-primary/50 disabled:opacity-40"
            >
              Lier
            </button>
          </div>
        )}
        <div className="flex gap-2">
          <input
            value={draft.name}
            onChange={(e) => setDraft((d) => ({ ...d, name: e.target.value }))}
            placeholder="Nouveau serveur léger : nom"
            className="w-1/3 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
          />
          <input
            value={draft.host}
            onChange={(e) => setDraft((d) => ({ ...d, host: e.target.value }))}
            placeholder="IP ou domaine"
            className="flex-1 min-w-0 rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-3 py-2 text-xs text-on-surface placeholder:text-outline"
          />
          <select
            value={draft.environment}
            onChange={(e) => setDraft((d) => ({ ...d, environment: e.target.value as "TEST" | "PROD" }))}
            className="rounded-xl border border-outline-variant/[0.2] bg-surface-container-high px-2 py-2 text-xs text-on-surface [color-scheme:dark]"
          >
            <option value="TEST">Test</option>
            <option value="PROD">Production</option>
          </select>
          <button
            disabled={!draft.name.trim() || !draft.host.trim() || busy}
            onClick={() =>
              run(async () => {
                await createLightweightClientServer(clientId, {
                  name: draft.name.trim(),
                  host: draft.host.trim(),
                  environment: draft.environment,
                });
                setDraft((d) => ({ ...d, name: "", host: "" }));
              }, "Création du serveur impossible.")
            }
            className="px-3 rounded-xl border border-outline-variant/[0.2] text-xs font-semibold text-on-surface hover:border-primary/50 disabled:opacity-40"
          >
            Ajouter
          </button>
        </div>
        <p className="text-[10px] text-outline">
          Un serveur léger n'a pas d'accès SSH : il sert à la cartographie. Pour scanner sa configuration, complétez-le
          dans Server Config.
        </p>
        {error && <p className="text-xs text-error">{error}</p>}
      </div>
    </section>
  );
};

export default ProjectServersPanel;
