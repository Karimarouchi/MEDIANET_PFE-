import React, { useEffect, useState } from "react";
import {
  approveDeployRun,
  createServerDeployment,
  getClientServers,
  getRepoDeployments,
  refuseDeployRun,
  setDeploymentAutoDeploy,
  updateServerDeployment,
  type CdRun,
  type CdTarget,
  type ProjectServerDto,
} from "../services/api";
import { deployStrategyOptions, validateDeployFields } from "../pages/serverConfigShared";
import { formatBytes, restoreCommand } from "../utils/cd";
import CdDiskPanel from "./CdDiskPanel";
import CdCheckPanel from "./CdCheckPanel";

const RUN_LABEL: Record<CdRun["status"], { text: string; className: string }> = {
  SUCCESS: { text: "Réussi", className: "bg-tertiary/15 text-tertiary" },
  RUNNING: { text: "En cours", className: "bg-primary/15 text-primary" },
  FAILED: { text: "Échec", className: "bg-error/15 text-error" },
  ROLLED_BACK: { text: "Version précédente remise", className: "bg-amber-500/15 text-amber-300" },
  BLOCKED: { text: "Bloqué", className: "bg-amber-500/15 text-amber-300" },
  BACKUP_FAILED: { text: "Sauvegarde impossible, rien déployé", className: "bg-error/15 text-error" },
  PENDING_APPROVAL: { text: "En attente d'accord", className: "bg-primary/15 text-primary" },
  REFUSED: { text: "Refusé", className: "bg-surface-variant text-on-surface-variant" },
  SUPERSEDED: { text: "Remplacé par un plus récent", className: "bg-surface-variant text-on-surface-variant" },
};

const field = "w-full rounded-xl border border-outline-variant/30 bg-surface-container-high px-3 py-2 text-sm text-on-surface";

function when(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("fr-FR", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
}

function apiMessage(err: unknown, fallback: string): string {
  const e = err as { response?: { data?: { message?: string; error?: string } } };
  return e?.response?.data?.message || e?.response?.data?.error || fallback;
}

type Draft = {
  serverId: number | "";
  path: string;
  branch: string;
  strategy: string;
  healthUrl: string;
  automatic: boolean;
  backupEnabled: boolean;
  backupService: string;
  approvalRequired: boolean;
};

const emptyDraft = (branch: string): Draft => ({
  serverId: "", path: "", branch, strategy: "DOCKER_COMPOSE", healthUrl: "", automatic: true,
  backupEnabled: false, backupService: "db", approvalRequired: false,
});

/** Deployment settings of one repository: created after the first manual install, editable afterwards. */
const CdForm: React.FC<{
  clientId: number;
  repoId: number;
  initial: Draft;
  existing: CdTarget | null;
  onSaved: () => void;
  onCancel: () => void;
}> = ({ clientId, repoId, initial, existing, onSaved, onCancel }) => {
  const [d, setD] = useState<Draft>(initial);
  const [servers, setServers] = useState<ProjectServerDto[] | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getClientServers(clientId).then((r) => setServers(r.data)).catch(() => setServers([]));
  }, [clientId]);

  const set = (patch: Partial<Draft>) => setD((cur) => ({ ...cur, ...patch }));
  const sshServers = (servers ?? []).filter((s) => s.sshConfigured);
  const compose = d.strategy !== "STATIC_NGINX";

  const save = async () => {
    setError(null);
    if (d.serverId === "") return setError("Choisissez le serveur.");
    const errors = validateDeployFields(d.path, "", d.branch);
    if (!d.path.trim()) errors.unshift("Indiquez le dossier du code sur le serveur.");
    if (compose && d.backupEnabled && !/^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/.test(d.backupService.trim())) {
      errors.unshift("Indiquez le service de la base dans docker-compose.yml (ex. db).");
    }
    if (errors.length) return setError(errors[0]);
    setSaving(true);
    try {
      const payload = {
        deployPath: d.path.trim(), linkedRepositoryId: repoId, deployBranch: d.branch.trim() || "main", deployStrategy: d.strategy,
        healthUrl: d.healthUrl.trim(), backupEnabled: compose && d.backupEnabled, backupService: d.backupService.trim(),
        approvalRequired: d.approvalRequired,
      };
      const serverId = Number(d.serverId);
      const saved = existing && existing.serverId === serverId
        ? (await updateServerDeployment(serverId, existing.deploymentId, payload)).data
        : (await createServerDeployment(serverId, payload)).data;
      if (Boolean(saved.autoDeployEnabled) !== d.automatic) await setDeploymentAutoDeploy(serverId, saved.id, d.automatic);
      onSaved();
    } catch (e) {
      setError(apiMessage(e, "Enregistrement refusé."));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mt-3 space-y-3 rounded-xl border border-primary/30 bg-primary/5 p-4 text-sm">
      <p className="text-[10px] font-bold uppercase tracking-widest text-primary">
        {existing ? "Modifier le déploiement" : "Configurer le déploiement continu"}
      </p>
      <p className="text-xs text-on-surface-variant">
        Faites d'abord la première installation à la main sur le serveur : <span className="font-mono">git clone</span> dans le dossier, le fichier
        <span className="font-mono"> .env</span>, puis <span className="font-mono">docker compose up -d --build</span>. Ensuite, chaque pipeline vert met
        à jour ce dossier tout seul.
      </p>
      <div className="grid gap-3 md:grid-cols-2">
        <label className="space-y-1">
          <span className="text-[11px] text-outline">Serveur</span>
          <select className={field} value={d.serverId} disabled={existing != null}
            title={existing ? "Pour un autre serveur, ajoutez un déploiement (+ Autre serveur)" : undefined}
            onChange={(e) => set({ serverId: e.target.value === "" ? "" : Number(e.target.value) })}>
            <option value="">{servers === null ? "Chargement…" : "Choisir un serveur"}</option>
            {sshServers.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.host})</option>)}
          </select>
          {servers && sshServers.length === 0 && (
            <span className="block text-[11px] text-amber-300">Aucun serveur avec accès SSH : ajoutez-en un dans l'onglet Serveurs.</span>
          )}
        </label>
        <label className="space-y-1">
          <span className="text-[11px] text-outline">Dossier du code sur le serveur (celui qui contient docker-compose.yml)</span>
          <input className={`${field} font-mono`} value={d.path} onChange={(e) => set({ path: e.target.value })} placeholder="/opt/antigone/app" spellCheck={false} />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] text-outline">Branche déployée</span>
          <input className={`${field} font-mono`} value={d.branch} onChange={(e) => set({ branch: e.target.value })} placeholder="main" spellCheck={false} />
        </label>
        <label className="space-y-1">
          <span className="text-[11px] text-outline">Mise à jour et redémarrage</span>
          <select className={field} value={d.strategy} onChange={(e) => set({ strategy: e.target.value })}>
            {deployStrategyOptions.map((o) => <option key={o.value} value={o.value}>{o.label} — {o.helper}</option>)}
          </select>
        </label>
        <label className="space-y-1 md:col-span-2">
          <span className="text-[11px] text-outline">Adresse de santé (optionnel), appelée depuis le serveur après le redémarrage</span>
          <input className={`${field} font-mono`} value={d.healthUrl} onChange={(e) => set({ healthUrl: e.target.value })} placeholder="http://localhost:18081/api/health" spellCheck={false} />
          <span className="block text-[11px] text-outline">Vide : tous les conteneurs doivent rester démarrés. Si la vérification échoue, la version précédente est remise.</span>
        </label>
      </div>

      {compose && (
        <div className="rounded-lg border border-outline-variant/[0.15] p-3 space-y-2">
          <label className="flex items-center gap-2 text-sm text-on-surface">
            <input type="checkbox" checked={d.backupEnabled} onChange={(e) => set({ backupEnabled: e.target.checked })} />
            Sauvegarder la base avant chaque déploiement (les 5 dernières sont gardées)
          </label>
          {d.backupEnabled && (
            <label className="block space-y-1 pl-6">
              <span className="text-[11px] text-outline">Service PostgreSQL dans docker-compose.yml</span>
              <input className={`${field} font-mono md:w-64`} value={d.backupService} onChange={(e) => set({ backupService: e.target.value })} placeholder="db" spellCheck={false} />
              <span className="block text-[11px] text-outline">
                Le nom de la base et l'utilisateur sont lus dans le conteneur ($POSTGRES_DB, $POSTGRES_USER) : aucun mot de passe n'est stocké par
                Vulnix. Si la sauvegarde échoue, rien n'est déployé.
              </span>
            </label>
          )}
        </div>
      )}

      <div className="rounded-lg border border-outline-variant/[0.15] p-3 space-y-2">
        <label className="flex items-center gap-2 text-sm text-on-surface">
          <input type="checkbox" checked={d.automatic} onChange={(e) => set({ automatic: e.target.checked })} />
          Déployer automatiquement chaque pipeline vert (tests, lint, build, barrière Vulnix)
        </label>
        {d.automatic && (
          <label className="flex items-center gap-2 pl-6 text-sm text-on-surface">
            <input type="checkbox" checked={d.approvalRequired} onChange={(e) => set({ approvalRequired: e.target.checked })} />
            Demander mon accord avant de déployer (notification + bouton Déployer / Refuser)
          </label>
        )}
      </div>

      <div className="rounded-lg bg-black/30 p-3 font-mono text-[11px] leading-relaxed text-slate-300">
        {d.automatic && d.approvalRequired && <>attente de l'accord (bouton Déployer)<br /></>}
        cd {d.path || "<dossier>"}<br />
        git fetch origin {d.branch || "main"}<br />
        {compose && d.backupEnabled && <>pg_dump de « {d.backupService || "db"} » → .vulnix-backups/ (vérifié, sinon arrêt)<br /></>}
        git reset --hard &lt;commit du pipeline vert&gt;<br />
        {compose ? "docker compose up -d --build" : "nginx -t && systemctl reload nginx"}<br />
        vérification {d.healthUrl ? d.healthUrl : "des conteneurs"} → sinon retour à la version précédente<br />
        notification (cloche + e-mail)
      </div>
      {error && <p className="text-xs text-error">{error}</p>}
      <div className="flex gap-2">
        <button type="button" onClick={save} disabled={saving}
          className="rounded-xl border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary hover:bg-primary/20 disabled:opacity-60">
          {saving ? "Enregistrement…" : "Enregistrer"}
        </button>
        <button type="button" onClick={onCancel} className="rounded-xl px-4 py-2 text-sm text-on-surface-variant hover:text-on-surface">Annuler</button>
      </div>
    </div>
  );
};

/** Green pipeline waiting for a decision. */
const ApprovalBox: React.FC<{ run: CdRun; target: CdTarget; onDone: () => void }> = ({ run, target, onDone }) => {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const act = async (fn: (id: number) => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn(run.id);
      onDone();
    } catch (e) {
      setError(apiMessage(e, "Action refusée."));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div role="alert" className="mt-2 rounded-lg border border-primary/40 bg-primary/10 p-3">
      <p className="text-xs font-semibold text-on-surface">
        Pipeline #{run.pipelineNumber} vert : le commit <span className="font-mono">{run.commitSha?.slice(0, 8)}</span> attend votre accord.
      </p>
      <p className="mt-0.5 text-[11px] text-on-surface-variant">
        Il partira sur {target.serverName} ({target.path}){target.backupEnabled ? " après une sauvegarde de la base" : ""}. Demandé le {when(run.startedAt)}.
      </p>
      <div className="mt-2 flex gap-2">
        <button type="button" disabled={busy} onClick={() => act(approveDeployRun)}
          className="rounded-lg border border-tertiary/40 bg-tertiary/15 px-3 py-1 text-xs font-semibold text-tertiary disabled:opacity-60">
          Déployer
        </button>
        <button type="button" disabled={busy} onClick={() => act(refuseDeployRun)}
          className="rounded-lg px-3 py-1 text-xs text-on-surface-variant hover:text-on-surface">
          Refuser
        </button>
      </div>
      {error && <p className="mt-1 text-[11px] text-error">{error}</p>}
    </div>
  );
};

const BackupList: React.FC<{ target: CdTarget }> = ({ target }) => {
  const [shown, setShown] = useState<number | null>(null);
  const [copied, setCopied] = useState(false);
  if (!target.backupEnabled && target.backups.length === 0) return null;
  return (
    <details className="mt-2 text-[11px]">
      <summary className="cursor-pointer text-on-surface-variant">
        Sauvegardes de la base ({target.backups.length}{target.backupEnabled ? `, service ${target.backupService}` : ", désactivées"})
      </summary>
      {target.backups.length === 0 ? (
        <p className="mt-1 text-outline">Aucune encore : la première sera faite au prochain déploiement.</p>
      ) : (
        <ul className="mt-1 space-y-1">
          {target.backups.map((b) => (
            <li key={b.id} className="rounded bg-black/20 px-2 py-1">
              <span className="font-mono text-on-surface">{b.backupFile}</span>
              <span className="text-outline"> · {formatBytes(b.backupBytes)} · avant {b.commitSha?.slice(0, 8)} · {when(b.startedAt)}</span>
              <button type="button" onClick={() => { setShown(shown === b.id ? null : b.id); setCopied(false); }}
                className="ml-2 font-semibold text-primary hover:underline">
                Restaurer…
              </button>
              {shown === b.id && target.path && (
                <div className="mt-1">
                  <p className="text-amber-300">
                    À lancer à la main sur le serveur. La base actuelle sera remplacée par cette sauvegarde : les autres services sont arrêtés
                    pendant la restauration, puis redémarrés.
                  </p>
                  <pre className="mt-1 overflow-auto rounded bg-black/40 p-2 font-mono text-slate-300">
                    {restoreCommand(target.path, target.backupService || "db", b.backupFile!)}
                  </pre>
                  <button type="button" className="mt-1 text-primary hover:underline" onClick={() => {
                    navigator.clipboard?.writeText(restoreCommand(target.path!, target.backupService || "db", b.backupFile!)).then(() => setCopied(true)).catch(() => undefined);
                  }}>
                    {copied ? "Copié" : "Copier la commande"}
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </details>
  );
};

/** Where this repository is deployed, what runs there, and the form to set it up or change it. */
const CdTargetsPanel: React.FC<{ clientId: number; repoId: number; branch: string; refreshKey: number }> = ({ clientId, repoId, branch, refreshKey }) => {
  const [targets, setTargets] = useState<CdTarget[] | null>(null);
  const [editing, setEditing] = useState<CdTarget | "new" | null>(null);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    getRepoDeployments(repoId).then((r) => setTargets(r.data)).catch(() => setTargets([]));
  }, [repoId, refreshKey, reload]);

  // While a deploy runs (after "Déployer"), refresh until it is over.
  const running = (targets ?? []).some((t) => t.last?.status === "RUNNING");
  useEffect(() => {
    if (!running) return;
    const t = window.setInterval(() => setReload((n) => n + 1), 5000);
    return () => window.clearInterval(t);
  }, [running]);

  if (!targets) return null;
  const onSaved = () => {
    setEditing(null);
    setReload((n) => n + 1);
  };
  const draftOf = (t: CdTarget): Draft => ({
    serverId: t.serverId, path: t.path ?? "", branch: t.branch ?? "main", strategy: t.strategy || "DOCKER_COMPOSE",
    healthUrl: t.healthUrl ?? "", automatic: t.automatic, backupEnabled: t.backupEnabled, backupService: t.backupService ?? "db",
    approvalRequired: t.approvalRequired,
  });

  return (
    <div className="mt-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-[10px] uppercase tracking-widest text-outline">Déploiement continu</p>
        {targets.length > 0 && editing === null && (
          <button type="button" onClick={() => setEditing("new")} className="text-xs font-semibold text-primary hover:underline">
            + Autre serveur
          </button>
        )}
      </div>

      {targets.length === 0 && editing === null && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-outline-variant/[0.15] bg-surface-container px-4 py-3 text-xs text-on-surface-variant">
          <span>
            <span className="font-semibold text-on-surface">Non configuré.</span> Après la première installation à la main sur le serveur,
            indiquez le dossier du code : chaque pipeline vert le mettra à jour.
          </span>
          <button type="button" onClick={() => setEditing("new")}
            className="rounded-xl border border-primary/30 bg-primary/10 px-3 py-1.5 text-xs font-semibold text-primary hover:bg-primary/20">
            Configurer le déploiement
          </button>
        </div>
      )}

      {editing === "new" && (
        <CdForm clientId={clientId} repoId={repoId} initial={emptyDraft(branch)} existing={null} onSaved={onSaved} onCancel={() => setEditing(null)} />
      )}

      {targets.map((t) => {
        if (editing !== null && editing !== "new" && editing.deploymentId === t.deploymentId) {
          return <CdForm key={t.deploymentId} clientId={clientId} repoId={repoId} initial={draftOf(t)} existing={t} onSaved={onSaved} onCancel={() => setEditing(null)} />;
        }
        const last = t.last;
        const label = last ? RUN_LABEL[last.status] : null;
        const problem = last && (last.status === "FAILED" || last.status === "ROLLED_BACK" || last.status === "BACKUP_FAILED");
        return (
          <div key={t.deploymentId} className="rounded-xl border border-outline-variant/[0.15] bg-surface-container px-4 py-3 text-xs">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <span className="font-headline text-sm font-semibold text-on-surface">{t.serverName}</span>
              <span className="font-mono text-outline">{t.host}:{t.path}</span>
              <span className="text-outline">branche {t.branch || "main"}</span>
              <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${t.automatic ? "bg-tertiary/15 text-tertiary" : "bg-surface-variant text-on-surface-variant"}`}>
                {t.automatic ? (t.approvalRequired ? "Automatique avec accord" : "Automatique après pipeline vert") : "Manuel"}
              </span>
              {t.backupEnabled && <span className="rounded-full bg-surface-variant px-2 py-0.5 text-[10px] font-bold text-on-surface-variant">Sauvegarde · {t.backupService}</span>}
              <button type="button" onClick={() => setEditing(t)} className="ml-auto text-xs font-semibold text-primary hover:underline">Modifier</button>
            </div>
            {t.pending && <ApprovalBox run={t.pending} target={t} onDone={() => setReload((n) => n + 1)} />}
            <div className="mt-2 flex flex-wrap gap-x-6 gap-y-1 text-on-surface-variant">
              <span>
                En production :{" "}
                {t.inProduction ? (
                  <span className="text-on-surface">
                    <span className="font-mono">{t.inProduction.commitSha?.slice(0, 8) ?? "?"}</span>
                    {t.inProduction.pipelineNumber ? ` (pipeline #${t.inProduction.pipelineNumber})` : ""} · {when(t.inProduction.finishedAt)}
                  </span>
                ) : (
                  <span className="text-outline">installation à la main (aucun déploiement Vulnix réussi encore)</span>
                )}
              </span>
              {last && label && (
                <span>
                  Dernier : <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${label.className}`}>{label.text}</span>{" "}
                  {last.trigger === "CI" && last.pipelineNumber ? `pipeline #${last.pipelineNumber}` : last.trigger.toLowerCase()} · {when(last.startedAt)}
                  {last.decidedBy ? ` · ${last.status === "REFUSED" ? "refusé" : "accordé"} par ${last.decidedBy}` : ""}
                </span>
              )}
              {t.healthUrl && <span>Santé : <span className="font-mono">{t.healthUrl}</span></span>}
            </div>
            {problem && last.logTail && (
              <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-black/40 p-2 font-mono text-[11px] leading-relaxed text-slate-300 whitespace-pre-wrap">
                {last.logTail}
              </pre>
            )}
            <CdCheckPanel deploymentId={t.deploymentId} />
            <BackupList target={t} />
            {t.strategy !== "STATIC_NGINX" && <CdDiskPanel deploymentId={t.deploymentId} serverName={t.serverName} />}
          </div>
        );
      })}
    </div>
  );
};

export default CdTargetsPanel;
