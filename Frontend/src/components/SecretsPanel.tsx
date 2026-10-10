import React, { useState } from "react";
import type { SecretDto } from "../services/api";
import {
  VERDICT_LABEL,
  effectiveVerdict,
  formatProba,
  groupSecrets,
  verdictBadge,
} from "../utils/secretView";

type Props = {
  secrets: SecretDto[];
  loading: boolean;
  triaging?: boolean;
  onTriage: () => void;
  onVerdict: (secretId: number, verdict: "REAL" | "FALSE_POSITIVE" | null) => void;
};

const COLS = ["Verdict", "Type", "Fichier", "Ligne", "Secret"];

const SecretRow: React.FC<{
  s: SecretDto;
  open: boolean;
  onToggle: () => void;
  onVerdict: Props["onVerdict"];
}> = ({ s, open, onToggle, onVerdict }) => {
  const v = effectiveVerdict(s);
  const overridden = !!s.analystVerdict;
  return (
    <>
      <tr
        className={`border-b border-outline-variant/[0.07] cursor-pointer transition-all hover:bg-primary/5 ${open ? "bg-primary/[0.04]" : ""}`}
        onClick={onToggle}
      >
        <td className="px-4 py-3 whitespace-nowrap">
          <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold ${verdictBadge(v)}`}>
            {VERDICT_LABEL[v]}
          </span>
          {!overridden && s.mlProba != null && (
            <span className="ml-2 text-[10px] text-outline">{formatProba(s.mlProba)}</span>
          )}
          {overridden && <span className="ml-2 text-[10px] text-primary">décidé par vous</span>}
        </td>
        <td className="px-4 py-3 text-sm text-on-surface font-headline">
          {(s.ruleId || "—").replace("credsweeper:", "")}
          {s.detectors && s.detectors.length > 1 && (
            <span
              className="ml-2 px-1.5 py-0.5 rounded-md text-[9px] font-bold bg-primary/15 text-primary"
              title="Signalé par gitleaks et par CredSweeper"
            >
              2 détecteurs
            </span>
          )}
          {s.detectors && s.detectors.length === 1 && s.detectors[0] === "credsweeper" && (
            <span className="ml-2 text-[9px] text-outline" title="Trouvé par CredSweeper, pas par gitleaks">
              CredSweeper
            </span>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-on-surface-variant font-mono truncate max-w-0">
          <span title={s.file}>{s.file ? s.file.split("/").slice(-2).join("/") : "—"}</span>
          {s.mlScope === "TEST_OR_DOC" && (
            <span className="ml-2 text-[10px] font-sans text-outline">(test / exemple / doc)</span>
          )}
        </td>
        <td className="px-4 py-3 text-xs text-center text-outline">{s.startLine ?? "—"}</td>
        <td className="px-4 py-3 text-xs font-mono text-error truncate max-w-0">
          <span title="Valeur masquée pour des raisons de sécurité">{s.maskedMatch ?? "••••••••"}</span>
        </td>
      </tr>
      {open && (
        <tr className="bg-surface-container/40 border-b border-outline-variant/[0.07]">
          <td colSpan={COLS.length} className="px-6 py-4 space-y-3">
            {s.mlReasons && s.mlReasons.length > 0 ? (
              <div>
                <p className="text-[10px] text-outline uppercase font-bold mb-1">Pourquoi ce verdict</p>
                <ul className="list-disc pl-5 text-xs text-on-surface-variant space-y-0.5">
                  {s.mlReasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-xs text-outline">
                {v === "UNTRIAGED" ? "Ce secret n'a pas encore été trié par le modèle." : "Aucune raison marquante."}
              </p>
            )}
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-[10px] text-outline uppercase font-bold mb-1">Description</p>
                <p className="text-on-surface-variant">{s.description || "Aucune description"}</p>
              </div>
              <div>
                <p className="text-[10px] text-outline uppercase font-bold mb-1">Chemin complet</p>
                <p className="font-mono text-on-surface-variant break-all text-xs">{s.file || "—"}</p>
              </div>
              <div>
                <p className="text-[10px] text-outline uppercase font-bold mb-1">Auteur / date</p>
                <p className="text-on-surface-variant text-xs">
                  {s.author || "—"} {s.date ? `· ${new Date(s.date).toLocaleString("fr-FR")}` : ""}
                </p>
              </div>
              <div>
                <p className="text-[10px] text-outline uppercase font-bold mb-1">Commit</p>
                <p className="font-mono text-on-surface-variant text-xs">{s.commit ? s.commit.substring(0, 7) : "—"}</p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2 pt-1" onClick={(e) => e.stopPropagation()}>
              <button
                onClick={() => onVerdict(s.id, "REAL")}
                className="px-3 py-1.5 rounded-lg text-xs font-bold border border-error/40 text-error hover:bg-error/10"
              >
                C'est un vrai secret
              </button>
              <button
                onClick={() => onVerdict(s.id, "FALSE_POSITIVE")}
                className="px-3 py-1.5 rounded-lg text-xs font-bold border border-tertiary/40 text-tertiary hover:bg-tertiary/10"
              >
                C'est un faux positif
              </button>
              {overridden && (
                <button
                  onClick={() => onVerdict(s.id, null)}
                  className="px-3 py-1.5 rounded-lg text-xs text-outline hover:text-on-surface"
                >
                  Annuler ma décision
                </button>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
};

const SecretTable: React.FC<{
  rows: SecretDto[];
  openId: number | null;
  setOpenId: (id: number | null) => void;
  onVerdict: Props["onVerdict"];
}> = ({ rows, openId, setOpenId, onVerdict }) => (
  <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] overflow-hidden shadow-2xl">
    <table className="w-full text-left border-collapse">
      <thead>
        <tr className="bg-surface-container-low/30 border-b border-outline-variant/[0.1]">
          {COLS.map((c) => (
            <th key={c} className="px-4 py-3 text-xs font-bold text-outline uppercase tracking-widest">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((s) => (
          <SecretRow
            key={s.id}
            s={s}
            open={openId === s.id}
            onToggle={() => setOpenId(openId === s.id ? null : s.id)}
            onVerdict={onVerdict}
          />
        ))}
      </tbody>
    </table>
  </div>
);

/** Secrets of a scan, triaged by the model: what to handle first, what to check, and the probable false positives. */
const SecretsPanel: React.FC<Props> = ({ secrets, loading, triaging, onTriage, onVerdict }) => {
  const [openId, setOpenId] = useState<number | null>(null);
  const [showFalse, setShowFalse] = useState(false);
  const [showTestDocs, setShowTestDocs] = useState(false);

  const g = groupSecrets(secrets);

  return (
    <div>
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <span className="material-symbols-outlined text-error text-lg">key_off</span>
        <h2 className="font-headline font-bold text-on-surface text-base">Secrets & Fuites</h2>
        {secrets.length > 0 && (
          <span className="ml-1 px-2 py-0.5 rounded-full text-[10px] font-bold bg-error-container text-on-error-container">
            {g.toHandle.length + g.toCheck.length}
          </span>
        )}
        {g.falsePositives.length > 0 && (
          <span className="text-[11px] text-outline">
            + {g.falsePositives.length} faux positif{g.falsePositives.length > 1 ? "s" : ""} probable
            {g.falsePositives.length > 1 ? "s" : ""} masqué{g.falsePositives.length > 1 ? "s" : ""}
          </span>
        )}
        {g.untriaged > 0 && (
          <button
            onClick={onTriage}
            disabled={triaging}
            className="ml-auto px-3 py-1.5 rounded-lg text-xs font-medium bg-primary/15 text-primary border border-primary/30 hover:bg-primary/25 disabled:opacity-50"
          >
            {triaging ? "Tri en cours…" : `Trier avec le modèle (${g.untriaged})`}
          </button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center gap-3 text-outline py-8 justify-center">
          <span className="material-symbols-outlined animate-spin">progress_activity</span> Chargement des secrets...
        </div>
      ) : secrets.length === 0 ? (
        <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 text-center">
          <span className="material-symbols-outlined text-3xl text-tertiary mb-3 block">shield_lock</span>
          <p className="text-on-surface font-headline font-bold mb-1">Aucun secret détecté</p>
          <p className="text-outline text-sm">Gitleaks n'a trouvé aucun secret exposé dans ce dépôt.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {g.toHandle.length > 0 && (
            <div>
              <p className="text-xs text-on-surface-variant mb-2">
                <strong className="text-error">À traiter en premier</strong> : secrets probablement réels, ceux du code
                de production d'abord.
              </p>
              <SecretTable rows={g.toHandle} openId={openId} setOpenId={setOpenId} onVerdict={onVerdict} />
            </div>
          )}
          {g.toCheck.length > 0 && (
            <div>
              <p className="text-xs text-on-surface-variant mb-2">
                <strong>À vérifier</strong> : le modèle hésite
                {g.untriaged > 0 ? " ou n'a pas encore trié ces secrets" : ""}.
              </p>
              <SecretTable rows={g.toCheck} openId={openId} setOpenId={setOpenId} onVerdict={onVerdict} />
            </div>
          )}
          {g.toHandle.length === 0 && g.toCheck.length === 0 && g.testAndDocs.length === 0 && (
            <div className="glass-panel rounded-2xl border border-tertiary/30 p-6 text-center text-sm text-on-surface">
              Tous les secrets signalés par Gitleaks sont probablement des faux positifs.
            </div>
          )}
          {g.testAndDocs.length > 0 && (
            <div>
              <button
                onClick={() => setShowTestDocs((v) => !v)}
                className="text-xs text-primary hover:underline mb-2"
              >
                {showTestDocs ? "Masquer" : "Voir"} {g.testAndDocs.length} secret{g.testAndDocs.length > 1 ? "s" : ""} dans
                des fichiers de test, d'exemple ou de documentation (priorité basse)
              </button>
              {showTestDocs && (
                <SecretTable rows={g.testAndDocs} openId={openId} setOpenId={setOpenId} onVerdict={onVerdict} />
              )}
            </div>
          )}
          {g.falsePositives.length > 0 && (
            <div>
              <button
                onClick={() => setShowFalse((v) => !v)}
                className="text-xs text-primary hover:underline mb-2"
              >
                {showFalse ? "Masquer" : "Voir"} les {g.falsePositives.length} faux positif
                {g.falsePositives.length > 1 ? "s" : ""} probable{g.falsePositives.length > 1 ? "s" : ""}
              </button>
              {showFalse && (
                <SecretTable rows={g.falsePositives} openId={openId} setOpenId={setOpenId} onVerdict={onVerdict} />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SecretsPanel;
