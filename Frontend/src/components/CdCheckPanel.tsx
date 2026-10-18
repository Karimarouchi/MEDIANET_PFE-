import React, { useState } from "react";
import { checkDeployment, type DeployCheck } from "../services/api";

const ICON = { OK: ["check_circle", "text-tertiary"], WARN: ["warning", "text-amber-300"], KO: ["cancel", "text-error"] } as const;

/** "Vérifier la configuration": runs the read-only checks on the server and lists them. */
const CdCheckPanel: React.FC<{ deploymentId: number }> = ({ deploymentId }) => {
  const [result, setResult] = useState<DeployCheck | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      setResult((await checkDeployment(deploymentId)).data);
    } catch (e) {
      const r = e as { response?: { data?: { message?: string } } };
      setError(r?.response?.data?.message || "Vérification impossible.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-2">
      <button type="button" onClick={run} disabled={busy}
        className="rounded-lg border border-primary/30 bg-primary/10 px-3 py-1 text-[11px] font-semibold text-primary hover:bg-primary/20 disabled:opacity-60">
        {busy ? "Vérification sur le serveur…" : "Vérifier la configuration"}
      </button>
      <span className="ml-2 text-[10px] text-outline">Lecture seule : rien n'est modifié sur le serveur.</span>
      {error && <p className="mt-1 text-[11px] text-error">{error}</p>}
      {result && (
        <div className={`mt-2 rounded-lg border p-3 ${result.ok ? "border-tertiary/30 bg-tertiary/5" : "border-error/30 bg-error/5"}`}>
          <p className={`text-[11px] font-semibold ${result.ok ? "text-tertiary" : "text-error"}`}>
            {result.ok ? "Prêt : le déploiement continu peut tourner sur ce serveur." : "À corriger avant d'activer le déploiement continu."}
          </p>
          <ul className="mt-1 space-y-0.5">
            {result.items.map((i, n) => (
              <li key={n} className="flex items-start gap-1.5 text-[11px] text-on-surface">
                <span className={`material-symbols-outlined text-[14px] ${ICON[i.level][1]}`}>{ICON[i.level][0]}</span>
                <span>{i.text}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default CdCheckPanel;
