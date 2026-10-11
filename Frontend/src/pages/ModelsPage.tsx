import React, { useEffect, useState } from "react";
import { getModelCards, type ModelCard, type ModelCardsResponse } from "../services/api";

export const STATUS_STYLE: Record<string, { label: string; cls: string; icon: string; help: string }> = {
  RELIABLE: {
    label: "Fiable",
    cls: "bg-tertiary/15 text-tertiary border-tertiary/30",
    icon: "verified",
    help: "Mesuré sur des données jamais vues et testé sur de vrais dépôts.",
  },
  IMPROVABLE: {
    label: "À améliorer",
    cls: "bg-amber-500/15 text-amber-300 border-amber-500/30",
    icon: "tune",
    help: "Utile, mais mesuré sur peu de données ou avec des limites importantes.",
  },
  THIRD_PARTY: {
    label: "Outil tiers",
    cls: "bg-primary/15 text-primary border-primary/30",
    icon: "extension",
    help: "Ce n'est pas un modèle de Medianet.",
  },
  REMOVED: {
    label: "Retiré",
    cls: "bg-error/15 text-error border-error/30",
    icon: "block",
    help: "Supprimé de l'application car non fiable.",
  },
};

export function statusOf(card: Pick<ModelCard, "status">) {
  return STATUS_STYLE[card.status] ?? STATUS_STYLE.IMPROVABLE;
}

const Fact: React.FC<{ label: string; children: React.ReactNode }> = ({ label, children }) => (
  <div>
    <p className="text-[10px] uppercase tracking-widest text-outline font-bold mb-1">{label}</p>
    <div className="text-sm text-on-surface-variant leading-relaxed">{children}</div>
  </div>
);

const Card: React.FC<{ card: ModelCard }> = ({ card }) => {
  const [open, setOpen] = useState(false);
  const st = statusOf(card);
  const live = card.live;
  return (
    <section className={`glass-panel rounded-2xl border p-5 space-y-4 ${card.removed ? "border-error/20 opacity-90" : "border-outline-variant/[0.15]"}`}>
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="font-headline text-lg font-semibold text-on-surface">{card.name}</h2>
          <p className="text-xs text-outline mt-0.5">
            Version <span className="font-mono text-on-surface-variant">{card.version}</span>
            {live?.exportedAt && <> · exporté le {live.exportedAt}</>}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {live?.tracked && (
            <span
              className={`text-[10px] font-bold px-2 py-1 rounded-full border ${live.installed ? "border-tertiary/30 text-tertiary" : "border-error/30 text-error"}`}
              title={live.installed ? "Le modèle est installé et utilisé par ce serveur" : "Fichiers du modèle absents de ce serveur"}
            >
              {live.installed ? "Actif sur ce serveur" : "Absent de ce serveur"}
            </span>
          )}
          <span className={`inline-flex items-center gap-1 text-[11px] font-bold px-3 py-1 rounded-full border ${st.cls}`} title={st.help}>
            <span className="material-symbols-outlined text-sm">{st.icon}</span>
            {st.label}
          </span>
        </div>
      </header>

      <Fact label="À quoi il sert">{card.purpose}</Fact>
      <Fact label="Où il est utilisé">{card.usedIn}</Fact>

      {card.metrics.length > 0 && (
        <div>
          <p className="text-[10px] uppercase tracking-widest text-outline font-bold mb-2">Résultats mesurés</p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
            {card.metrics.map((m) => (
              <div key={m.label} className="rounded-xl border border-outline-variant/[0.15] bg-surface-container px-3 py-2">
                <p className="text-xl font-bold text-on-surface">{m.value}</p>
                <p className="text-[11px] text-on-surface-variant leading-snug">{m.label}</p>
                {m.note && <p className="text-[10px] text-outline mt-0.5">{m.note}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="rounded-xl border border-amber-500/25 bg-amber-500/5 px-4 py-3">
        <p className="text-[10px] uppercase tracking-widest text-amber-300 font-bold mb-1">Limites à connaître</p>
        <ul className="list-disc pl-5 text-xs text-on-surface-variant space-y-1">
          {card.limits.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </div>

      <button onClick={() => setOpen((v) => !v)} className="text-xs text-primary hover:underline flex items-center gap-1">
        <span className="material-symbols-outlined text-sm">{open ? "expand_less" : "expand_more"}</span>
        {open ? "Masquer" : "Voir"} comment il décide et avec quelles données
      </button>
      {open && (
        <div className="grid gap-4 md:grid-cols-2">
          <Fact label="Comment il décide">{card.how}</Fact>
          <Fact label="Données d'entraînement">
            <p className="font-medium text-on-surface">{card.dataset.name}</p>
            <p>{card.dataset.size}</p>
            <p className="text-xs text-outline mt-1">Découpe : {card.dataset.split}</p>
          </Fact>
          {card.sources.length > 0 && (
            <Fact label="Chiffres tirés de">
              <ul className="font-mono text-[11px] text-outline space-y-0.5">
                {card.sources.map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </Fact>
          )}
        </div>
      )}
    </section>
  );
};

const ModelsPage: React.FC = () => {
  const [data, setData] = useState<ModelCardsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getModelCards()
      .then((r) => setData(r.data))
      .catch(() => setError("Impossible de charger les fiches des modèles."));
  }, []);

  return (
    <div className="space-y-6 max-w-5xl">
      <header>
        <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight mb-2">Modèles ML</h1>
        <p className="text-sm text-on-surface-variant max-w-3xl">
          Les modèles d'apprentissage automatique utilisés par Medianet : ce qu'ils font, comment ils ont été mesurés et
          surtout leurs limites. Un modèle est un indicateur qui aide à prioriser : il ne remplace jamais la décision
          d'un analyste.
        </p>
      </header>

      {error && <p className="text-sm text-error">{error}</p>}
      {!data && !error && <p className="text-sm text-outline">Chargement…</p>}
      {data?.error && <p className="text-sm text-amber-300">{data.error}</p>}

      <div className="space-y-5">
        {data?.models.map((m) => (
          <Card key={m.id} card={m} />
        ))}
      </div>

      {data?.updated && (
        <p className="text-[11px] text-outline">
          Fiches mises à jour le {data.updated}. {data.note}
        </p>
      )}
    </div>
  );
};

export default ModelsPage;
