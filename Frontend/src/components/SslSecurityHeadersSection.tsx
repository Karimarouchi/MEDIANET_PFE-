import React, { useMemo, useState } from 'react';
import type { SslResultDto } from '../services/api';
import SecurityHeaderDetailsDrawer, { type HeaderDrawerTab } from './SecurityHeaderDetailsDrawer';
import {
  type HeaderBadge,
  type HeaderPresentation,
  badgeLabel,
  computeHeadersSummary,
} from './sslHeaderModel';

type Props = { result: SslResultDto };

const BADGE_CLS: Record<HeaderBadge, string> = {
  conforme: 'bg-tertiary/12 text-tertiary border-tertiary/25',
  partiel: 'bg-[#ffaa40]/12 text-[#ffaa40] border-[#ffaa40]/25',
  observation: 'bg-[#a4e6ff]/12 text-[#a4e6ff] border-[#a4e6ff]/25',
  a_corriger: 'bg-error/12 text-error border-error/25',
  recommande: 'bg-[#a4e6ff]/10 text-[#a4e6ff] border-[#a4e6ff]/20',
  contextuel: 'bg-[#a78bfa]/12 text-[#c4b5fd] border-[#a78bfa]/25',
  non_requis: 'bg-tertiary/8 text-tertiary/80 border-tertiary/20',
  non_teste: 'bg-outline/10 text-outline border-outline/20',
  non_detecte: 'bg-slate-500/15 text-slate-300 border-slate-500/25',
  presence_nc: 'bg-[#ffaa40]/10 text-[#ffaa40] border-[#ffaa40]/20',
};

const PRIORITY_LABEL: Record<string, string> = {
  critique: 'Critique',
  haute: 'Haute',
  moyenne: 'Moyenne',
  basse: 'Basse',
  contextuelle: 'Contextuelle',
};

const SslSecurityHeadersSection: React.FC<Props> = ({ result }) => {
  const summary = useMemo(() => computeHeadersSummary(result), [result]);
  const [open, setOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<HeaderDrawerTab>('understand');

  const selected = summary.items.find(i => i.id === selectedId) || null;

  const openItem = (id: string, t: HeaderDrawerTab = 'understand') => {
    setSelectedId(id);
    setTab(t);
    setOpen(true);
  };

  return (
    <div className="bg-surface-container rounded-2xl p-5 space-y-5">
      <div>
        <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-secondary text-lg">http</span>
          Protection HTTP du navigateur
        </h2>
        <p className="text-xs text-outline">
          Cette analyse vérifie les politiques envoyées au navigateur pour limiter
          les injections de contenu, le clickjacking, les fuites d’informations et
          l’utilisation abusive de certaines fonctionnalités.
        </p>
      </div>

      {/* Synthèse */}
      <section className="rounded-xl border border-primary/20 bg-surface-container-low p-4 space-y-3">
        <div className="text-[10px] font-bold text-primary uppercase tracking-widest">Synthèse</div>
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5">
          {(() => {
            const score = summary.mainScore;
            const color =
              score >= 90 ? '#00fc92'
                : score >= 70 ? '#a4e6ff'
                : score >= 50 ? '#ffe066'
                : score >= 30 ? '#ffaa40'
                : '#ffb4ab';
            return (
              <div className="shrink-0 flex flex-col items-center gap-1.5">
                <div
                  className="relative w-[104px] h-[104px] rounded-full flex items-center justify-center"
                  style={{
                    background: `conic-gradient(${color} ${score * 3.6}deg, rgba(255,255,255,0.06) 0deg)`,
                    boxShadow: `0 0 24px ${color}33`,
                  }}
                  aria-label={`Score protection HTTP ${score} sur 100`}
                >
                  <div className="absolute inset-[8px] rounded-full bg-surface-container-low flex flex-col items-center justify-center">
                    <span className="text-2xl font-headline font-extrabold leading-none" style={{ color }}>
                      {score}
                    </span>
                    <span className="text-[10px] font-bold text-outline mt-0.5">/100</span>
                  </div>
                </div>
                <div className="text-[10px] font-bold uppercase tracking-wider text-outline">Protection HTTP</div>
              </div>
            );
          })()}

          <div className="flex-1 w-full space-y-2">
            <div className="text-xs text-on-surface-variant">
              {summary.conformes} protections conformes
              {summary.partielles > 0 ? ` · ${summary.partielles} partielle${summary.partielles > 1 ? 's' : ''}` : ''}
              {summary.observations > 0 ? ` · ${summary.observations} en mode observation` : ''}
            </div>
            <div className="text-xs text-outline">
              Isolation cross-origin : {summary.isolationLabel}
            </div>
            <div className="text-xs text-on-surface">
              <span className="text-outline">Priorité principale :</span> {summary.primaryPriority}
            </div>
            <div className="flex flex-wrap gap-1.5 pt-1">
              <Chip>{summary.conformes} conformes</Chip>
              <Chip tone="warn">{summary.partielles} partielle{summary.partielles > 1 ? 's' : ''}</Chip>
              <Chip tone="info">{summary.observations} mode observation</Chip>
              <Chip tone="ctx">{summary.contextuelles} politiques contextuelles</Chip>
            </div>
          </div>
        </div>
        <p className="text-xs text-on-surface-variant leading-relaxed">{summary.conclusion}</p>
      </section>

      {/* Principales */}
      <div>
        <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">
          Protections HTTP principales
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {summary.mainItems.map(item => (
            <HeaderCard key={item.id} item={item} onOpen={() => openItem(item.id)} expanded={open && selectedId === item.id} />
          ))}
        </div>
      </div>

      {/* Contextuelles */}
      <div>
        <div className="text-[10px] font-bold text-outline uppercase tracking-widest mb-2">
          Protections avancées et contextuelles
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {summary.contextualItems.map(item => (
            <HeaderCard
              key={item.id}
              item={item}
              actionLabel="Évaluer cette protection"
              onOpen={() => openItem(item.id)}
              expanded={open && selectedId === item.id}
            />
          ))}
        </div>
        <div className="mt-3 rounded-xl border border-[#a78bfa]/25 bg-[#a78bfa]/8 px-4 py-3 flex items-start gap-2">
          <span className="material-symbols-outlined text-[#c4b5fd] text-base shrink-0 mt-0.5">info</span>
          <p className="text-xs text-on-surface-variant leading-relaxed">
            Ces protections sont contextuelles et leur absence ne constitue pas automatiquement une vulnérabilité.
            Elles doivent être activées uniquement lorsque l’architecture et les fonctionnalités de l’application le nécessitent.
            Impact sur le score principal : aucun.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-outline-variant/20 bg-surface-container-highest/30 px-4 py-3 flex items-start gap-2">
        <span className="material-symbols-outlined text-primary text-base shrink-0 mt-0.5">clinical_notes</span>
        <p className="text-xs text-on-surface-variant leading-relaxed">{summary.conclusion}</p>
      </div>

      <SecurityHeaderDetailsDrawer
        open={open}
        onClose={() => setOpen(false)}
        item={selected}
        result={result}
        tab={tab}
        onTabChange={setTab}
      />
    </div>
  );
};

function HeaderCard({
  item, onOpen, expanded, actionLabel = 'Voir les détails',
}: {
  item: HeaderPresentation;
  onOpen: () => void;
  expanded: boolean;
  actionLabel?: string;
}) {
  return (
    <article className="rounded-xl border border-outline-variant/20 bg-surface-container-low p-4 flex flex-col gap-3">
      <div className="flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
          <span className="material-symbols-outlined text-primary text-lg">{item.icon}</span>
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="font-headline font-bold text-sm text-on-surface">{item.abbr}</h3>
            <span className="text-[10px] text-outline">{item.name}</span>
          </div>
          <p className="text-[11px] text-outline leading-relaxed mt-1">{item.utility}</p>
        </div>
      </div>

      <span className={`self-start inline-flex text-[10px] font-bold px-2 py-1 rounded-full border ${BADGE_CLS[item.badge]}`}>
        {item.kind === 'contextual' ? item.statusLabel : badgeLabel(item.badge)}
      </span>

      <div className="text-[11px] text-on-surface-variant space-y-0.5">
        <div><span className="text-outline">Statut :</span> {item.statusLabel}</div>
        {item.kind === 'contextual' && (
          <div><span className="text-outline">Impact sur le score principal :</span> Aucun</div>
        )}
        {item.shortValue && (
          <div className="font-mono text-[10px] text-on-surface/80 break-all">
            <span className="text-outline font-sans">Valeur :</span> {item.shortValue}
          </div>
        )}
        {!item.shortValue && !item.observedValue && item.kind !== 'contextual' && item.badge !== 'conforme' && (
          <div className="text-[#ffaa40]">Valeur : Présence non confirmée / non disponible</div>
        )}
        {item.conclusion && <div className="text-outline leading-relaxed pt-0.5">{item.conclusion}</div>}
        <div><span className="text-outline">Priorité :</span> {PRIORITY_LABEL[item.priority] || item.priority}</div>
      </div>

      <button
        type="button"
        onClick={onOpen}
        aria-expanded={expanded}
        className="mt-auto self-start min-h-[44px] px-3 rounded-xl text-xs font-bold text-primary border border-primary/25 hover:bg-primary/10 transition-colors"
      >
        {actionLabel}
      </button>
    </article>
  );
}

function Chip({ children, tone }: { children: React.ReactNode; tone?: 'warn' | 'info' | 'ctx' }) {
  const cls = tone === 'warn'
    ? 'bg-[#ffaa40]/10 text-[#ffaa40] border-[#ffaa40]/25'
    : tone === 'info'
      ? 'bg-[#a4e6ff]/10 text-[#a4e6ff] border-[#a4e6ff]/25'
      : tone === 'ctx'
        ? 'bg-[#a78bfa]/10 text-[#c4b5fd] border-[#a78bfa]/25'
        : 'bg-tertiary/10 text-tertiary border-tertiary/25';
  return (
    <span className={`text-[10px] font-bold px-2 py-1 rounded-full border ${cls}`}>{children}</span>
  );
}

export default SslSecurityHeadersSection;
