import React, { useMemo, useState } from 'react';
import type { SslResultDto } from '../services/api';
import VulnerabilityDetailsDrawer, { type VulnDrawerTab } from './VulnerabilityDetailsDrawer';
import {
  type VulnConfidence,
  type VulnPresentation,
  type VulnResultStatus,
  buildSectionConclusion,
  buildSummaryConclusion,
  buildVulnPresentations,
  confidenceLabel,
  severityLabel,
  statusLabel,
} from './sslVulnModel';

type Props = { result: SslResultDto };

type FilterId =
  | 'all'
  | 'detected'
  | 'not_detected'
  | 'confirm'
  | 'critical'
  | 'high'
  | 'medium';

const FILTERS: { id: FilterId; label: string }[] = [
  { id: 'all', label: 'Toutes' },
  { id: 'detected', label: 'Détectées' },
  { id: 'not_detected', label: 'Non détectées' },
  { id: 'confirm', label: 'À confirmer' },
  { id: 'critical', label: 'Critiques' },
  { id: 'high', label: 'Élevées' },
  { id: 'medium', label: 'Moyennes' },
];

const STATUS_META: Record<VulnResultStatus, { icon: string; tip: string; cls: string }> = {
  detected: {
    icon: 'gpp_bad',
    tip: 'Les tests indiquent que le serveur présente cette vulnérabilité.',
    cls: 'bg-error/15 text-error border-error/30',
  },
  not_detected: {
    icon: 'verified_user',
    tip: 'Les tests exécutés n’ont pas identifié cette vulnérabilité.',
    cls: 'bg-tertiary/12 text-tertiary border-tertiary/25',
  },
  inconclusive: {
    icon: 'help',
    tip: 'Les données disponibles ne permettent pas d’établir un résultat fiable.',
    cls: 'bg-[#ffaa40]/12 text-[#ffaa40] border-[#ffaa40]/25',
  },
  not_tested: {
    icon: 'remove',
    tip: 'Aucun moteur d’analyse n’a exécuté ce test.',
    cls: 'bg-outline/10 text-outline border-outline/20',
  },
  test_error: {
    icon: 'warning',
    tip: 'Le test n’a pas pu être terminé correctement.',
    cls: 'bg-[#ff7b54]/15 text-[#ff7b54] border-[#ff7b54]/30',
  },
};

const CONF_META: Record<VulnConfidence, { tip: string; cls: string }> = {
  high: {
    tip: 'Plusieurs outils indépendants ont produit le même résultat.',
    cls: 'text-tertiary bg-tertiary/10 border-tertiary/25',
  },
  medium: {
    tip: 'Une source complète ou plusieurs sources partiellement concordantes.',
    cls: 'text-[#ffe066] bg-[#ffe066]/10 border-[#ffe066]/25',
  },
  low: {
    tip: 'Le résultat repose sur une quantité limitée de preuves et peut nécessiter une vérification complémentaire.',
    cls: 'text-outline bg-surface-container-highest border-outline/20',
  },
  unknown: {
    tip: 'Niveau de confiance non déterminé.',
    cls: 'text-outline bg-surface-container-highest border-outline/20',
  },
};

function cardBorder(v: VulnPresentation): string {
  if (v.status === 'detected') return 'border-error/35 bg-error/[0.06]';
  if (v.status === 'not_detected' && v.confidence === 'high') return 'border-tertiary/25 bg-surface-container-low';
  if (v.status === 'not_detected' && v.confidence === 'low') return 'border-outline-variant/20 bg-surface-container-low';
  if (v.status === 'test_error' || v.status === 'inconclusive') return 'border-[#ffaa40]/25 bg-[#ffaa40]/[0.04]';
  return 'border-outline-variant/15 bg-surface-container-low';
}

const SslVulnerabilitiesSection: React.FC<Props> = ({ result }) => {
  const items = useMemo(() => buildVulnPresentations(result), [result]);
  const [filter, setFilter] = useState<FilterId>('all');
  const [query, setQuery] = useState('');
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [tab, setTab] = useState<VulnDrawerTab>('understand');
  const [fixedIds, setFixedIds] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem(`ssl-vuln-fixed-${result.domain}`);
      return raw ? new Set(JSON.parse(raw) as string[]) : new Set();
    } catch {
      return new Set();
    }
  });

  const selected = items.find(v => v.id === selectedId) || null;

  const stats = useMemo(() => {
    const tested = items.filter(v => v.status !== 'not_tested').length;
    const detected = items.filter(v => v.status === 'detected').length;
    const notDetected = items.filter(v => v.status === 'not_detected').length;
    const inconclusive = items.filter(v => v.status === 'inconclusive' || v.status === 'test_error').length;
    const high = items.filter(v => v.confidence === 'high').length;
    const low = items.filter(v => v.confidence === 'low' || v.confidence === 'unknown').length;
    // Score /100 : 100 si rien n’est détecté, pénalités selon sévérité / erreurs
    let score = 100;
    for (const v of items) {
      if (v.status === 'detected') {
        if (v.theoreticalSeverity === 'critical') score -= 22;
        else if (v.theoreticalSeverity === 'high') score -= 12;
        else score -= 6;
      } else if (v.status === 'test_error' || v.status === 'inconclusive') {
        score -= 3;
      } else if (v.status === 'not_detected' && v.confidence === 'low') {
        score -= 1;
      }
    }
    score = Math.max(0, Math.min(100, score));
    return { tested, detected, notDetected, inconclusive, high, low, total: items.length, score };
  }, [items]);

  const scoreColor =
    stats.score >= 90 ? '#00fc92'
      : stats.score >= 70 ? '#a4e6ff'
      : stats.score >= 50 ? '#ffe066'
      : stats.score >= 30 ? '#ffaa40'
      : '#ffb4ab';

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter(v => {
      if (filter === 'detected' && v.status !== 'detected') return false;
      if (filter === 'not_detected' && v.status !== 'not_detected') return false;
      if (filter === 'confirm' && !(v.needsSecondSource || v.confidence === 'low')) return false;
      if (filter === 'critical' && v.theoreticalSeverity !== 'critical') return false;
      if (filter === 'high' && v.theoreticalSeverity !== 'high') return false;
      if (filter === 'medium' && v.theoreticalSeverity !== 'medium') return false;
      if (!q) return true;
      return (
        v.name.toLowerCase().includes(q)
        || (v.cve || '').toLowerCase().includes(q)
        || v.summary.toLowerCase().includes(q)
      );
    });
  }, [items, filter, query]);

  const openDrawer = (id: string, t: VulnDrawerTab = 'understand') => {
    setSelectedId(id);
    setTab(t);
    setDrawerOpen(true);
  };

  const toggleFixed = () => {
    if (!selectedId) return;
    setFixedIds(prev => {
      const next = new Set(prev);
      if (next.has(selectedId)) next.delete(selectedId);
      else next.add(selectedId);
      try {
        localStorage.setItem(
          `ssl-vuln-fixed-${result.domain}`,
          JSON.stringify(Array.from(next)),
        );
      } catch { /* ignore */ }
      return next;
    });
  };

  return (
    <div className="bg-surface-container rounded-2xl p-5 space-y-5">
      <div>
        <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-error text-lg">bug_report</span>
          Vulnérabilités SSL/TLS connues
        </h2>
        <p className="text-xs text-outline">
          Cette analyse recherche les principales failles historiques affectant
          les protocoles TLS, les bibliothèques cryptographiques et les suites de
          chiffrement du serveur.
        </p>
      </div>

      {/* Synthèse */}
      <section className="rounded-xl border border-primary/20 bg-surface-container-low p-4 space-y-3">
        <div className="text-[10px] font-bold text-primary uppercase tracking-widest">Synthèse</div>
        <div className="flex flex-col sm:flex-row items-center sm:items-start gap-5">
          {/* Score circulaire /100 */}
          <div className="shrink-0 flex flex-col items-center gap-1.5">
            <div
              className="relative w-[104px] h-[104px] rounded-full flex items-center justify-center"
              style={{
                background: `conic-gradient(${scoreColor} ${stats.score * 3.6}deg, rgba(255,255,255,0.06) 0deg)`,
                boxShadow: `0 0 24px ${scoreColor}33`,
              }}
              aria-label={`Score vulnérabilités ${stats.score} sur 100`}
            >
              <div className="absolute inset-[8px] rounded-full bg-surface-container-low flex flex-col items-center justify-center">
                <span className="text-2xl font-headline font-extrabold leading-none" style={{ color: scoreColor }}>
                  {stats.score}
                </span>
                <span className="text-[10px] font-bold text-outline mt-0.5">/100</span>
              </div>
            </div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-outline">Score vulns</div>
          </div>

          <div className="flex-1 w-full space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <Stat label="Vulnérabilités analysées" value={`${stats.total}`} />
              <Stat label="Détectées" value={`${stats.detected}`} tone={stats.detected > 0 ? 'bad' : 'ok'} />
              <Stat label="Non détectées" value={`${stats.notDetected}`} />
              <Stat label="Inconclusifs / erreurs" value={`${stats.inconclusive}`} />
              <Stat label="Confiance élevée" value={`${stats.high}`} tone="ok" />
              <Stat label="À confirmer / faible" value={`${stats.low}`} tone="warn" />
            </div>
            <p className="text-xs text-on-surface-variant leading-relaxed">{buildSummaryConclusion(items)}</p>
          </div>
        </div>
      </section>

      {/* Filtres + recherche */}
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map(f => (
            <button
              key={f.id}
              type="button"
              onClick={() => setFilter(f.id)}
              className={`min-h-[36px] px-3 rounded-xl text-[11px] font-bold border transition-colors ${
                filter === f.id
                  ? 'bg-primary/15 text-primary border-primary/30'
                  : 'bg-surface-container-highest text-outline border-outline-variant/20 hover:border-primary/20'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="relative">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-lg">search</span>
          <input
            type="search"
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Rechercher par nom ou CVE…"
            className="w-full min-h-[44px] rounded-xl bg-surface-container-highest border border-outline-variant/20 pl-10 pr-3 text-sm text-on-surface placeholder:text-outline/40 focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
      </div>

      {/* Cartes */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {filtered.map(v => {
          const sm = STATUS_META[v.status];
          const cm = CONF_META[v.confidence];
          return (
            <article key={v.id} className={`rounded-xl border p-4 flex flex-col gap-3 ${cardBorder(v)}`}>
              <div className="flex items-start gap-3">
                <div
                  title={sm.tip}
                  className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${sm.cls}`}
                >
                  <span className="material-symbols-outlined text-base" style={{ fontVariationSettings: "'FILL' 1" }}>
                    {sm.icon}
                  </span>
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="font-headline font-bold text-sm text-on-surface">{v.name}</h3>
                    {v.cve && (
                      <span className="text-[9px] font-mono text-outline bg-surface-container-highest px-1.5 py-0.5 rounded">
                        {v.cve}
                      </span>
                    )}
                    {fixedIds.has(v.id) && (
                      <span className="text-[9px] font-bold text-tertiary bg-tertiary/10 px-1.5 py-0.5 rounded">Corrigé</span>
                    )}
                  </div>
                  <p className="text-[11px] text-outline leading-relaxed mt-1">{v.summary}</p>
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5">
                <span title={sm.tip} className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-1 rounded-full border ${sm.cls}`}>
                  {statusLabel(v.status)}
                </span>
                <span title={cm.tip} className={`inline-flex items-center text-[10px] font-bold px-2 py-1 rounded-full border ${cm.cls}`}>
                  {confidenceLabel(v.confidence)}
                </span>
              </div>

              <div className="text-[11px] text-on-surface-variant space-y-0.5">
                <div>Sources : {v.sourcesLabel}</div>
                {v.needsSecondSource && (
                  <div className="text-[#ffaa40]">Résultat à confirmer avec une seconde source</div>
                )}
                <div>
                  Sévérité si vulnérable :{' '}
                  <span className="font-bold text-on-surface">{severityLabel(v.theoreticalSeverity)}</span>
                </div>
              </div>

              <button
                type="button"
                onClick={() => openDrawer(v.id)}
                aria-expanded={drawerOpen && selectedId === v.id}
                className="mt-auto self-start min-h-[44px] px-3 rounded-xl text-xs font-bold text-primary border border-primary/25 hover:bg-primary/10 transition-colors"
              >
                Voir les détails
              </button>
            </article>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <p className="text-xs text-outline text-center py-4">Aucune vulnérabilité ne correspond à ce filtre.</p>
      )}

      <div className="rounded-xl border border-outline-variant/20 bg-surface-container-highest/30 px-4 py-3 flex items-start gap-2">
        <span className="material-symbols-outlined text-primary text-base shrink-0 mt-0.5">clinical_notes</span>
        <p className="text-xs text-on-surface-variant leading-relaxed">{buildSectionConclusion(items)}</p>
      </div>

      <VulnerabilityDetailsDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        vuln={selected}
        result={result}
        tab={tab}
        onTabChange={setTab}
        markedFixed={!!selectedId && fixedIds.has(selectedId)}
        onToggleFixed={toggleFixed}
      />
    </div>
  );
};

function Stat({
  label, value, tone,
}: {
  label: string;
  value: string;
  tone?: 'ok' | 'bad' | 'warn';
}) {
  const color =
    tone === 'bad' ? 'text-error'
      : tone === 'ok' ? 'text-tertiary'
      : tone === 'warn' ? 'text-[#ffaa40]'
      : 'text-on-surface';
  return (
    <div>
      <div className="text-[10px] text-outline">{label}</div>
      <div className={`text-sm font-headline font-bold ${color}`}>{value}</div>
    </div>
  );
}

export default SslVulnerabilitiesSection;
