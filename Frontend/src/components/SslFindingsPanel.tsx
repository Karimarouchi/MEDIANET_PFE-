import React, { useMemo, useState } from 'react';
import type { SslResultDto } from '../services/api';
import { fixTargets, sslFindings, type Finding, type FindingSeverity } from '../utils/sslFindings';

const SEVERITY_STYLE: Record<FindingSeverity, { label: string; cls: string; dot: string }> = {
  critique: { label: 'Critique', cls: 'bg-error/15 text-error border-error/30', dot: 'bg-error' },
  élevée: { label: 'Élevée', cls: 'bg-[#ffaa40]/15 text-[#ffaa40] border-[#ffaa40]/30', dot: 'bg-[#ffaa40]' },
  moyenne: { label: 'Moyenne', cls: 'bg-[#ffe066]/15 text-[#ffe066] border-[#ffe066]/30', dot: 'bg-[#ffe066]' },
  faible: { label: 'Faible', cls: 'bg-surface-variant text-on-surface-variant border-outline-variant/30', dot: 'bg-outline' },
};

const CopyButton: React.FC<{ text: string }> = ({ text }) => {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          window.setTimeout(() => setDone(false), 1500);
        }).catch(() => undefined);
      }}
      className="shrink-0 rounded-lg border border-outline-variant/30 px-2 py-1 text-[10px] font-semibold text-on-surface-variant hover:text-on-surface hover:bg-surface-container-highest"
    >
      {done ? 'Copié' : 'Copier'}
    </button>
  );
};

const FindingCard: React.FC<{ f: Finding; targets: Array<'nginx' | 'apache'>; sameFixAs?: string }> = ({ f, targets, sameFixAs }) => {
  const s = SEVERITY_STYLE[f.severity];
  const configs = targets
    .map((t) => ({ t, line: t === 'nginx' ? f.nginx : f.apache }))
    .filter((c): c is { t: 'nginx' | 'apache'; line: string } => !!c.line);
  return (
    <li className="rounded-xl border border-outline-variant/[0.15] bg-surface-container-low p-4 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${s.cls}`}>{s.label}</span>
        <h3 className="font-headline font-bold text-sm text-on-surface">{f.title}</h3>
        {f.cve && <span className="text-[9px] font-mono text-outline bg-surface-container-highest px-1.5 py-0.5 rounded">{f.cve}</span>}
        {f.toConfirm && (
          <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-amber-500/15 text-amber-300">à confirmer</span>
        )}
      </div>
      <p className="text-xs text-on-surface-variant leading-relaxed">
        <span className="font-semibold text-on-surface">Faille si non corrigé : </span>{f.risk}
      </p>
      <p className="text-xs text-on-surface-variant leading-relaxed">
        <span className="font-semibold text-on-surface">Corriger : </span>{f.fix}
      </p>
      {sameFixAs ? (
        <p className="text-xs text-outline">Même ligne de configuration que « {sameFixAs} » ci-dessus : une seule modification corrige les deux.</p>
      ) : configs.map((c) => (
        <div key={c.t} className="flex items-start gap-2">
          <span className="w-12 shrink-0 pt-1.5 text-[10px] font-bold uppercase text-outline">{c.t}</span>
          <pre className="min-w-0 flex-1 overflow-x-auto rounded-lg bg-black/40 px-3 py-1.5 font-mono text-[11px] text-slate-200 whitespace-pre-wrap break-all">{c.line}</pre>
          <CopyButton text={c.line} />
        </div>
      ))}
      <p className="text-[10px] text-outline">
        {f.toConfirm ? `Vu par un seul outil (${f.seenBy}) : à vérifier avant d’agir.` : `Détecté par : ${f.seenBy}.`}
      </p>
    </li>
  );
};

/**
 * The part of the SSL result that tells what to do: problems from the most to the least severe (each with the flaw
 * it leaves open and the configuration line that fixes it), then the checks that passed, folded.
 */
const SslFindingsPanel: React.FC<{ result: SslResultDto; provisional?: boolean }> = ({ result, provisional }) => {
  const { findings, passed, untested } = useMemo(() => sslFindings(result), [result]);
  const [passedOpen, setPassedOpen] = useState(false);
  const targets = fixTargets(result.webServer);
  const counts = (['critique', 'élevée', 'moyenne', 'faible'] as FindingSeverity[])
    .map((sev) => ({ sev, n: findings.filter((f) => f.severity === sev).length }))
    .filter((c) => c.n > 0);

  return (
    <div className="space-y-4">
      <div className="rounded-2xl bg-surface-container p-5 space-y-4" id="ssl-problems">
        <div className="flex flex-wrap items-center gap-2">
          <span className="material-symbols-outlined text-base text-primary">build</span>
          <h2 className="font-headline font-bold text-base text-on-surface">
            {findings.length === 0 ? 'Aucun problème à corriger' : `${findings.length} problème${findings.length > 1 ? 's' : ''} à corriger`}
          </h2>
          {counts.map((c) => (
            <span key={c.sev} className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${SEVERITY_STYLE[c.sev].cls}`}>
              {c.n} {SEVERITY_STYLE[c.sev].label.toLowerCase()}{c.n > 1 ? 's' : ''}
            </span>
          ))}
          <div className="flex-1" />
          <span className="text-[10px] text-outline">
            {result.webServer === 'nginx' || result.webServer === 'apache'
              ? `Corrections pour ${result.webServer === 'nginx' ? 'nginx' : 'Apache'} (serveur détecté)`
              : 'Corrections pour nginx et Apache'}
          </span>
        </div>
        {provisional && (
          <p className="text-xs text-primary">Liste provisoire : des sources n’ont pas encore répondu.</p>
        )}
        {findings.length === 0 ? (
          <p className="text-sm text-tertiary">La configuration HTTPS ne présente aucun défaut connu parmi les contrôles réalisés.</p>
        ) : (
          <ul className="space-y-3">
            {findings.map((f, i) => {
              // Same configuration lines as a problem above: say so instead of printing the block twice.
              const key = `${f.nginx ?? ''}|${f.apache ?? ''}`;
              const earlier = key !== '|' ? findings.slice(0, i).find((o) => `${o.nginx ?? ''}|${o.apache ?? ''}` === key) : undefined;
              return <FindingCard key={f.id} f={f} targets={targets} sameFixAs={earlier?.title} />;
            })}
          </ul>
        )}
      </div>

      <div className="rounded-2xl bg-surface-container">
        <button type="button" onClick={() => setPassedOpen(!passedOpen)} aria-expanded={passedOpen}
          className="w-full flex items-center gap-2 px-5 py-3 text-left hover:bg-surface-container-high/40 transition-colors rounded-2xl">
          <span className="material-symbols-outlined text-base text-tertiary">task_alt</span>
          <span className="font-headline font-bold text-sm text-on-surface">Ce qui est bon</span>
          <span className="text-xs text-outline">
            {passed.length} contrôle{passed.length > 1 ? 's' : ''} réussi{passed.length > 1 ? 's' : ''}
            {untested.length > 0 ? ` · ${untested.length} non testé${untested.length > 1 ? 's' : ''}` : ''}
          </span>
          <span className="material-symbols-outlined ml-auto text-outline text-base">{passedOpen ? 'expand_less' : 'expand_more'}</span>
        </button>
        {passedOpen && (
          <div className="px-5 pb-4 space-y-3">
            <div className="flex flex-wrap gap-1.5">
              {passed.map((p) => (
                <span key={p.id} title={p.singleSource ? 'Vérifié par un seul outil' : undefined}
                  className={`inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded-full border ${p.singleSource
                    ? 'border-outline-variant/30 text-on-surface-variant' : 'border-tertiary/30 bg-tertiary/10 text-tertiary'}`}>
                  <span className="material-symbols-outlined text-[13px]" aria-hidden="true">check</span>{p.label}
                </span>
              ))}
            </div>
            {passed.some((p) => p.singleSource) && (
              <p className="text-[10px] text-outline">En gris : vérifié par un seul outil.</p>
            )}
            {untested.length > 0 && (
              <p className="text-[11px] text-outline">Non testé (outil indisponible pendant ce scan) : {untested.join(', ')}.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default SslFindingsPanel;
