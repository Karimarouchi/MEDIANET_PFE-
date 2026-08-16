import React, { useEffect, useId, useMemo, useState } from 'react';
import { createPortal } from 'react-dom';
import type { SslResultDto } from '../services/api';
import { detectPreferredServer } from './sslVulnModel';
import {
  type HeaderPresentation,
  badgeLabel,
} from './sslHeaderModel';

export type HeaderDrawerTab = 'understand' | 'value' | 'recommend' | 'config';

type Props = {
  open: boolean;
  onClose: () => void;
  item: HeaderPresentation | null;
  result: SslResultDto;
  tab: HeaderDrawerTab;
  onTabChange: (t: HeaderDrawerTab) => void;
};

function copyText(text: string) {
  if (!text) return;
  navigator.clipboard?.writeText(text).catch(() => {});
}

const SecurityHeaderDetailsDrawer: React.FC<Props> = ({
  open, onClose, item, result, tab, onTabChange,
}) => {
  const titleId = useId();
  const preferred = useMemo(() => detectPreferredServer(result), [result]);
  const [serverTab, setServerTab] = useState<'nginx' | 'apache'>(preferred.server);

  useEffect(() => {
    if (open) setServerTab(preferred.server);
  }, [open, preferred.server, item?.id]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  if (!open || !item) return null;

  const conf = serverTab === 'nginx' ? item.nginx : item.apache;

  const panel = (
    <div className="fixed inset-0 z-[9999] flex justify-end" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <button type="button" aria-label="Fermer" className="absolute inset-0 bg-black/65 backdrop-blur-md" onClick={onClose} />
      <aside className="relative z-10 flex h-[100dvh] max-h-[100dvh] w-full max-w-full sm:w-[min(600px,92vw)] flex-col bg-[#12141a] border-l border-outline-variant/20 shadow-2xl text-[#e6edf3]">
        <header className="shrink-0 px-5 py-4 border-b border-outline-variant/15 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-[10px] font-bold uppercase tracking-widest text-[#8b949e] mb-1">Protection HTTP</div>
            <h2 id={titleId} className="font-headline font-bold text-lg truncate">{item.name}</h2>
            <div className="text-[11px] text-[#8b949e] mt-0.5">{item.abbr} · {badgeLabel(item.badge)}</div>
          </div>
          <button type="button" onClick={onClose} aria-label="Fermer"
            className="w-11 h-11 shrink-0 rounded-xl border border-outline-variant/20 flex items-center justify-center text-[#8b949e] hover:text-[#e6edf3]">
            <span className="material-symbols-outlined">close</span>
          </button>
        </header>

        <div className="shrink-0 px-5 pt-3 flex gap-1 border-b border-outline-variant/10 overflow-x-auto">
          {([
            ['understand', 'Comprendre'],
            ['value', 'Valeur détectée'],
            ['recommend', 'Recommandation'],
            ['config', 'Configuration'],
          ] as const).map(([id, label]) => (
            <button key={id} type="button" onClick={() => onTabChange(id)}
              className={`px-3 py-2.5 text-xs font-bold min-h-[44px] whitespace-nowrap border-b-2 ${
                tab === id ? 'border-primary text-primary' : 'border-transparent text-[#8b949e] hover:text-[#e6edf3]'
              }`}>
              {label}
            </button>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-4 space-y-3">
          {tab === 'understand' && (
            <>
              <Block title="À quoi sert cette protection ?" body={item.role} />
              <Block title="Quel risque réduit-elle ?" body={item.risk} />
              <Block title="Quand faut-il l’activer ?" body={item.when} />
              <Mini label="Caractère" value={
                item.requirement === 'obligatoire' ? 'Obligatoire / essentielle'
                  : item.requirement === 'recommande' ? 'Recommandée'
                  : 'Contextuelle'
              } />
              <Mini label="Impact potentiel sur l’application" value={item.impact} />
            </>
          )}

          {tab === 'value' && (
            <>
              <Mini label="Nom de l’en-tête" value={item.headerName} />
              <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e]">Valeur complète observée</div>
                  {item.observedValue && (
                    <button type="button" onClick={() => copyText(item.observedValue || '')}
                      className="text-[10px] font-bold text-primary min-h-[28px]">Copier</button>
                  )}
                </div>
                {item.observedValue ? (
                  <pre className="font-mono text-[11px] text-[#e6edf3] whitespace-pre-wrap break-all">{item.observedValue}</pre>
                ) : (
                  <p className="text-xs text-[#ffaa40]">Présence non confirmée — aucune valeur brute n’est disponible dans les données analysées.</p>
                )}
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <Mini label="URL analysée" value={String(item.details.analyzedUrl || 'Non disponible')} />
                <Mini label="Code HTTP" value={String(item.details.httpStatus || 'Non disponible')} />
                <Mini label="Réponse finale" value={String(item.details.analyzedUrl || 'Non disponible')} />
                <Mini label="Date du contrôle" value={String(item.details.checkedAt || 'Non disponible')} />
                <Mini label="Source" value={String(item.details.source || 'Non disponible')} />
                <Mini label="Contrôle live" value={String(item.details.live || 'non')} />
              </div>
              {item.id === 'hsts' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <Mini label="max-age" value={String(item.details.maxAge || 'Non disponible')} />
                  <Mini label="includeSubDomains" value={item.details.includeSubDomains ? 'Oui' : 'Non'} />
                  <Mini label="preload" value={item.details.preload ? 'Oui' : 'Non'} />
                </div>
              )}
              {item.id === 'csp' && Array.isArray(item.details.findings) && (
                <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] mb-1">Analyse des directives</div>
                  {(item.details.findings as string[]).length === 0
                    ? <p className="text-xs text-[#8b949e]">Aucun point faible évident détecté automatiquement.</p>
                    : (
                      <ul className="space-y-1">
                        {(item.details.findings as string[]).map(f => (
                          <li key={f} className="text-xs text-[#ffaa40]">• {f}</li>
                        ))}
                      </ul>
                    )}
                </div>
              )}
              {item.id === 'permissions' && Array.isArray(item.details.features) && (
                <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
                  <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] mb-1">Fonctionnalités contrôlées</div>
                  {(item.details.features as string[]).length === 0
                    ? <p className="text-xs text-[#8b949e]">Aucune fonctionnalité parsée.</p>
                    : (
                      <ul className="space-y-1">
                        {(item.details.features as string[]).map(f => (
                          <li key={f} className="text-xs text-[#e6edf3]">• {f}</li>
                        ))}
                      </ul>
                    )}
                </div>
              )}
              <p className="text-[11px] text-[#8b949e] leading-relaxed">
                Routes testées côté moteur : page d’accueil HTTPS (réponse finale après redirections).
                Les contrôles multi-routes (404, API) s’affichent ici lorsqu’ils sont fournis par le backend.
              </p>
            </>
          )}

          {tab === 'recommend' && (
            <>
              <Block title="Recommandation" body={item.recommendation} />
              {item.conclusion && <Block title="Conclusion" body={item.conclusion} />}
              {item.id === 'hsts' && (
                <div className="rounded-xl border border-primary/20 bg-primary/5 px-3 py-2.5 space-y-1.5 text-xs text-[#c9d1d9]">
                  <div className="font-bold text-primary text-[10px] uppercase tracking-wider">Déploiement progressif</div>
                  <p>Étape 1 : max-age=300</p>
                  <p>Étape 2 : max-age=86400</p>
                  <p>Étape 3 : max-age=31536000</p>
                  <p>Étape 4 facultative : includeSubDomains et preload après validation de tous les sous-domaines.</p>
                  <p className="text-[#8b949e] pt-1">{String(item.details.note || '')}</p>
                </div>
              )}
              {item.kind === 'contextual' && (
                <div className="rounded-xl border border-[#a78bfa]/30 bg-[#a78bfa]/10 px-3 py-2 text-xs text-[#c4b5fd] leading-relaxed">
                  Ces protections sont contextuelles et leur absence ne constitue pas automatiquement une vulnérabilité.
                  Elles doivent être activées uniquement lorsque l’architecture et les fonctionnalités de l’application le nécessitent.
                  Impact sur le score principal : aucun.
                </div>
              )}
            </>
          )}

          {tab === 'config' && (
            <>
              <div className={`rounded-xl border px-3 py-2 text-xs ${
                item.kind === 'contextual'
                  ? 'border-[#a78bfa]/30 bg-[#a78bfa]/10 text-[#c4b5fd]'
                  : 'border-[#ffaa40]/30 bg-[#ffaa40]/10 text-[#ffaa40]'
              }`}>
                {item.kind === 'contextual'
                  ? 'Les extraits ci-dessous sont commentés volontairement. Ne les activez pas uniquement pour faire disparaître « Non configuré ».'
                  : 'Exemple générique : adaptez cette directive aux ressources et au fonctionnement réel de l’application avant de l’utiliser en production.'}
              </div>
              <div className="flex gap-1">
                {(['nginx', 'apache'] as const).map(s => (
                  <button key={s} type="button" onClick={() => setServerTab(s)}
                    className={`px-3 py-2 rounded-lg text-[10px] font-bold uppercase min-h-[40px] border ${
                      serverTab === s ? 'bg-primary/20 text-primary border-primary/30' : 'bg-white/5 text-[#8b949e] border-white/10'
                    }`}>
                    {s === 'nginx' ? 'Nginx' : 'Apache'}
                    {preferred.detected && preferred.server === s ? ' · détecté' : ''}
                  </button>
                ))}
              </div>
              <pre className="font-mono text-[10px] text-[#8b949e] bg-black/40 rounded-xl p-3 border border-white/[0.06] whitespace-pre-wrap break-all">{conf}</pre>
              <Mini label="Emplacement probable" value={item.configPathHint} />
              <Mini label="Commande de vérification" value={item.verifyCommand} />
              <Mini label="Validation / rechargement" value={item.reloadCommand[serverTab]} />
              <div className="flex flex-wrap gap-2">
                <button type="button" onClick={() => copyText(conf)}
                  className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-primary/30 text-primary">
                  Copier la configuration
                </button>
                <button type="button" onClick={() => copyText(item.verifyCommand)}
                  className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-primary/30 text-primary">
                  Copier la commande
                </button>
              </div>
            </>
          )}
        </div>
      </aside>
    </div>
  );

  return createPortal(panel, document.body);
};

function Block({ title, body }: { title: string; body: string }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
      <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] mb-1">{title}</div>
      <p className="text-xs text-[#e6edf3] leading-relaxed">{body}</p>
    </div>
  );
}

function Mini({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
      <div className="text-[10px] font-bold uppercase tracking-wider text-[#8b949e] mb-1">{label}</div>
      <div className="text-xs text-[#e6edf3] break-all">{value}</div>
    </div>
  );
}

export default SecurityHeaderDetailsDrawer;
