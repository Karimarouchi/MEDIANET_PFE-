import React, { useMemo, useState } from 'react';
import type { CertificateDetailDto, SslResultDto } from '../services/api';
import CertificateDetailsDrawer, {
  type CertDrawerSection,
  type CertDrawerTab,
} from './CertificateDetailsDrawer';

type Props = {
  result: SslResultDto;
  certificateScore: number;
};

type BadgeKind = 'valid' | 'ok' | 'info' | 'watch' | 'critical' | 'untested' | 'undetected' | 'na';

const BADGE_META: Record<BadgeKind, { label: string; icon: string; cls: string; tip: string }> = {
  valid: {
    label: 'Valide', icon: 'verified_user',
    cls: 'bg-tertiary/12 text-tertiary border-tertiary/25',
    tip: 'Le certificat est actuellement dans sa période de validité.',
  },
  ok: {
    label: 'Conforme', icon: 'check_circle',
    cls: 'bg-tertiary/12 text-tertiary border-tertiary/25',
    tip: 'La vérification a été effectuée et aucun problème n’a été détecté.',
  },
  info: {
    label: 'Information', icon: 'info',
    cls: 'bg-[#a4e6ff]/12 text-[#a4e6ff] border-[#a4e6ff]/25',
    tip: 'Cette donnée est informative et ne représente pas un risque.',
  },
  watch: {
    label: 'À surveiller', icon: 'warning',
    cls: 'bg-[#ffaa40]/12 text-[#ffaa40] border-[#ffaa40]/25',
    tip: 'Aucun danger immédiat, mais une amélioration est recommandée.',
  },
  critical: {
    label: 'Critique', icon: 'cancel',
    cls: 'bg-error/12 text-error border-error/25',
    tip: 'Un problème important nécessite une correction rapide.',
  },
  untested: {
    label: 'Non testé', icon: 'help',
    cls: 'bg-outline/10 text-outline border-outline/20',
    tip: 'Cette vérification n’a pas été exécutée par le moteur d’analyse.',
  },
  undetected: {
    label: 'Non détecté', icon: 'search_off',
    cls: 'bg-slate-500/15 text-slate-300 border-slate-500/25',
    tip: 'Le scanner a recherché cette information mais ne l’a pas trouvée.',
  },
  na: {
    label: 'Non disponible', icon: 'remove',
    cls: 'bg-white/5 text-outline border-white/10',
    tip: 'Cette information n’est pas présente dans les données analysées.',
  },
};

function StatusBadge({ kind, label }: { kind: BadgeKind; label?: string }) {
  const m = BADGE_META[kind];
  return (
    <span
      title={m.tip}
      className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-1 rounded-full border ${m.cls}`}
    >
      <span className="material-symbols-outlined text-[13px]" style={{ fontVariationSettings: "'FILL' 1" }}>{m.icon}</span>
      {label || m.label}
    </span>
  );
}

function formatDateShort(iso?: string | null) {
  if (!iso) return 'Non disponible';
  try {
    const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + 'Z');
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
  } catch {
    return iso;
  }
}

function issuerOrg(detail: CertificateDetailDto, result: SslResultDto) {
  const fromChain = detail.chain?.[0]?.issuer?.organization
    || detail.chain?.[0]?.issuer?.commonName;
  if (fromChain) return fromChain;
  const raw = result.sslyzeCertIssuer || result.certIssuer || '';
  const m = raw.match(/O=([^,]+)/i);
  return m?.[1] || raw.replace(/^CN=/, '') || 'Non disponible';
}

function validityBadge(detail: CertificateDetailDto): { kind: BadgeKind; label: string } {
  const days = detail.daysRemaining;
  if (detail.expired || detail.validityStatus === 'EXPIRED' || (days != null && days < 0)) {
    return { kind: 'critical', label: 'Critique' };
  }
  if (detail.validityStatus === 'EXPIRING_CRITICAL' || (days != null && days < 15)) {
    return { kind: 'critical', label: 'Attention' };
  }
  if (detail.validityStatus === 'EXPIRING_SOON' || (days != null && days <= 30)) {
    return { kind: 'watch', label: 'À surveiller' };
  }
  if (detail.validityStatus === 'VALID') return { kind: 'valid', label: 'Valide' };
  return { kind: 'untested', label: 'Non testé' };
}

function AnalysisCard({
  icon, title, utility, badge, children, actionLabel, onAction, ariaExpanded,
}: {
  icon: string;
  title: string;
  utility: string;
  badge: React.ReactNode;
  children: React.ReactNode;
  actionLabel: string;
  onAction: () => void;
  ariaExpanded: boolean;
}) {
  return (
    <article className="rounded-xl border border-outline-variant/20 bg-surface-container-low p-4 flex flex-col min-h-[200px]">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-start gap-3">
          <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
            <span className="material-symbols-outlined text-primary text-lg">{icon}</span>
          </div>
          <div>
            <h3 className="font-headline font-bold text-sm text-on-surface">{title}</h3>
            <p className="text-[11px] text-outline leading-relaxed mt-1">{utility}</p>
          </div>
        </div>
        {badge}
      </div>
      <div className="flex-1 space-y-2 text-sm text-on-surface mb-4">{children}</div>
      <button
        type="button"
        onClick={onAction}
        aria-expanded={ariaExpanded}
        className="mt-auto self-start min-h-[44px] px-3 py-1.5 rounded-xl text-xs font-bold text-primary border border-primary/25 hover:bg-primary/10 transition-colors"
      >
        {actionLabel}
      </button>
    </article>
  );
}

const CertificateDetailSection: React.FC<Props> = ({ result, certificateScore }) => {
  const detail = useMemo<CertificateDetailDto>(() => result.certificateDetail || {
    validityStatus: result.certExpired ? 'EXPIRED' : 'UNKNOWN',
    daysRemaining: result.certDaysLeft,
    expired: result.certExpired,
    commonName: result.certSubject,
    chainComplete: result.chainComplete,
    transparencyStatus: result.certTransparency ? 'CONFORME' : 'NON_DETECTE',
    ocspStaplingStatus: (result.ocspStapling || result.sslyzeOcspStapling) ? 'CONFORME' : 'NON_DETECTE',
    revocationStatus: 'NON_TESTE',
    sans: [],
    chain: [],
    trustStores: [],
    confidence: result.sslyzeStatus === 'READY' ? 'Haute' : 'Faible',
  }, [result]);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [section, setSection] = useState<CertDrawerSection>('validity');
  const [tab, setTab] = useState<CertDrawerTab>('detail');

  const openDrawer = (s: CertDrawerSection, t: CertDrawerTab = 'detail') => {
    setSection(s);
    setTab(t);
    setDrawerOpen(true);
  };

  const vBadge = validityBadge(detail);
  const days = detail.daysRemaining;
  const pct = detail.percentRemaining != null
    ? Math.max(0, Math.min(100, detail.percentRemaining))
    : (days != null && days > 0 ? Math.min(100, Math.round(days / 90 * 100)) : 0);
  const barColor = vBadge.kind === 'critical' ? '#ffb4ab' : vBadge.kind === 'watch' ? '#ffaa40' : '#00fc92';

  const cryptoStrong = detail.securityLevel === 'FORT' && !detail.weakKey && !detail.obsoleteSignature;
  const domainOk = detail.hostnameMatch === 'MATCH';
  const chainOk = detail.chainComplete === true;
  const trustedCount = (detail.trustStores || []).filter(t => t.status === 'TRUSTED').length;
  const trustTotal = (detail.trustStores || []).length || 5;
  const trustAllTested = (detail.trustStores || []).every(t => t.status === 'TRUSTED' || t.status === 'NOT_TRUSTED');

  const revWatch =
    detail.transparencyStatus === 'CONFORME'
    && (detail.revocationStatus === 'NON_DETECTE' || detail.ocspStaplingStatus === 'NON_DETECTE');

  const conclusion = (() => {
    if (detail.expired) return 'Le certificat est expiré. Les navigateurs modernes rejettent la connexion.';
    if (!domainOk && detail.hostnameMatch === 'MISMATCH') {
      return 'Le certificat ne correspond pas au domaine analysé.';
    }
    if (chainOk && domainOk && !detail.expired) {
      return 'Le certificat correspond au domaine analysé, sa chaîne de confiance est complète et aucun problème critique n’a été détecté.';
    }
    return 'L’analyse du certificat présente des points à vérifier dans le détail.';
  })();

  const compactChain = (detail.chain || []).filter((c, i, arr) => {
    if (c.type === 'SERVER') return true;
    if (c.type === 'ROOT') return true;
    // keep first intermediate only for compact view if many
    if (c.type === 'INTERMEDIATE') {
      return arr.findIndex(x => x.type === 'INTERMEDIATE') === i;
    }
    return i < 3;
  });

  const previewSans = (detail.sans || []).slice(0, 3);

  return (
    <div className="bg-surface-container rounded-2xl p-5 space-y-5">
      <div>
        <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-primary text-lg">shield_lock</span>
          Certificat SSL/TLS
        </h2>
        <p className="text-xs text-outline">
          Cette analyse vérifie l’identité du site, la période de validité du
          certificat et la confiance accordée par les navigateurs.
        </p>
      </div>

      {/* ── Synthèse ─────────────────────────────────────────────── */}
      <section className="rounded-xl border border-primary/20 bg-surface-container-low p-4">
        <div className="flex flex-col lg:flex-row lg:items-stretch gap-5">
          <div className="flex-1 min-w-0">
            <div className="text-[10px] font-bold text-primary uppercase tracking-widest mb-3">Synthèse</div>
            <div className={`text-base font-headline font-bold ${
              vBadge.kind === 'critical' ? 'text-error' : vBadge.kind === 'watch' ? 'text-[#ffaa40]' : 'text-tertiary'
            }`}>
              {detail.expired ? 'Certificat expiré' : domainOk ? 'Certificat valide' : 'Certificat à vérifier'}
            </div>
            <div className="text-sm text-on-surface mt-1">
              <span className="font-bold">{detail.commonName || detail.testedHostname || result.domain}</span>
              <span className="text-outline"> · Émis par {issuerOrg(detail, result)}</span>
            </div>
            <p className="text-xs text-on-surface-variant mt-2 leading-relaxed">{conclusion}</p>

            <div className="flex flex-wrap gap-1.5 mt-3">
              {vBadge.kind === 'valid' && <StatusBadge kind="valid" />}
              {domainOk && <StatusBadge kind="ok" label="Domaine vérifié" />}
              {chainOk && <StatusBadge kind="ok" label="Chaîne complète" />}
              {cryptoStrong && <StatusBadge kind="ok" label="Cryptographie forte" />}
            </div>

            <p className="text-[11px] text-outline mt-3">
              Analyse effectuée avec {detail.tool || 'SSLyze'} et OpenSSL
              {detail.confidence ? ` · Confiance ${detail.confidence.toLowerCase() === 'haute' ? 'élevée' : detail.confidence.toLowerCase()}` : ''}
            </p>
          </div>

          <div className="lg:w-48 shrink-0 rounded-xl border border-outline-variant/20 bg-surface-container-highest/40 p-4 flex flex-col items-center justify-center text-center gap-1.5">
            <div className="text-[10px] font-bold uppercase tracking-widest text-outline">Score certificat</div>
            <div className="text-3xl font-headline font-extrabold text-primary">{certificateScore}<span className="text-base text-outline">/25</span></div>
            <div className="text-sm font-bold text-on-surface">
              {days != null ? `${days} jours restants` : 'Durée inconnue'}
            </div>
            <div className="text-[11px] text-outline">
              Confiance {detail.confidence?.toLowerCase() === 'haute' ? 'élevée' : (detail.confidence?.toLowerCase() || '—')}
            </div>
            <button
              type="button"
              onClick={() => openDrawer('evidence', 'detail')}
              className="mt-2 w-full min-h-[44px] rounded-xl bg-primary/15 border border-primary/30 text-primary text-xs font-bold hover:bg-primary/25 transition-colors"
            >
              Voir l’analyse complète
            </button>
          </div>
        </div>
      </section>

      {/* ── Main 2×2 grid ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <AnalysisCard
          icon="event_available"
          title="Validité du certificat"
          utility="Cette vérification indique si le certificat est actuellement utilisable et permet d’anticiper son renouvellement avant son expiration."
          badge={<StatusBadge kind={vBadge.kind} label={vBadge.label} />}
          actionLabel="Plus de détails"
          onAction={() => openDrawer('validity')}
          ariaExpanded={drawerOpen && section === 'validity'}
        >
          <div className="text-2xl font-headline font-extrabold text-on-surface">
            {days != null ? `${days} jours restants` : 'Non disponible'}
          </div>
          <div className="h-1.5 w-full bg-surface-container-highest rounded-full overflow-hidden mt-1">
            <div className="h-full rounded-full" style={{ width: `${pct}%`, background: barColor }} />
          </div>
          <div className="text-xs text-outline pt-1">Émis le {formatDateShort(detail.notBefore)}</div>
          <div className="text-xs text-outline">Expire le {formatDateShort(detail.notAfter)}</div>
          <div className="text-xs text-on-surface-variant">Renouvellement conseillé {detail.recommendedRenewalDate || '—'}</div>
        </AnalysisCard>

        <AnalysisCard
          icon="fingerprint"
          title="Identité et domaines protégés"
          utility="Cette vérification confirme que le certificat appartient bien au domaine analysé et indique les noms de domaine qu’il protège."
          badge={
            domainOk ? <StatusBadge kind="ok" label="Domaine vérifié" />
              : detail.hostnameMatch === 'MISMATCH' ? <StatusBadge kind="critical" label="Non correspondant" />
              : <StatusBadge kind="untested" />
          }
          actionLabel="Voir tous les domaines"
          onAction={() => openDrawer('identity')}
          ariaExpanded={drawerOpen && section === 'identity'}
        >
          <div className="text-xs text-outline">Domaine principal</div>
          <div className="font-bold text-on-surface">{detail.commonName || 'Non disponible'}</div>
          <div className="text-xs text-outline mt-2">Domaine analysé</div>
          <div className="text-sm text-on-surface">{detail.testedHostname || result.domain}</div>
          <div className="text-xs text-outline mt-3 mb-1">
            {(detail.sans?.length ?? 0) > 0 ? `${detail.sans!.length} domaines protégés` : 'SAN non disponible'}
          </div>
          <ul className="space-y-1">
            {previewSans.map(s => (
              <li key={s.value} className="flex items-center gap-1.5 text-xs text-on-surface">
                <span className="material-symbols-outlined text-tertiary text-[14px]">check</span>
                <span className="font-mono">{s.value}</span>
              </li>
            ))}
          </ul>
          <div className="text-[11px] text-outline pt-1">
            Wildcard : {detail.wildcard == null ? 'Non disponible' : (detail.wildcard ? 'présent' : 'absent')}
          </div>
        </AnalysisCard>

        <AnalysisCard
          icon="encrypted"
          title="Sécurité cryptographique"
          utility="Cette section évalue la robustesse de la clé publique et de la signature utilisées pour protéger l’authenticité du certificat."
          badge={
            cryptoStrong ? <StatusBadge kind="ok" label="Cryptographie forte" />
              : detail.securityLevel === 'FAIBLE' || detail.weakKey || detail.obsoleteSignature
                ? <StatusBadge kind="critical" />
                : detail.securityLevel === 'MOYEN' ? <StatusBadge kind="watch" />
                : <StatusBadge kind="untested" />
          }
          actionLabel="Plus de détails"
          onAction={() => openDrawer('crypto')}
          ariaExpanded={drawerOpen && section === 'crypto'}
        >
          <div className="text-xs text-outline">Clé publique</div>
          <div className="font-bold">
            {[detail.keyType, detail.curveName || (detail.keySize != null ? `${detail.keySize} bits` : null)]
              .filter(Boolean).join(' ') || 'Non disponible'}
          </div>
          <div className="text-xs text-outline mt-2">Signature</div>
          <div className="text-sm">{detail.signatureAlgorithm || 'Non disponible'}</div>
          <div className="text-xs text-outline mt-2">Niveau de sécurité</div>
          <div className="font-bold text-tertiary">
            {detail.securityLevel === 'FORT' ? 'Fort'
              : detail.securityLevel === 'MOYEN' ? 'Moyen'
              : detail.securityLevel === 'FAIBLE' ? 'Faible' : 'Inconnu'}
          </div>
        </AnalysisCard>

        <AnalysisCard
          icon="account_tree"
          title="Chaîne de confiance"
          utility="Cette vérification s’assure que le certificat du site peut être relié à une autorité racine reconnue par les navigateurs et les systèmes."
          badge={
            chainOk && detail.rootRecognized !== false
              ? <StatusBadge kind="ok" label="Chaîne vérifiée" />
              : detail.chainComplete === false ? <StatusBadge kind="critical" label="Chaîne incomplète" />
              : <StatusBadge kind="untested" />
          }
          actionLabel="Voir la chaîne complète"
          onAction={() => openDrawer('chain')}
          ariaExpanded={drawerOpen && section === 'chain'}
        >
          <div className="space-y-1 py-1">
            {compactChain.length === 0 && <p className="text-xs text-outline italic">Non disponible</p>}
            {compactChain.map((c, i) => (
              <div key={i}>
                <div className="text-xs">
                  <span className="font-bold text-on-surface">{c.subject?.commonName || '—'}</span>
                  <span className="text-outline"> · {
                    c.type === 'SERVER' ? 'Certificat serveur'
                      : c.type === 'ROOT' ? 'Autorité racine' : 'Autorité intermédiaire'
                  }</span>
                </div>
                {i < compactChain.length - 1 && <div className="text-outline/50 text-center text-[10px] leading-none py-0.5">↓</div>}
              </div>
            ))}
          </div>
          <div className="text-[11px] text-outline pt-1">
            {(detail.chain?.length || 0)} certificats
            {chainOk ? ' · Chaîne complète' : ''}
            {detail.rootRecognized ? ' · Racine reconnue' : ''}
            {detail.chainOrderValid ? ' · Ordre correct' : ''}
          </div>
        </AnalysisCard>
      </div>

      {/* ── Secondary row ────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <AnalysisCard
          icon="policy"
          title="Révocation et transparence"
          utility="Cette vérification recherche les mécanismes permettant de savoir si le certificat a été révoqué et confirme sa présence dans les journaux publics de transparence."
          badge={
            revWatch ? <StatusBadge kind="watch" />
              : detail.transparencyStatus === 'CONFORME' && detail.revocationStatus === 'CONFORME'
                ? <StatusBadge kind="ok" />
                : detail.revocationStatus === 'NON_TESTE' ? <StatusBadge kind="untested" />
                : <StatusBadge kind="watch" />
          }
          actionLabel="Plus de détails"
          onAction={() => openDrawer('revocation')}
          ariaExpanded={drawerOpen && section === 'revocation'}
        >
          <div className="text-xs">
            <span className="text-outline">Transparence du certificat</span>
            <div className="font-bold mt-0.5">
              {detail.transparencyStatus === 'CONFORME'
                ? `Présente · ${detail.sctCount ?? 0} SCT`
                : detail.transparencyStatus === 'NON_DETECTE' ? 'Non détectée' : 'Non testée'}
            </div>
          </div>
          <div className="text-xs mt-2">
            <span className="text-outline">OCSP Stapling</span>
            <div className="font-bold mt-0.5">
              {detail.ocspStaplingStatus === 'CONFORME' ? 'Actif'
                : detail.ocspStaplingStatus === 'NON_DETECTE' ? 'Non détecté' : 'Non testé'}
            </div>
          </div>
          <div className="text-xs mt-2">
            <span className="text-outline">État de révocation</span>
            <div className="font-bold mt-0.5">
              {detail.revocationStatus === 'CONFORME' ? 'Vérifié'
                : detail.revocationStatus === 'NON_DETECTE' ? 'Non vérifié'
                : detail.revocationStatus === 'NON_TESTE' ? 'Non testé' : 'Inconclusif'}
            </div>
          </div>
          <p className="text-[11px] text-outline leading-relaxed pt-1">
            {detail.transparencyStatus === 'CONFORME'
              ? 'La transparence du certificat est conforme. La vérification de révocation n’a pas fourni de réponse concluante.'
              : 'Consultez le détail pour les preuves OCSP, CRL et CT.'}
          </p>
        </AnalysisCard>

        <AnalysisCard
          icon="devices"
          title="Compatibilité des navigateurs"
          utility="Cette vérification estime si la chaîne du certificat est reconnue par les principaux systèmes et navigateurs."
          badge={
            trustAllTested && trustedCount === trustTotal
              ? <StatusBadge kind="ok" label="Largement reconnu" />
              : trustAllTested && trustedCount > 0
                ? <StatusBadge kind="watch" />
                : <StatusBadge kind="untested" />
          }
          actionLabel="Voir la compatibilité"
          onAction={() => openDrawer('compatibility')}
          ariaExpanded={drawerOpen && section === 'compatibility'}
        >
          <div className="font-bold text-on-surface">
            {trustAllTested
              ? `${trustedCount} environnement${trustedCount > 1 ? 's' : ''} reconnu${trustedCount > 1 ? 's' : ''} sur ${trustTotal}`
              : 'Non testé'}
          </div>
          <div className="flex flex-wrap gap-2 mt-3">
            {(detail.trustStores || [
              { platform: 'Android', status: 'NOT_TESTED' },
              { platform: 'Apple', status: 'NOT_TESTED' },
              { platform: 'Java', status: 'NOT_TESTED' },
              { platform: 'Mozilla', status: 'NOT_TESTED' },
              { platform: 'Windows', status: 'NOT_TESTED' },
            ]).map(ts => (
              <div key={ts.platform}
                title={ts.status === 'TRUSTED' ? 'Reconnu' : ts.status === 'NOT_TRUSTED' ? 'Non reconnu' : 'Non testé'}
                className={`w-9 h-9 rounded-lg border flex items-center justify-center text-[9px] font-bold ${
                  ts.status === 'TRUSTED' ? 'border-tertiary/40 text-tertiary bg-tertiary/10'
                    : ts.status === 'NOT_TRUSTED' ? 'border-error/40 text-error bg-error/10'
                    : 'border-outline-variant/20 text-outline bg-surface-container-highest/40'
                }`}>
                {ts.platform.slice(0, 3)}
              </div>
            ))}
          </div>
        </AnalysisCard>
      </div>

      {/* ── Evidence link ────────────────────────────────────────── */}
      <div className="flex justify-start">
        <button
          type="button"
          onClick={() => openDrawer('evidence', 'evidence')}
          className="text-xs font-bold text-outline hover:text-primary transition-colors inline-flex items-center gap-1.5 min-h-[44px]"
        >
          <span className="material-symbols-outlined text-base">science</span>
          Voir les preuves techniques
        </button>
      </div>

      <CertificateDetailsDrawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        section={section}
        tab={tab}
        onTabChange={setTab}
        detail={detail}
        result={result}
      />
    </div>
  );
};

export default CertificateDetailSection;
