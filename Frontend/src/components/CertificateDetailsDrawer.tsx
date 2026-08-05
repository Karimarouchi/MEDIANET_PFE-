import React, { useEffect, useId } from 'react';
import { createPortal } from 'react-dom';
import type {
  CertificateDetailDto,
  CertChainEntryDto,
  CertSanEntryDto,
  SslResultDto,
} from '../services/api';

export type CertDrawerSection =
  | 'validity'
  | 'identity'
  | 'crypto'
  | 'chain'
  | 'revocation'
  | 'compatibility'
  | 'usages'
  | 'evidence';

export type CertDrawerTab = 'detail' | 'raw' | 'evidence';

type Props = {
  open: boolean;
  onClose: () => void;
  section: CertDrawerSection;
  tab: CertDrawerTab;
  onTabChange: (t: CertDrawerTab) => void;
  detail: CertificateDetailDto;
  result: SslResultDto;
};

const na = (v: unknown) =>
  v === null || v === undefined || v === '' ? 'Non disponible' : String(v);

function copyText(text: string) {
  if (!text) return;
  navigator.clipboard?.writeText(text).catch(() => {});
}

function formatDate(iso?: string | null, withTime = true) {
  if (!iso) return 'Non disponible';
  try {
    const d = new Date(iso.includes('T') ? iso : iso.replace(' ', 'T') + (iso.includes('Z') ? '' : 'Z'));
    if (Number.isNaN(d.getTime())) return iso;
    return withTime ? d.toLocaleString('fr-FR') : d.toLocaleDateString('fr-FR');
  } catch {
    return iso;
  }
}

function chainTypeLabel(t?: string | null) {
  if (t === 'SERVER') return 'Certificat serveur';
  if (t === 'INTERMEDIATE') return 'Autorité intermédiaire';
  if (t === 'ROOT') return 'Autorité racine';
  return t || 'Certificat';
}

function chainIcon(t?: string | null) {
  if (t === 'SERVER') return 'language';
  if (t === 'INTERMEDIATE') return 'account_tree';
  if (t === 'ROOT') return 'account_balance';
  return 'description';
}

function sanRole(s: CertSanEntryDto, tested?: string | null) {
  const host = (tested || '').toLowerCase();
  const val = (s.value || '').toLowerCase();
  if (host && val === host) return 'Domaine analysé';
  if (s.matchStatus === 'NO_MATCH' && host && !host.endsWith(val.replace(/^\*\./, ''))) {
    // still covered by same cert if overall match
    return 'Domaine également protégé';
  }
  if (s.matchStatus === 'MATCH' || s.matchStatus === 'WILDCARD_MATCH') return 'Domaine analysé';
  return 'Domaine également protégé';
}

function Field({ label, value, copy }: { label: string; value: React.ReactNode; copy?: string }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5">
      <div className="flex items-center justify-between gap-2 mb-1">
        <div className="text-[10px] font-bold text-[#8b949e] uppercase tracking-wider">{label}</div>
        {copy && (
          <button type="button" onClick={() => copyText(copy)}
            className="text-[10px] font-bold text-primary hover:underline min-h-[28px]">
            Copier
          </button>
        )}
      </div>
      <div className="text-xs text-[#e6edf3] break-all">{value}</div>
    </div>
  );
}

function NameBlock({ title, n }: { title: string; n?: CertChainEntryDto['subject'] }) {
  if (!n) return <Field label={title} value="Non disponible" />;
  return (
    <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5 space-y-1 text-[#e6edf3]">
      <div className="text-[10px] font-bold text-[#8b949e] uppercase tracking-wider">{title}</div>
      <div className="text-xs text-[#e6edf3]">
        <span className="text-[#8b949e]">Organisation :</span> {na(n.organization)}
      </div>
      <div className="text-xs text-[#e6edf3]">
        <span className="text-[#8b949e]">Nom commun :</span> {na(n.commonName)}
      </div>
      <div className="text-xs text-[#e6edf3]">
        <span className="text-[#8b949e]">Pays :</span> {na(n.countryName || n.country)}
      </div>
      {n.rfc4514 && (
        <details className="pt-1">
          <summary className="text-[10px] font-bold text-primary cursor-pointer">Voir les données brutes</summary>
          <pre className="mt-1 font-mono text-[10px] text-[#8b949e] whitespace-pre-wrap">{n.rfc4514}</pre>
        </details>
      )}
    </div>
  );
}

const SECTION_TITLES: Record<CertDrawerSection, string> = {
  validity: 'Validité',
  identity: 'Identité et domaines',
  crypto: 'Cryptographie',
  chain: 'Chaîne de confiance',
  revocation: 'Révocation et transparence',
  compatibility: 'Compatibilité',
  usages: 'Usages autorisés',
  evidence: 'Preuves techniques',
};

const CertificateDetailsDrawer: React.FC<Props> = ({
  open, onClose, section, tab, onTabChange, detail, result,
}) => {
  const titleId = useId();

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

  if (!open) return null;

  const downloadPem = () => {
    if (!detail.leafPem) return;
    const blob = new Blob([detail.leafPem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${detail.commonName || result.domain || 'certificate'}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(detail, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificat-${detail.commonName || result.domain || 'detail'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderDetail = () => {
    switch (section) {
      case 'validity':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Cette vérification indique si le certificat est actuellement utilisable
              et permet d’anticiper son renouvellement.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="Émission (exacte)" value={formatDate(detail.notBefore)} />
              <Field label="Expiration (exacte)" value={formatDate(detail.notAfter)} />
              <Field label="Durée totale" value={detail.totalValidityDays != null ? `${detail.totalValidityDays} jours` : 'Non disponible'} />
              <Field label="% validité restante" value={detail.percentRemaining != null ? `${detail.percentRemaining}%` : 'Non disponible'} />
              <Field label="Jours restants" value={detail.daysRemaining != null ? String(detail.daysRemaining) : 'Non disponible'} />
              <Field label="Renouvellement recommandé" value={na(detail.recommendedRenewalDate)} />
              <Field label="Fuseau" value="UTC (valeurs X.509)" />
              <Field label="Méthode de recommandation" value="30 jours avant Not After" />
              <Field label="Not Before (brut)" value={na(detail.notBefore)} copy={detail.notBefore || undefined} />
              <Field label="Not After (brut)" value={na(detail.notAfter)} copy={detail.notAfter || undefined} />
            </div>
          </div>
        );
      case 'identity':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Cette vérification confirme que le certificat appartient bien au domaine
              analysé et indique les autres domaines qu’il protège.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="Nom commun (CN)" value={na(detail.commonName)} copy={detail.commonName || undefined} />
              <Field label="Domaine analysé" value={na(detail.testedHostname)} />
              <Field label="Correspondance globale" value={
                detail.hostnameMatch === 'MATCH' ? 'Domaine vérifié'
                  : detail.hostnameMatch === 'MISMATCH' ? 'Non correspondant'
                  : 'Non testé'
              } />
              <Field label="Wildcard" value={detail.wildcard == null ? 'Non disponible' : (detail.wildcard ? 'Présent' : 'Absent')} />
            </div>
            <div className="space-y-2">
              <div className="text-[10px] font-bold text-outline uppercase tracking-wider">Domaines SAN</div>
              {(detail.sans || []).length === 0 && <p className="text-xs text-outline italic">Non disponible</p>}
              {(detail.sans || []).map(s => (
                <div key={`${s.type}-${s.value}`} className="flex flex-wrap items-center gap-2 rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2">
                  <span className="text-[9px] font-mono uppercase text-[#8b949e]">{s.type}</span>
                  <span className="font-mono text-xs flex-1 break-all text-[#e6edf3]">{s.value}</span>
                  <span className="text-[10px] font-bold text-[#a4e6ff]">{sanRole(s, detail.testedHostname)}</span>
                  <button type="button" onClick={() => copyText(s.value)} className="text-[10px] font-bold text-primary min-h-[28px]">Copier</button>
                </div>
              ))}
            </div>
            {detail.chain?.[0] && (
              <div className="grid grid-cols-1 gap-2">
                <NameBlock title="Subject DN" n={detail.chain[0].subject} />
                <NameBlock title="Issuer DN" n={detail.chain[0].issuer} />
              </div>
            )}
          </div>
        );
      case 'crypto':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Cette section évalue la robustesse de la clé publique et de la signature
              utilisées par le certificat.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="Algorithme de clé publique" value={na(detail.publicKeyAlgorithm)} />
              <Field label="Type de clé" value={na(detail.keyType)} />
              <Field label="Courbe elliptique" value={na(detail.curveName)} />
              <Field label="Taille" value={detail.keySize != null ? `${detail.keySize} bits` : 'Non disponible'} />
              <Field label="Signature" value={na(detail.signatureAlgorithm)} />
              <Field label="Hachage" value={na(detail.hashAlgorithm)} />
              <Field label="Clé faible" value={detail.weakKey == null ? 'Non testé' : (detail.weakKey ? 'Oui' : 'Non')} />
              <Field label="Signature obsolète" value={detail.obsoleteSignature == null ? 'Non testé' : (detail.obsoleteSignature ? 'Oui' : 'Non')} />
              <Field label="Niveau" value={
                detail.securityLevel === 'FORT' ? 'Fort'
                  : detail.securityLevel === 'MOYEN' ? 'Moyen'
                  : detail.securityLevel === 'FAIBLE' ? 'Faible' : 'Inconnu'
              } />
              <Field label="Équivalence" value={
                detail.keyType === 'EC' && detail.keySize === 256
                  ? 'EC P-256 ≈ RSA 3072 bits (NIST)'
                  : detail.keyType === 'RSA' && (detail.keySize || 0) >= 2048
                    ? 'RSA ≥ 2048 bits — minimum actuel'
                    : 'Non disponible'
              } />
            </div>
          </div>
        );
      case 'chain':
        return (
          <div className="space-y-4">
            <p className="text-xs text-outline leading-relaxed">
              Cette vérification relie le certificat du site à une autorité racine
              reconnue par les navigateurs et les systèmes.
            </p>
            <div className="relative pl-4">
              <div className="absolute left-[19px] top-3 bottom-3 w-px bg-white/10" />
              {(detail.chain || []).map((entry, idx) => (
                <div key={idx} className="relative mb-3 last:mb-0">
                  <div className="absolute -left-4 top-3 w-6 h-6 rounded-full bg-surface-container-highest border border-primary/30 flex items-center justify-center z-10">
                    <span className="material-symbols-outlined text-[14px] text-primary">{chainIcon(entry.type)}</span>
                  </div>
                  <div className="ml-6 rounded-xl border border-white/[0.08] bg-black/25 p-3 space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[10px] font-bold uppercase tracking-wider text-primary">{chainTypeLabel(entry.type)}</span>
                      <span className="text-[10px] font-bold text-tertiary">{entry.status === 'EXPIRED' ? 'Expiré' : 'Valide'}</span>
                    </div>
                    <NameBlock title="Sujet" n={entry.subject} />
                    <NameBlock title="Émetteur" n={entry.issuer} />
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <Field label="Expiration" value={formatDate(entry.notAfter)} />
                      <Field label="Signature" value={na(entry.signatureAlgorithm)} />
                      <Field label="N° de série" value={na(entry.serialNumber)} copy={entry.serialNumber || undefined} />
                      <Field label="SHA-256" value={na(entry.sha256Fingerprint)} copy={entry.sha256Fingerprint || undefined} />
                    </div>
                  </div>
                </div>
              ))}
              {(!detail.chain || detail.chain.length === 0) && (
                <p className="text-xs text-outline italic ml-6">Chaîne non disponible</p>
              )}
            </div>
          </div>
        );
      case 'revocation':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Cette section recherche les mécanismes permettant de vérifier si le
              certificat a été révoqué et contrôle sa transparence publique.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="URL OCSP" value={detail.ocspUrl || (detail.ocspUrlStatus === 'NON_DETECTE' ? 'Non détectée' : 'Non testé')} copy={detail.ocspUrl || undefined} />
              <Field label="Réponse OCSP" value={
                detail.ocspResponseStatus === 'CONFORME' ? 'Vérifiée'
                  : detail.ocspResponseStatus === 'NON_DETECTE' ? 'Non détectée'
                  : detail.ocspResponseStatus === 'NON_TESTE' ? 'Non testé' : 'Inconclusif'
              } />
              <Field label="État de révocation" value={
                detail.revocationStatus === 'CONFORME' ? 'Vérifié (preuve OCSP)'
                  : detail.revocationStatus === 'NON_DETECTE' ? 'Non vérifié'
                  : detail.revocationStatus === 'NON_TESTE' ? 'Non testé' : 'Inconclusif'
              } />
              <Field label="OCSP Stapling" value={
                detail.ocspStaplingStatus === 'CONFORME' ? 'Actif'
                  : detail.ocspStaplingStatus === 'NON_DETECTE' ? 'Non détecté' : 'Non testé'
              } />
              <Field label="URL CRL" value={detail.crlUrl || (detail.crlUrlStatus === 'NON_DETECTE' ? 'Non détectée' : 'Non testé')} copy={detail.crlUrl || undefined} />
              <Field label="Certificate Transparency" value={
                detail.transparencyStatus === 'CONFORME' ? 'Présente' : detail.transparencyStatus === 'NON_DETECTE' ? 'Non détectée' : 'Non testé'
              } />
              <Field label="Nombre de SCT" value={detail.sctCount != null ? String(detail.sctCount) : 'Non disponible'} />
              <Field label="Journaux CT" value={na(detail.ctLogs)} />
              <Field label="Must-Staple" value={detail.mustStaple == null ? 'Non testé' : (detail.mustStaple ? 'Présent' : 'Absent')} />
              <Field label="Date du contrôle" value={formatDate(detail.scannedAt || result.sslyzeScanStarted)} />
            </div>
            <div className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2 text-[11px] text-outline leading-relaxed">
              Preuve : OCSP stapled {detail.ocspResponseStatus === 'CONFORME' ? 'présent' : 'absent'} · AIA OCSP {detail.ocspUrl ? 'présent' : 'absent'} · SCT={detail.sctCount ?? 'n/a'}
            </div>
          </div>
        );
      case 'compatibility':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Cette vérification estime si la chaîne du certificat est reconnue par les
              principaux navigateurs et systèmes d’exploitation.
            </p>
            <div className="space-y-2">
              {(detail.trustStores || []).map(ts => (
                <div key={ts.platform} className="rounded-xl border border-white/[0.06] bg-black/20 px-3 py-2.5 flex items-center justify-between gap-3">
                  <div>
                    <div className="text-sm font-bold text-on-surface">{ts.platform}</div>
                    <div className="text-[10px] text-outline">Version : {na(ts.storeVersion)}</div>
                    {ts.validationError && <div className="text-[10px] text-error mt-0.5">{ts.validationError}</div>}
                  </div>
                  <span className={`text-[10px] font-bold px-2 py-1 rounded-full ${
                    ts.status === 'TRUSTED' ? 'bg-tertiary/15 text-tertiary'
                      : ts.status === 'NOT_TRUSTED' ? 'bg-error/15 text-error'
                      : 'bg-outline/15 text-outline'
                  }`}>
                    {ts.status === 'TRUSTED' ? 'Reconnu' : ts.status === 'NOT_TRUSTED' ? 'Non reconnu' : 'Non testé'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        );
      case 'usages':
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Ces extensions précisent les opérations pour lesquelles le certificat
              peut être utilisé, notamment l’authentification d’un serveur HTTPS.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="Auth. serveur" value={detail.serverAuth == null ? 'Non testé' : (detail.serverAuth ? 'Autorisée' : 'Non autorisée')} />
              <Field label="Auth. client" value={detail.clientAuth == null ? 'Non testé' : (detail.clientAuth ? 'Autorisée' : 'Non autorisée / non déclarée')} />
              <Field label="Certificat final" value={detail.isCa == null ? 'Non testé' : (detail.isCa ? 'Non' : 'Oui')} />
              <Field label="Autorité de certification" value={detail.isCa == null ? 'Non testé' : (detail.isCa ? 'Oui' : 'Non')} />
              <Field label="Key Usage" value={!detail.keyUsage || detail.keyUsage === 'NON_TESTE' ? 'Non testé' : detail.keyUsage === 'NON_DETECTE' ? 'Non détecté' : detail.keyUsage} />
              <Field label="Extended Key Usage" value={!detail.extendedKeyUsage || detail.extendedKeyUsage === 'NON_TESTE' ? 'Non testé' : detail.extendedKeyUsage === 'NON_DETECTE' ? 'Non détecté' : detail.extendedKeyUsage} />
              <Field label="Basic Constraints" value={!detail.basicConstraints || detail.basicConstraints === 'NON_TESTE' ? 'Non testé' : detail.basicConstraints} />
            </div>
          </div>
        );
      case 'evidence':
      default:
        return (
          <div className="space-y-3">
            <p className="text-xs text-outline leading-relaxed">
              Ces données permettent de consulter la source exacte de chaque résultat
              et de vérifier la fiabilité de l’analyse.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              <Field label="Domaine testé" value={na(detail.endpoint || result.domain)} />
              <Field label="Adresse IP" value={na(detail.ip || result.sslyzeIpAddress)} />
              <Field label="Port" value={detail.port != null ? String(detail.port) : na(result.sslyzePort)} />
              <Field label="SNI" value={na(detail.sni || result.sslyzeSni)} />
              <Field label="Date du scan" value={formatDate(detail.scannedAt || result.sslyzeScanStarted)} />
              <Field label="Durée" value={na(detail.scanDuration)} />
              <Field label="Outil" value={na(detail.tool)} />
              <Field label="Version" value={na(detail.toolVersion || result.sslyzeVersion)} />
              <Field label="Confiance" value={na(detail.confidence)} />
              <Field label="Erreur" value={na(detail.validationError)} />
            </div>
          </div>
        );
    }
  };

  const panel = (
    <div
      className="fixed inset-0 z-[9999] flex justify-end"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
    >
      {/* Backdrop: floute toute la page derrière */}
      <button
        type="button"
        aria-label="Fermer le panneau"
        className="absolute inset-0 bg-black/65 backdrop-blur-md"
        onClick={onClose}
      />

      <aside
        className="relative z-10 flex h-[100dvh] max-h-[100dvh] w-full max-w-full sm:w-[min(560px,92vw)] flex-col bg-[#12141a] border-l border-outline-variant/20 shadow-2xl text-[#e6edf3]"
      >
        <header className="shrink-0 px-5 py-4 border-b border-outline-variant/15 flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="text-[10px] font-bold uppercase tracking-widest text-outline mb-1">Analyse certificat</div>
            <h2 id={titleId} className="font-headline font-bold text-lg text-on-surface truncate">{SECTION_TITLES[section]}</h2>
          </div>
          <button type="button" onClick={onClose} aria-label="Fermer"
            className="w-11 h-11 shrink-0 rounded-xl border border-outline-variant/20 flex items-center justify-center text-outline hover:text-on-surface hover:border-primary/30 transition-colors">
            <span className="material-symbols-outlined">close</span>
          </button>
        </header>

        <div className="shrink-0 px-5 pt-3 flex gap-1 border-b border-outline-variant/10 overflow-x-auto">
          {([
            ['detail', 'Vue détaillée'],
            ['raw', 'Données brutes'],
            ['evidence', 'Preuves'],
          ] as const).map(([id, label]) => (
            <button key={id} type="button"
              onClick={() => onTabChange(id)}
              className={`px-3 py-2.5 text-xs font-bold min-h-[44px] whitespace-nowrap border-b-2 transition-colors ${
                tab === id ? 'border-primary text-primary' : 'border-transparent text-outline hover:text-on-surface'
              }`}>
              {label}
            </button>
          ))}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto overscroll-contain px-5 py-4">
          {tab === 'detail' && renderDetail()}
          {tab === 'raw' && (
            <pre className="font-mono text-[10px] text-[#8b949e] bg-black/40 rounded-xl p-3 border border-outline-variant/15 whitespace-pre-wrap break-all">
              {JSON.stringify(detail, null, 2)}
            </pre>
          )}
          {tab === 'evidence' && (
            <div className="space-y-3">
              <p className="text-xs text-outline leading-relaxed">
                Ces données permettent de consulter la source exacte de chaque résultat
                et de vérifier la fiabilité de l’analyse.
              </p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                <Field label="Domaine testé" value={na(detail.endpoint || result.domain)} />
                <Field label="Adresse IP" value={na(detail.ip || result.sslyzeIpAddress)} />
                <Field label="Port" value={detail.port != null ? String(detail.port) : na(result.sslyzePort)} />
                <Field label="SNI" value={na(detail.sni || result.sslyzeSni)} />
                <Field label="Date du scan" value={formatDate(detail.scannedAt || result.sslyzeScanStarted)} />
                <Field label="Durée" value={na(detail.scanDuration)} />
                <Field label="Outil" value={na(detail.tool)} />
                <Field label="Version" value={na(detail.toolVersion || result.sslyzeVersion)} />
                <Field label="Confiance" value={na(detail.confidence)} />
                <Field label="Erreur" value={na(detail.validationError)} />
                <Field label="Empreinte SHA-256" value={na(detail.sha256Fingerprint)} copy={detail.sha256Fingerprint || undefined} />
                <Field label="N° de série" value={na(detail.serialNumber)} copy={detail.serialNumber || undefined} />
              </div>
            </div>
          )}
        </div>

        <footer className="shrink-0 px-5 py-3 border-t border-outline-variant/15 flex flex-wrap gap-2 bg-[#12141a]">
          <button type="button" disabled={!detail.sha256Fingerprint}
            onClick={() => copyText(detail.sha256Fingerprint || '')}
            className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-primary/30 text-primary disabled:opacity-40">
            Copier SHA-256
          </button>
          <button type="button" disabled={!detail.serialNumber}
            onClick={() => copyText(detail.serialNumber || '')}
            className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-primary/30 text-primary disabled:opacity-40">
            Copier série
          </button>
          <button type="button" disabled={!detail.leafPem} onClick={downloadPem}
            className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-tertiary/30 text-tertiary disabled:opacity-40">
            Télécharger PEM
          </button>
          <button type="button" onClick={exportJson}
            className="min-h-[44px] px-3 rounded-xl text-[11px] font-bold border border-outline-variant/20 text-on-surface-variant">
            Exporter JSON
          </button>
        </footer>
      </aside>
    </div>
  );

  return createPortal(panel, document.body);
};

export default CertificateDetailsDrawer;
