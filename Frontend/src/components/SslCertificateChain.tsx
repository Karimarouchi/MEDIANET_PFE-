import React from 'react';
import type { CertChainEntryDto, SslResultDto } from '../services/api';

const ROLE: Record<string, string> = {
  SERVER: 'Certificat du site',
  INTERMEDIATE: 'Autorité intermédiaire',
  ROOT: 'Autorité racine',
};

const STATUS: Record<string, { label: string; cls: string }> = {
  VALID: { label: 'Valide', cls: 'bg-tertiary/15 text-tertiary' },
  EXPIRED: { label: 'Expiré', cls: 'bg-error/15 text-error' },
  NOT_YET_VALID: { label: 'Pas encore valide', cls: 'bg-error/15 text-error' },
};

function nameOf(n: CertChainEntryDto['subject']): string {
  return n?.commonName || n?.organization || n?.rfc4514 || '—';
}

/** One sentence: is the chain the browsers need complete, and what to do when it is not. */
export function chainVerdict(result: SslResultDto): { ok: boolean | null; text: string } {
  const d = result.certificateDetail;
  const chain = d?.chain ?? [];
  if (d?.selfSigned) return { ok: false, text: 'Certificat auto-signé : aucune autorité reconnue ne le garantit.' };
  if (chain.some((c) => c.status === 'EXPIRED')) {
    return { ok: false, text: 'Un maillon de la chaîne est expiré : remplacez le certificat ou servez la chaîne à jour (fullchain).' };
  }
  if (d?.chainComplete === false || result.chainComplete === false) {
    return { ok: false, text: 'Il manque un certificat intermédiaire : certains téléphones et outils refuseront le site. Servez le fichier fullchain.pem.' };
  }
  if (chain.length === 0) return { ok: null, text: 'Chaîne non relevée pendant ce scan.' };
  return { ok: true, text: 'Chaîne complète : tous les navigateurs peuvent remonter jusqu’à une autorité qu’ils connaissent.' };
}

/**
 * The certificate chain only (site → intermediate(s) → root): the one certificate detail that is not shown anywhere
 * else, and the one to look at when the site works on a computer but not on a phone or in a tool.
 */
const SslCertificateChain: React.FC<{ result: SslResultDto }> = ({ result }) => {
  const chain = result.certificateDetail?.chain ?? [];
  const verdict = chainVerdict(result);
  const color = verdict.ok === true ? 'text-tertiary' : verdict.ok === false ? 'text-error' : 'text-outline';
  return (
    <div className="bg-surface-container rounded-2xl p-5 space-y-3">
      <div>
        <h2 className="font-headline font-bold text-sm flex items-center gap-2 mb-1">
          <span className="material-symbols-outlined text-primary text-base">link</span>
          Chaîne de confiance du certificat
        </h2>
        <p className="text-xs text-outline leading-relaxed">
          Qui garantit le certificat du site, maillon par maillon. À regarder quand le site marche sur un ordinateur
          mais pas sur un téléphone ou dans un outil.
        </p>
      </div>
      <p className={`text-xs font-semibold ${color}`}>{verdict.text}</p>
      {chain.length > 0 && (
        <ol className="space-y-2">
          {chain.map((c, i) => {
            const st = STATUS[c.status ?? ''] ?? { label: c.status || '—', cls: 'bg-surface-variant text-on-surface-variant' };
            return (
              <li key={`${c.sha256Fingerprint ?? i}`} className="flex items-start gap-3 rounded-xl border border-outline-variant/[0.12] bg-surface-container-low px-3 py-2">
                <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 text-[11px] font-bold text-primary">{i + 1}</span>
                <div className="min-w-0 flex-1 text-xs">
                  <p className="text-[10px] uppercase tracking-wider text-outline">{ROLE[c.type] ?? c.type}</p>
                  <p className="font-semibold text-on-surface break-words">{nameOf(c.subject)}</p>
                  {c.type !== 'ROOT' && <p className="text-outline">signé par {nameOf(c.issuer)}</p>}
                </div>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-bold ${st.cls}`}>{st.label}</span>
              </li>
            );
          })}
        </ol>
      )}
    </div>
  );
};

export default SslCertificateChain;
