import React from 'react';
import type { SslResultDto } from '../services/api';

/** "CN=R11, O=Let's Encrypt, C=US" → "Let's Encrypt (R11)". */
export function issuerName(raw: string | null | undefined): string {
  if (!raw || raw === 'unknown') return 'Inconnu';
  const o = /(?:^|,\s*)O\s*=\s*([^,]+)/.exec(raw)?.[1]?.trim();
  const cn = /(?:^|,\s*)CN\s*=\s*([^,]+)/.exec(raw)?.[1]?.trim();
  if (o && cn && cn !== o) return `${o} (${cn})`;
  return o || cn || raw;
}

function formatDate(raw: string | null | undefined): string | null {
  if (!raw || raw === '—') return null;
  const d = new Date(raw);
  return Number.isNaN(d.getTime()) ? raw : d.toLocaleDateString('fr-FR', { day: '2-digit', month: 'long', year: 'numeric' });
}

/** The certificate in four lines: who issued it, until when, which names, which key. */
const SslCertificateBrief: React.FC<{ result: SslResultDto }> = ({ result }) => {
  const cd = result.certificateDetail;
  const sslyze = result.sslyzeStatus === 'READY';
  const days = sslyze && result.sslyzeDaysLeft != null ? result.sslyzeDaysLeft : (cd?.daysRemaining ?? result.certDaysLeft);
  const until = formatDate(cd?.notAfter || result.certNotAfterStr);
  const names = (cd?.sans ?? []).filter((s) => s.type?.toUpperCase().includes('DNS')).map((s) => s.value);
  const keyBits = sslyze && result.sslyzeKeySize > 0 ? result.sslyzeKeySize : (cd?.keySize ?? null);
  const keyType = (cd?.keyType || cd?.publicKeyAlgorithm || '').toUpperCase();
  const key = keyType.includes('EC') ? `ECDSA${cd?.curveName ? ` ${cd.curveName}` : ''}` : `RSA${keyBits ? ` ${keyBits} bits` : ''}`;
  const dayCls = days == null ? 'text-outline' : days < 0 ? 'text-error' : days <= 30 ? 'text-[#ffaa40]' : 'text-tertiary';

  const rows: Array<[string, React.ReactNode]> = [
    ['Émis par', issuerName(sslyze && result.sslyzeCertIssuer ? result.sslyzeCertIssuer : result.certIssuer)],
    ['Valide jusqu’au', (
      <span>
        {until ?? '—'}
        {days != null && <span className={`ml-2 font-semibold ${dayCls}`}>{days < 0 ? `expiré depuis ${-days} j` : `encore ${days} j`}</span>}
      </span>
    )],
    ['Domaines couverts', names.length > 0 ? `${names.slice(0, 4).join(', ')}${names.length > 4 ? ` et ${names.length - 4} autre(s)` : ''}`
      : result.certSansCount ? `${result.certSansCount} nom(s)` : '—'],
    ['Clé', key],
  ];

  return (
    <div className="rounded-2xl bg-surface-container p-5">
      <div className="flex items-center gap-2 mb-3">
        <span className="material-symbols-outlined text-base text-primary">verified</span>
        <h2 className="font-headline font-bold text-sm text-on-surface">Certificat</h2>
      </div>
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
        {rows.map(([label, value]) => (
          <div key={label} className="flex gap-2 min-w-0">
            <dt className="w-32 shrink-0 text-outline">{label}</dt>
            <dd className="min-w-0 text-on-surface break-words">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
};

export default SslCertificateBrief;
