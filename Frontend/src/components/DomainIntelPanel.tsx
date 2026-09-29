import React, { useState } from 'react';
import {
  getCertTransparency,
  getDnsSecurity,
  type CertTransparencyResultDto,
  type DnsSecurityResultDto,
} from '../services/api';

interface DomainIntelPanelProps {
  domain: string;
}

function DnsChip({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-bold border ${
      ok ? 'bg-tertiary/10 text-tertiary border-tertiary/25' : 'bg-error/10 text-error border-error/25'
    }`}>
      <span className="material-symbols-outlined text-[14px]">{ok ? 'check_circle' : 'cancel'}</span>
      {label}
    </span>
  );
}

const DomainIntelPanel: React.FC<DomainIntelPanelProps> = ({ domain }) => {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ct, setCt] = useState<CertTransparencyResultDto | null>(null);
  const [dns, setDns] = useState<DnsSecurityResultDto | null>(null);

  const runCheck = async () => {
    const d = domain.trim();
    if (!d) return;
    setOpen(true);
    setLoading(true);
    setError(null);
    try {
      const [ctRes, dnsRes] = await Promise.all([getCertTransparency(d), getDnsSecurity(d)]);
      setCt(ctRes.data);
      setDns(dnsRes.data);
    } catch {
      setError("Impossible de récupérer l'intelligence du domaine.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mb-8 print:hidden">
      <button
        type="button"
        onClick={runCheck}
        disabled={!domain.trim() || loading}
        className="flex items-center gap-2 px-5 py-3 rounded-xl bg-surface-container border border-outline-variant/20 text-on-surface-variant hover:text-primary hover:border-primary/40 transition-all text-sm font-headline font-semibold disabled:opacity-40 disabled:cursor-not-allowed"
      >
        <span className="material-symbols-outlined text-base">{loading ? 'progress_activity' : 'radar'}</span>
        {loading ? 'Analyse en cours…' : 'Découvrir sous-domaines & sécurité DNS'}
      </button>

      {open && (
        <div className="mt-4 glass-panel rounded-3xl border border-outline-variant/[0.18] p-6 space-y-6">
          {loading ? (
            <div className="flex items-center gap-3 text-outline text-sm py-4">
              <span className="material-symbols-outlined animate-spin text-primary">progress_activity</span>
              Interrogation de crt.sh et des serveurs DNS…
            </div>
          ) : error ? (
            <p className="text-sm text-error">{error}</p>
          ) : (
            <>
              {/* Certificate Transparency */}
              {ct && (
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h3 className="font-headline text-base font-bold text-on-surface">
                        Sous-domaines découverts (Certificate Transparency)
                      </h3>
                      <p className="text-[11px] text-outline">
                        {ct.totalCertificates} sous-domaine{ct.totalCertificates > 1 ? 's' : ''} vu{ct.totalCertificates > 1 ? 's' : ''} dans les logs CT publics
                        {ct.unknownCount > 0 && (
                          <span className="text-amber-300 font-semibold"> · {ct.unknownCount} non surveillé{ct.unknownCount > 1 ? 's' : ''} par Vulnix</span>
                        )}
                      </p>
                    </div>
                  </div>
                  {ct.status === 'ERROR' ? (
                    <p className="text-sm text-error flex items-center gap-2">
                      <span className="material-symbols-outlined text-base">cloud_off</span>
                      crt.sh est temporairement indisponible — réessayez dans quelques instants.
                    </p>
                  ) : ct.subdomains.length === 0 ? (
                    <p className="text-sm text-outline">Aucun sous-domaine trouvé dans les logs CT.</p>
                  ) : (
                    <div className="max-h-64 overflow-y-auto space-y-1.5 pr-1">
                      {ct.subdomains.map((s) => (
                        <div
                          key={s.subdomain}
                          className={`flex items-center justify-between gap-3 rounded-xl border px-3 py-2 ${
                            s.knownAsset
                              ? 'border-outline-variant/[0.1] bg-surface-container/40'
                              : 'border-amber-300/25 bg-amber-300/5'
                          }`}
                        >
                          <div className="min-w-0">
                            <p className="text-xs font-semibold text-on-surface truncate">{s.subdomain}</p>
                            <p className="text-[10px] text-outline truncate">{s.issuer}</p>
                          </div>
                          <span className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-bold ${
                            s.knownAsset ? 'text-outline' : 'text-amber-300'
                          }`}>
                            {s.knownAsset ? 'Connu' : 'Non surveillé'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* DNS security */}
              {dns && (
                <div>
                  <h3 className="font-headline text-base font-bold text-on-surface mb-3">
                    Sécurité DNS
                  </h3>
                  <div className="flex flex-wrap gap-2 mb-3">
                    <DnsChip ok={dns.spfPresent} label={dns.spfPresent ? 'SPF présent' : 'SPF absent'} />
                    <DnsChip ok={dns.dmarcPresent} label={dns.dmarcPresent ? `DMARC présent (${dns.dmarcPolicy || '?'})` : 'DMARC absent'} />
                    {dns.caaStatus === 'READY' ? (
                      <DnsChip ok={dns.caaRecords.length > 0} label={dns.caaRecords.length > 0 ? 'CAA présent' : 'CAA absent'} />
                    ) : (
                      <span className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1 text-[11px] font-bold border bg-surface-container-high text-outline border-outline-variant/20">
                        <span className="material-symbols-outlined text-[14px]">help</span>
                        CAA non testable
                      </span>
                    )}
                  </div>
                  <div className="space-y-1.5 text-[11px] font-mono">
                    {dns.spfRecord && (
                      <p className="text-on-surface-variant break-all"><span className="text-outline">SPF:</span> {dns.spfRecord}</p>
                    )}
                    {dns.dmarcRecord && (
                      <p className="text-on-surface-variant break-all"><span className="text-outline">DMARC:</span> {dns.dmarcRecord}</p>
                    )}
                    {dns.caaRecords.map((c, i) => (
                      <p key={i} className="text-on-surface-variant break-all"><span className="text-outline">CAA:</span> {c}</p>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
};

export default DomainIntelPanel;
