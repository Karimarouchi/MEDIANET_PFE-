import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createCiToken,
  listCiTokens,
  revokeCiToken,
  type CiTokenCreatedDto,
  type CiTokenDto,
} from '../services/api';

type Props = {
  clientId: number;
  repositoryIds: number[];
  repositoryUrls: string[];
};

const CiTokenSection: React.FC<Props> = ({ clientId, repositoryIds, repositoryUrls }) => {
  const [tokens, setTokens] = useState<CiTokenDto[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [name, setName] = useState('GitHub Actions');
  const [expiresInDays, setExpiresInDays] = useState('90');
  const [selectedRepoIds, setSelectedRepoIds] = useState<number[]>([]);
  const [created, setCreated] = useState<CiTokenCreatedDto | null>(null);
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);

  const repoOptions = useMemo(
    () => repositoryIds.map((id, index) => ({ id, url: repositoryUrls[index] ?? `Dépôt #${id}` })),
    [repositoryIds, repositoryUrls],
  );

  const loadTokens = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await listCiTokens(clientId);
      setTokens(res.data);
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || 'Impossible de charger les jetons CI.');
    } finally {
      setLoading(false);
    }
  }, [clientId]);

  useEffect(() => {
    loadTokens();
  }, [loadTokens]);

  useEffect(() => {
    setSelectedRepoIds(repositoryIds);
  }, [repositoryIds]);

  const toggleRepo = (id: number) => {
    setSelectedRepoIds((prev) => (prev.includes(id) ? prev.filter((entry) => entry !== id) : [...prev, id]));
  };

  const handleCreate = async () => {
    setError(null);
    setMessage(null);
    setCopied(false);
    if (!selectedRepoIds.length) {
      setError('Sélectionnez au moins un dépôt lié à ce projet.');
      return;
    }
    setSaving(true);
    try {
      const res = await createCiToken({
        name,
        clientId,
        repositoryIds: selectedRepoIds,
        expiresInDays: Number(expiresInDays),
      });
      setCreated(res.data);
      setMessage('Jeton créé. Copiez-le maintenant — il ne sera plus affiché.');
      await loadTokens();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || 'Création du jeton impossible.');
    } finally {
      setSaving(false);
    }
  };

  const handleCopy = async () => {
    if (!created?.token) return;
    try {
      await navigator.clipboard.writeText(created.token);
      setCopied(true);
    } catch {
      setError('Copie automatique impossible — sélectionnez le jeton manuellement.');
    }
  };

  const handleRevoke = async (id: number) => {
    if (!window.confirm('Révoquer ce jeton ? Les pipelines GitHub qui l’utilisent recevront un 401.')) {
      return;
    }
    setError(null);
    setMessage(null);
    try {
      await revokeCiToken(id);
      if (created?.id === id) {
        setCreated(null);
      }
      setMessage('Jeton révoqué.');
      await loadTokens();
    } catch (err: any) {
      setError(err?.response?.data?.error || err?.response?.data?.message || 'Révocation impossible.');
    }
  };

  return (
    <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
      <div>
        <h2 className="font-headline text-xl font-semibold text-on-surface">Jetons CI (quality gate)</h2>
        <p className="mt-2 text-sm text-on-surface-variant">
          Un jeton <code className="text-on-surface">vx_live_…</code> par projet, à coller dans GitHub Secrets
          (<code className="text-on-surface">VULNIX_CI_TOKEN</code>). Pas de mot de passe employé. Révoquable à tout moment.
        </p>
      </div>

      {(message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {error || message}
        </div>
      )}

      {created?.token && (
        <div className="rounded-2xl border border-primary/30 bg-primary/10 p-4 space-y-3">
          <p className="text-sm font-semibold text-on-surface">Secret affiché une seule fois</p>
          <pre className="overflow-x-auto rounded-xl bg-surface-container-high px-3 py-2 text-xs text-on-surface">{created.token}</pre>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={handleCopy} className="rounded-xl bg-primary px-3 py-2 text-xs font-headline font-semibold text-on-primary">
              {copied ? 'Copié' : 'Copier le jeton'}
            </button>
            <button type="button" onClick={() => setCreated(null)} className="rounded-xl border border-outline-variant/[0.2] px-3 py-2 text-xs font-headline font-semibold text-on-surface">
              Masquer
            </button>
          </div>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-[1fr_180px]">
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="Nom (ex. GitHub Actions CourtLinker)"
          className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm"
        />
        <select
          value={expiresInDays}
          onChange={(e) => setExpiresInDays(e.target.value)}
          className="rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm"
        >
          <option value="30">Expire dans 30 jours</option>
          <option value="90">Expire dans 90 jours</option>
          <option value="365">Expire dans 1 an</option>
          <option value="0">Jusqu’à révocation</option>
        </select>
      </div>

      <div className="space-y-2">
        <p className="text-xs uppercase tracking-[0.2em] text-outline">Dépôts autorisés</p>
        {repoOptions.length ? (
          repoOptions.map((repo) => (
            <label key={repo.id} className="flex items-center gap-3 rounded-xl bg-surface-container-high px-3 py-2 text-sm text-on-surface">
              <input type="checkbox" checked={selectedRepoIds.includes(repo.id)} onChange={() => toggleRepo(repo.id)} />
              <span className="truncate">{repo.url}</span>
            </label>
          ))
        ) : (
          <p className="text-sm text-outline">Liez d’abord un dépôt à ce projet, puis créez un jeton.</p>
        )}
      </div>

      <button
        type="button"
        onClick={handleCreate}
        disabled={saving || !repoOptions.length}
        className="rounded-2xl bg-primary px-4 py-3 text-sm font-headline font-semibold text-on-primary disabled:opacity-50"
      >
        {saving ? 'Création…' : 'Créer un jeton CI'}
      </button>

      {loading ? (
        <p className="text-sm text-outline">Chargement des jetons…</p>
      ) : (
        <div className="space-y-2">
          {tokens.length ? tokens.map((token) => (
            <div key={token.id} className="flex flex-col gap-2 rounded-2xl bg-surface-container-high px-4 py-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <p className="font-headline text-sm font-semibold text-on-surface">{token.name}</p>
                <p className="text-xs text-outline mt-1">
                  {token.tokenPrefix}… · {token.active ? 'actif' : 'révoqué'}
                  {token.expiresAt ? ` · expire ${new Date(token.expiresAt).toLocaleDateString()}` : ' · sans expiration'}
                  {token.lastUsedAt ? ` · dernier usage ${new Date(token.lastUsedAt).toLocaleString()}` : ' · jamais utilisé'}
                </p>
              </div>
              {token.active ? (
                <button type="button" onClick={() => handleRevoke(token.id)} className="text-xs text-error font-semibold">
                  Révoquer
                </button>
              ) : (
                <span className="text-xs text-outline">Révoqué</span>
              )}
            </div>
          )) : <p className="text-sm text-outline">Aucun jeton CI pour ce projet.</p>}
        </div>
      )}
    </section>
  );
};

export default CiTokenSection;
