import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { getGithubLinkUrl, getGitlabLinkUrl, linkProviderToken } from '../services/api';

const extractApiError = (err: any, fallback: string) =>
  err?.response?.data?.message || err?.response?.data?.error || fallback;

const Profile: React.FC = () => {
  const { user, refreshUser } = useAuth();
  const [searchParams] = useSearchParams();
  const [githubToken, setGithubToken] = useState('');
  const [gitlabToken, setGitlabToken] = useState('');
  const [busyProvider, setBusyProvider] = useState<'GITHUB' | 'GITLAB' | null>(null);
  const [showManual, setShowManual] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const linkedProvider = searchParams.get('linked');
  const callbackError = searchParams.get('error');

  const handleGitlabOAuth = async () => {
    setError(null);
    setMessage(null);
    setBusyProvider('GITLAB');
    try {
      const res = await getGitlabLinkUrl();
      window.location.href = res.data.url;
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de démarrer la liaison GitLab.'));
      setBusyProvider(null);
    }
  };

  const handleGithubOAuth = async () => {
    setError(null);
    setMessage(null);
    setBusyProvider('GITHUB');
    try {
      const res = await getGithubLinkUrl();
      window.location.href = res.data.url;
    } catch (err: any) {
      setError(extractApiError(err, 'Impossible de démarrer la liaison GitHub.'));
      setBusyProvider(null);
    }
  };

  const handleManualLink = async (provider: 'GITHUB' | 'GITLAB', token: string) => {
    if (!token.trim()) return;
    setBusyProvider(provider);
    setError(null);
    setMessage(null);
    try {
      await linkProviderToken(provider, token.trim());
      await refreshUser();
      setMessage(provider === 'GITHUB' ? 'Token GitHub lié.' : 'Token GitLab lié.');
      if (provider === 'GITHUB') setGithubToken('');
      if (provider === 'GITLAB') setGitlabToken('');
    } catch (err: any) {
      setError(extractApiError(err, 'Échec de la liaison du token.'));
    } finally {
      setBusyProvider(null);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <header className="space-y-2">
        <p className="text-xs uppercase tracking-[0.35em] text-outline">Identity Hub</p>
        <h1 className="font-headline text-3xl font-bold text-on-surface">Profil et liaisons Git</h1>
        <p className="text-sm text-on-surface-variant max-w-2xl">
          Gérez votre rôle applicatif, votre fournisseur principal et les accès Git utilisés pour lister les dépôts et appliquer les correctifs.
        </p>
      </header>

      {(linkedProvider || callbackError || message || error) && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${error || callbackError ? 'border-error/40 bg-error/10 text-error' : 'border-primary/30 bg-primary/10 text-primary'}`}>
          {callbackError ? 'La liaison GitLab a échoué.' : null}
          {linkedProvider === 'github' ? 'Compte GitHub lié avec succès.' : null}
          {linkedProvider === 'gitlab' ? 'Compte GitLab lié avec succès.' : null}
          {message ? ` ${message}` : null}
          {error ? ` ${error}` : null}
        </div>
      )}

      <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <div className="flex items-center gap-4">
            {user?.avatarUrl ? (
              <img src={user.avatarUrl} alt={user.login} className="h-16 w-16 rounded-2xl object-cover border border-outline-variant/[0.2]" />
            ) : (
              <div className="h-16 w-16 rounded-2xl bg-surface-container-high flex items-center justify-center border border-outline-variant/[0.2]">
                <span className="material-symbols-outlined text-3xl text-primary">person</span>
              </div>
            )}
            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">{user?.name || user?.login}</h2>
              <p className="text-sm text-outline">@{user?.login}</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">Rôle</p>
              <p className="mt-2 font-headline text-lg text-on-surface">{user?.role || 'N/A'}</p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">Provider principal</p>
              <p className="mt-2 font-headline text-lg text-on-surface">{user?.primaryProvider || 'LOCAL'}</p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">Email</p>
              <p className="mt-2 text-sm text-on-surface">{user?.email || 'Non renseigné'}</p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">Comptes liés</p>
              <p className="mt-2 text-sm text-on-surface">GitHub: {user?.hasGithubLinked ? 'Oui' : 'Non'} · GitLab: {user?.hasGitlabLinked ? 'Oui' : 'Non'}</p>
            </div>
          </div>
        </div>

        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <h2 className="font-headline text-xl font-semibold text-on-surface">Connexions OAuth</h2>
          <p className="text-sm text-on-surface-variant">
            Reliez GitHub et GitLab depuis votre profil pour afficher les dépôts dans l’application et activer les actions de correctif sur chaque provider.
          </p>

          <div className="grid gap-3">
            <button
              onClick={handleGithubOAuth}
              disabled={busyProvider === 'GITHUB'}
              className="w-full rounded-2xl border border-[#444c56] bg-[#24292f] px-4 py-3 font-headline text-sm font-semibold text-white disabled:opacity-60"
            >
              {busyProvider === 'GITHUB' ? 'Redirection GitHub…' : user?.hasGithubLinked ? 'Reconnecter GitHub' : 'Connecter avec GitHub'}
            </button>
            <button
              onClick={handleGitlabOAuth}
              disabled={busyProvider === 'GITLAB'}
              className="w-full rounded-2xl bg-primary px-4 py-3 font-headline text-sm font-semibold text-on-primary disabled:opacity-60"
            >
              {busyProvider === 'GITLAB' ? 'Redirection GitLab…' : user?.hasGitlabLinked ? 'Reconnecter GitLab' : 'Connecter avec GitLab'}
            </button>
            <button
              onClick={() => setShowManual(v => !v)}
              className="w-full flex items-center justify-center gap-2 rounded-2xl border border-outline-variant/[0.3] px-4 py-2.5 text-xs font-headline font-medium text-on-surface-variant hover:text-on-surface hover:border-outline-variant/60 transition-colors"
            >
              <span className="material-symbols-outlined text-base">{showManual ? 'keyboard_arrow_up' : 'keyboard_arrow_down'}</span>
              {showManual ? 'Masquer la connexion manuelle' : 'Se connecter manuellement (PAT)'}
            </button>
          </div>
        </div>
      </section>

      {showManual && (
      <section className="grid gap-6 lg:grid-cols-2">
        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <h2 className="font-headline text-xl font-semibold text-on-surface">Token GitHub manuel</h2>
          <p className="text-sm text-on-surface-variant">Pour lier un compte GitHub sans OAuth ou remplacer le token actuel.</p>
          <input
            type="password"
            value={githubToken}
            onChange={(e) => setGithubToken(e.target.value)}
            placeholder="ghp_..."
            className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none"
          />
          <button
            onClick={() => handleManualLink('GITHUB', githubToken)}
            disabled={busyProvider === 'GITHUB' || !githubToken.trim()}
            className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface disabled:opacity-60"
          >
            {busyProvider === 'GITHUB' ? 'Validation…' : 'Lier le token GitHub'}
          </button>
        </div>

        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <h2 className="font-headline text-xl font-semibold text-on-surface">Token GitLab manuel</h2>
          <p className="text-sm text-on-surface-variant">Alternative à OAuth pour relier un PAT GitLab existant.</p>
          <input
            type="password"
            value={gitlabToken}
            onChange={(e) => setGitlabToken(e.target.value)}
            placeholder="glpat-..."
            className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none"
          />
          <button
            onClick={() => handleManualLink('GITLAB', gitlabToken)}
            disabled={busyProvider === 'GITLAB' || !gitlabToken.trim()}
            className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface disabled:opacity-60"
          >
            {busyProvider === 'GITLAB' ? 'Validation…' : 'Lier le token GitLab'}
          </button>
        </div>
      </section>      )}    </div>
  );
};

export default Profile;