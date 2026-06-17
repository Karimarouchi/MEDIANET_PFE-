import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { loginWithEmail } from '../services/api';

const Login: React.FC = () => {
  const navigate = useNavigate();
  const { refreshUser } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const error = new URLSearchParams(window.location.search).get('error');
  const oauthMessage = useMemo(() => {
    if (!error) return null;
    if (error === 'oauth_failed') return 'Erreur lors de l’authentification GitHub.';
    if (error === 'user_failed') return 'Impossible de récupérer les informations utilisateur.';
    if (error === 'server_error') return 'Erreur serveur. Vérifiez la configuration OAuth.';
    return 'Erreur de connexion.';
  }, [error]);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setFormError(null);
    try {
      const res = await loginWithEmail(email.trim(), password);
      localStorage.setItem('vulnix_token', res.data.token);
      await refreshUser();
      navigate('/');
    } catch (err: any) {
      const status = err?.response?.status;
      if (status === 504 || !err?.response) {
        setFormError('Le backend ne repond pas sur localhost:8080. Demarrez le backend ou attendez la fin du demarrage, puis reessayez.');
      } else if (status === 423) {
        setFormError('Ce compte est suspendu. Contactez un administrateur pour le reactiver.');
      } else if (status >= 500) {
        setFormError('Le serveur a retourne une erreur interne. Verifiez le backend puis reessayez.');
      } else {
        setFormError(err?.response?.data?.message || err?.response?.data?.error || 'Email ou mot de passe invalide.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-surface-container-lowest flex items-center justify-center relative overflow-hidden">

      {/* Background glow effects */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[400px] bg-secondary/5 rounded-full blur-3xl" />
      </div>

      {/* Grid background */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: 'linear-gradient(rgba(164,230,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(164,230,255,0.5) 1px, transparent 1px)',
          backgroundSize: '40px 40px',
        }}
      />

      <div className="relative z-10 w-full max-w-md px-6">
        {/* Logo + title */}
        <div className="text-center mb-12">
          <div className="flex items-center justify-center mb-6">
            <div className="w-16 h-16 bg-gradient-to-br from-primary to-secondary rounded-2xl flex items-center justify-center shadow-[0_0_40px_rgba(164,230,255,0.3)]">
              <span className="material-symbols-outlined text-on-primary text-3xl" style={{ fontVariationSettings: "'FILL' 1" }}>shield</span>
            </div>
          </div>
          <h1 className="text-4xl font-bold font-headline text-on-surface tracking-tight mb-2">Vulnix</h1>
          <p className="text-outline text-sm">Security Intelligence Platform</p>
          <div className="mt-3 inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-primary/10 border border-primary/20">
            <span className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse"></span>
            <span className="text-primary text-[10px] font-bold font-headline tracking-widest uppercase">Quantum Observer v1.0</span>
          </div>
        </div>

        {/* Login card */}
        <div className="glass-panel rounded-2xl border border-outline-variant/[0.15] p-8 shadow-2xl shadow-primary/5 backdrop-blur-xl">
          <h2 className="text-xl font-bold font-headline text-on-surface mb-2">Accès sécurisé</h2>
          <p className="text-sm text-on-surface-variant mb-8 leading-relaxed">
            Connectez-vous avec votre compte Vulnix.
          </p>

          {/* Error message */}
          {(oauthMessage || formError) && (
            <div className="mb-6 flex items-center gap-3 px-4 py-3 rounded-xl bg-error/10 border border-error/20">
              <span className="material-symbols-outlined text-error text-base">error</span>
              <p className="text-sm text-error">
                {formError || oauthMessage}
              </p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.2em] text-outline">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@medianet.tn"
                className="w-full rounded-xl border border-outline-variant/[0.18] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none focus:border-primary/50"
                autoComplete="email"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.2em] text-outline">Mot de passe</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-xl border border-outline-variant/[0.18] bg-surface-container px-4 py-3 text-sm text-on-surface outline-none focus:border-primary/50"
                autoComplete="current-password"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading || !email.trim() || !password}
              className="w-full flex items-center justify-center gap-3 px-6 py-4 rounded-xl bg-primary text-on-primary font-bold font-headline text-sm transition-all hover:shadow-[0_0_20px_rgba(164,230,255,0.18)] active:scale-[0.98] disabled:opacity-60"
            >
              <span className="material-symbols-outlined text-base">login</span>
              {loading ? 'Connexion…' : 'Se connecter'}
            </button>
          </form>

          {/* Info badges */}
          <div className="grid grid-cols-2 gap-3 mt-6">
            {[
              { icon: 'mail', label: 'Email', sub: 'Connexion locale' },
              { icon: 'lock', label: 'BCrypt', sub: 'Mot de passe haché' },
            ].map(item => (
              <div key={item.label} className="flex flex-col items-center gap-1.5 p-3 rounded-xl bg-surface-container border border-outline-variant/[0.1]">
                <span className="material-symbols-outlined text-primary text-lg">{item.icon}</span>
                <span className="text-[10px] font-bold text-on-surface font-headline">{item.label}</span>
                <span className="text-[9px] text-outline">{item.sub}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-[11px] text-outline mt-6">
          Vulnix · Projet de Fin d'Études · 2025–2026
        </p>
      </div>
    </div>
  );
};

export default Login;
