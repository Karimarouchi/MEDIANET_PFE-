import React, { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  getGithubLinkUrl,
  getGitlabLinkUrl,
  linkProviderToken,
  updateAiSettings,
  clearAiSettings,
} from "../services/api";

const extractApiError = (err: any, fallback: string) =>
  err?.response?.data?.message || err?.response?.data?.error || fallback;

const Profile: React.FC = () => {
  const { user, refreshUser } = useAuth();
  const [searchParams] = useSearchParams();
  const [githubToken, setGithubToken] = useState("");
  const [gitlabToken, setGitlabToken] = useState("");
  const [gitlabUrl, setGitlabUrl] = useState("");
  const [busyProvider, setBusyProvider] = useState<"GITHUB" | "GITLAB" | null>(
    null,
  );
  const [showManual, setShowManual] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // AI Settings states
  const [aiProvider, setAiProvider] = useState("");
  const [aiModel, setAiModel] = useState("");
  const [aiApiKey, setAiApiKey] = useState("");
  const [aiSaving, setAiSaving] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const [aiSuccess, setAiSuccess] = useState<string | null>(null);

  useEffect(() => {
    if (user) {
      setAiProvider(user.aiProvider || "");
      setAiModel(user.aiModel || "");
      if (user.gitlabUrl) {
        setGitlabUrl(user.gitlabUrl);
      }
      // Ne pas pré-remplir la clé pour sécurité
    }
  }, [user]);

  const linkedProvider = searchParams.get("linked");
  const callbackError = searchParams.get("error");

  const handleSaveAiSettings = async () => {
    if (!aiProvider) {
      setAiError("Choisissez un provider.");
      return;
    }
    if (!aiApiKey.trim()) {
      setAiError("La clé API est requise.");
      return;
    }
    setAiSaving(true);
    setAiError(null);
    setAiSuccess(null);
    try {
      await updateAiSettings({ aiProvider, aiModel, aiApiKey });
      await refreshUser();
      setAiSuccess("Paramètres IA sauvegardés avec succès.");
      setAiApiKey(""); // Clear key from state after save
    } catch (err: any) {
      setAiError(
        err?.response?.data?.message || "Erreur lors de la sauvegarde.",
      );
    } finally {
      setAiSaving(false);
    }
  };

  const handleClearAiSettings = async () => {
    setAiSaving(true);
    setAiError(null);
    setAiSuccess(null);
    try {
      await clearAiSettings();
      await refreshUser();
      setAiProvider("");
      setAiModel("");
      setAiApiKey("");
      setAiSuccess(
        "Configuration IA réinitialisée. Clé système par défaut utilisée.",
      );
    } catch (err: any) {
      setAiError("Erreur lors de la réinitialisation.");
    } finally {
      setAiSaving(false);
    }
  };

  const handleGitlabOAuth = async () => {
    setError(null);
    setMessage(null);
    setBusyProvider("GITLAB");
    try {
      const res = await getGitlabLinkUrl();
      window.location.href = res.data.url;
    } catch (err: any) {
      setError(
        extractApiError(err, "Impossible de démarrer la liaison GitLab."),
      );
      setBusyProvider(null);
    }
  };

  const handleGithubOAuth = async () => {
    setError(null);
    setMessage(null);
    setBusyProvider("GITHUB");
    try {
      const res = await getGithubLinkUrl();
      window.location.href = res.data.url;
    } catch (err: any) {
      setError(
        extractApiError(err, "Impossible de démarrer la liaison GitHub."),
      );
      setBusyProvider(null);
    }
  };

  const handleManualLink = async (
    provider: "GITHUB" | "GITLAB",
    token: string,
    glUrl?: string,
  ) => {
    if (!token.trim()) return;
    setBusyProvider(provider);
    setError(null);
    setMessage(null);
    try {
      await linkProviderToken(provider, token.trim(), glUrl);
      await refreshUser();
      setMessage(
        provider === "GITHUB" ? "Token GitHub lié." : "Token GitLab lié.",
      );
      if (provider === "GITHUB") setGithubToken("");
      if (provider === "GITLAB") setGitlabToken("");
    } catch (err: any) {
      setError(extractApiError(err, "Échec de la liaison du token."));
    } finally {
      setBusyProvider(null);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <header className="space-y-2">
        <p className="text-xs uppercase tracking-[0.35em] text-outline">
          Identity Hub
        </p>
        <h1 className="font-headline text-3xl font-bold text-on-surface">
          Profil et liaisons Git
        </h1>
        <p className="text-sm text-on-surface-variant max-w-2xl">
          Gérez votre rôle applicatif, votre fournisseur principal et les accès
          Git utilisés pour lister les dépôts et appliquer les correctifs.
        </p>
      </header>
      {(linkedProvider || callbackError || message || error) && (
        <div
          className={`rounded-2xl border px-4 py-3 text-sm ${error || callbackError ? "border-error/40 bg-error/10 text-error" : "border-primary/30 bg-primary/10 text-primary"}`}
        >
          {callbackError ? "La liaison GitLab a échoué." : null}
          {linkedProvider === "github"
            ? "Compte GitHub lié avec succès."
            : null}
          {linkedProvider === "gitlab"
            ? "Compte GitLab lié avec succès."
            : null}
          {message ? ` ${message}` : null}
          {error ? ` ${error}` : null}
        </div>
      )}
      <section className="grid gap-6 lg:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <div className="flex items-center gap-4">
            {user?.avatarUrl ? (
              <img
                src={user.avatarUrl}
                alt={user.login}
                className="h-16 w-16 rounded-2xl object-cover border border-outline-variant/[0.2]"
              />
            ) : (
              <div className="h-16 w-16 rounded-2xl bg-surface-container-high flex items-center justify-center border border-outline-variant/[0.2]">
                <span className="material-symbols-outlined text-3xl text-primary">
                  person
                </span>
              </div>
            )}
            <div>
              <h2 className="font-headline text-xl font-semibold text-on-surface">
                {user?.name || user?.login}
              </h2>
              <p className="text-sm text-outline">@{user?.login}</p>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">
                Rôle
              </p>
              <p className="mt-2 font-headline text-lg text-on-surface">
                {user?.role || "N/A"}
              </p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">
                Provider principal
              </p>
              <p className="mt-2 font-headline text-lg text-on-surface">
                {user?.primaryProvider || "LOCAL"}
              </p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">
                Email
              </p>
              <p className="mt-2 text-sm text-on-surface">
                {user?.email || "Non renseigné"}
              </p>
            </div>
            <div className="rounded-2xl bg-surface-container-high px-4 py-3">
              <p className="text-[11px] uppercase tracking-[0.25em] text-outline">
                Comptes liés
              </p>
              <p className="mt-2 text-sm text-on-surface">
                GitHub: {user?.hasGithubLinked ? "Oui" : "Non"} · GitLab:{" "}
                {user?.hasGitlabLinked ? "Oui" : "Non"}
              </p>
            </div>
          </div>
        </div>

        <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
          <h2 className="font-headline text-xl font-semibold text-on-surface">
            Connexions OAuth
          </h2>
          <p className="text-sm text-on-surface-variant">
            Reliez GitHub et GitLab depuis votre profil pour afficher les dépôts
            dans l’application et activer les actions de correctif sur chaque
            provider.
          </p>

          <div className="grid gap-3">
            <button
              onClick={handleGithubOAuth}
              disabled={busyProvider === "GITHUB"}
              className="w-full rounded-2xl border border-[#444c56] bg-[#24292f] px-4 py-3 font-headline text-sm font-semibold text-white disabled:opacity-60"
            >
              {busyProvider === "GITHUB"
                ? "Redirection GitHub…"
                : user?.hasGithubLinked
                  ? "Reconnecter GitHub"
                  : "Connecter avec GitHub"}
            </button>
            <button
              onClick={handleGitlabOAuth}
              disabled={busyProvider === "GITLAB"}
              className="w-full rounded-2xl bg-primary px-4 py-3 font-headline text-sm font-semibold text-on-primary disabled:opacity-60"
            >
              {busyProvider === "GITLAB"
                ? "Redirection GitLab…"
                : user?.hasGitlabLinked
                  ? "Reconnecter GitLab"
                  : "Connecter avec GitLab"}
            </button>
            <button
              onClick={() => setShowManual((v) => !v)}
              className="w-full flex items-center justify-center gap-2 rounded-2xl border border-outline-variant/[0.3] px-4 py-2.5 text-xs font-headline font-medium text-on-surface-variant hover:text-on-surface hover:border-outline-variant/60 transition-colors"
            >
              <span className="material-symbols-outlined text-base">
                {showManual ? "keyboard_arrow_up" : "keyboard_arrow_down"}
              </span>
              {showManual
                ? "Masquer la connexion manuelle"
                : "Se connecter manuellement (PAT)"}
            </button>
          </div>
        </div>
      </section>
      {showManual && (
        <section className="grid gap-6 lg:grid-cols-2">
          <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
            <h2 className="font-headline text-xl font-semibold text-on-surface">
              Token GitHub manuel
            </h2>
            <p className="text-sm text-on-surface-variant">
              Pour lier un compte GitHub sans OAuth ou remplacer le token
              actuel.
            </p>
            <input
              type="password"
              value={githubToken}
              onChange={(e) => setGithubToken(e.target.value)}
              placeholder="ghp_..."
              className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none"
            />
            <button
              onClick={() => handleManualLink("GITHUB", githubToken)}
              disabled={busyProvider === "GITHUB" || !githubToken.trim()}
              className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface disabled:opacity-60"
            >
              {busyProvider === "GITHUB"
                ? "Validation…"
                : "Lier le token GitHub"}
            </button>
          </div>

          <div className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-4">
            <h2 className="font-headline text-xl font-semibold text-on-surface">
              Token GitLab manuel
            </h2>
            <p className="text-sm text-on-surface-variant">
              Alternative à OAuth pour relier un PAT GitLab existant ou une URL auto-hébergée.
            </p>
            <div className="space-y-3">
              <input
                type="text"
                value={gitlabUrl}
                onChange={(e) => setGitlabUrl(e.target.value)}
                placeholder="URL GitLab (ex: https://gitlab.entreprise.com)"
                className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none"
              />
              <input
                type="password"
                value={gitlabToken}
                onChange={(e) => setGitlabToken(e.target.value)}
                placeholder="glpat-..."
                className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface outline-none"
              />
            </div>
            {user?.hasGitlabLinked && user?.gitlabUrl && (
              <p className="text-xs text-on-surface-variant/80 italic">
                Actuellement lié à : <span className="text-primary font-mono">{user.gitlabUrl}</span>
              </p>
            )}
            <button
              onClick={() => handleManualLink("GITLAB", gitlabToken, gitlabUrl)}
              disabled={busyProvider === "GITLAB" || !gitlabToken.trim()}
              className="rounded-2xl border border-outline-variant/[0.2] px-4 py-3 text-sm font-headline font-semibold text-on-surface disabled:opacity-60"
            >
              {busyProvider === "GITLAB"
                ? "Validation…"
                : "Lier le token GitLab"}
            </button>
          </div>
        </section>
      )}
      {/* Section IA */}
      <section className="rounded-3xl border border-outline-variant/[0.18] bg-surface-container p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h2 className="font-headline text-xl font-semibold text-on-surface">
              Clé IA personnelle
            </h2>
            <p className="text-sm text-on-surface-variant mt-1">
              Par défaut, l'application utilise la clé Gemini système. Vous
              pouvez la remplacer par votre propre clé pour utiliser un modèle
              plus performant (Gemini Pro, Claude Opus, GPT-4o, etc.).
            </p>
          </div>
          {/* Status badge */}
          <div
            className={`shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[11px] font-bold ${
              user?.hasCustomAiKey
                ? "bg-tertiary/15 border border-tertiary/30 text-tertiary"
                : "bg-surface-container-high border border-outline-variant/[0.2] text-outline"
            }`}
          >
            <span className="material-symbols-outlined text-[13px]">
              {user?.hasCustomAiKey ? "verified" : "lock_open"}
            </span>
            {user?.hasCustomAiKey
              ? `Clé personnelle · ${user.aiProvider}`
              : "Clé système (Gemini)"}
          </div>
        </div>

        {/* Provider selector */}
        <div>
          <label className="block text-[11px] uppercase tracking-widest text-outline mb-2">
            Provider IA
          </label>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[
              {
                value: "",
                label: "Système (défaut)",
                icon: "settings",
                desc: "Gemini Flash",
              },
              {
                value: "GEMINI",
                label: "Google Gemini",
                icon: "auto_awesome",
                desc: "Gemini Pro / Flash",
              },
              {
                value: "CLAUDE",
                label: "Anthropic Claude",
                icon: "psychology",
                desc: "Opus / Sonnet / Haiku",
              },
              {
                value: "OPENAI",
                label: "OpenAI",
                icon: "smart_toy",
                desc: "GPT-4o / GPT-4 Turbo",
              },
            ].map((p) => (
              <button
                key={p.value}
                onClick={() => {
                  setAiProvider(p.value);
                  setAiModel("");
                  setAiError(null);
                }}
                className={`p-3 rounded-2xl border text-left transition-all ${
                  aiProvider === p.value
                    ? "border-primary/50 bg-primary/10 text-primary"
                    : "border-outline-variant/[0.18] bg-surface-container-high text-on-surface-variant hover:border-primary/30 hover:text-on-surface"
                }`}
              >
                <span className="material-symbols-outlined text-lg block mb-1">
                  {p.icon}
                </span>
                <p className="text-xs font-semibold">{p.label}</p>
                <p className="text-[10px] opacity-60 mt-0.5">{p.desc}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Model + Key — seulement si provider sélectionné */}
        {aiProvider && (
          <div className="space-y-4">
            {/* Model */}
            <div>
              <label className="block text-[11px] uppercase tracking-widest text-outline mb-2">
                Modèle{" "}
                <span className="text-outline/50 normal-case tracking-normal">
                  (laisser vide pour le défaut du provider)
                </span>
              </label>
              <div className="flex gap-2 flex-wrap">
                {/* Suggestions selon provider */}
                {(aiProvider === "GEMINI"
                  ? ["gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-pro"]
                  : aiProvider === "CLAUDE"
                    ? [
                        "claude-opus-4-5",
                        "claude-sonnet-4-5",
                        "claude-haiku-3-5",
                      ]
                    : ["gpt-4o", "gpt-4-turbo", "gpt-4o-mini"]
                ).map((m) => (
                  <button
                    key={m}
                    onClick={() => setAiModel(m)}
                    className={`px-3 py-1.5 rounded-full text-xs border transition-all ${
                      aiModel === m
                        ? "border-primary/50 bg-primary/10 text-primary"
                        : "border-outline-variant/[0.2] text-outline hover:border-primary/30 hover:text-on-surface"
                    }`}
                  >
                    {m}
                  </button>
                ))}
              </div>
              <input
                type="text"
                className="mt-2 w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline outline-none focus:border-primary/50"
                placeholder={
                  aiProvider === "GEMINI"
                    ? "Ex: gemini-1.5-pro ou gemini-2.5-pro"
                    : aiProvider === "CLAUDE"
                      ? "Ex: claude-opus-4-5 ou claude-3-5-sonnet-20241022"
                      : "Ex: gpt-4o ou gpt-4-turbo"
                }
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
              />
            </div>

            {/* API Key */}
            <div>
              <label className="block text-[11px] uppercase tracking-widest text-outline mb-2">
                Clé API{" "}
                {user?.hasCustomAiKey && (
                  <span className="normal-case tracking-normal text-tertiary">
                    (déjà configurée — saisir une nouvelle pour remplacer)
                  </span>
                )}
              </label>
              <input
                type="password"
                className="w-full rounded-2xl border border-outline-variant/[0.2] bg-surface-container-high px-4 py-3 text-sm text-on-surface placeholder:text-outline outline-none focus:border-primary/50"
                placeholder={
                  aiProvider === "GEMINI"
                    ? "AIza..."
                    : aiProvider === "CLAUDE"
                      ? "sk-ant-..."
                      : "sk-..."
                }
                value={aiApiKey}
                onChange={(e) => setAiApiKey(e.target.value)}
              />
              <p className="text-[11px] text-outline mt-1.5">
                La clé est stockée de façon sécurisée côté serveur et jamais
                renvoyée au navigateur.
              </p>
            </div>
          </div>
        )}

        {/* Messages */}
        {aiError && (
          <div className="flex items-center gap-2 rounded-2xl border border-error/30 bg-error/10 px-4 py-3 text-sm text-error">
            <span className="material-symbols-outlined text-base">error</span>{" "}
            {aiError}
          </div>
        )}
        {aiSuccess && (
          <div className="flex items-center gap-2 rounded-2xl border border-primary/30 bg-primary/10 px-4 py-3 text-sm text-primary">
            <span className="material-symbols-outlined text-base">
              check_circle
            </span>{" "}
            {aiSuccess}
          </div>
        )}

        {/* Buttons */}
        <div className="flex gap-3">
          {aiProvider && (
            <button
              onClick={handleSaveAiSettings}
              disabled={aiSaving}
              className="flex items-center gap-2 rounded-2xl bg-primary px-6 py-3 font-headline text-sm font-semibold text-on-primary disabled:opacity-60 hover:opacity-90 transition-opacity"
            >
              <span className="material-symbols-outlined text-base">
                {aiSaving ? "progress_activity" : "save"}
              </span>
              {aiSaving ? "Sauvegarde..." : "Sauvegarder"}
            </button>
          )}
          {user?.hasCustomAiKey && (
            <button
              onClick={handleClearAiSettings}
              disabled={aiSaving}
              className="flex items-center gap-2 rounded-2xl border border-outline-variant/[0.2] px-6 py-3 font-headline text-sm font-semibold text-on-surface-variant hover:text-error hover:border-error/30 disabled:opacity-60 transition-all"
            >
              <span className="material-symbols-outlined text-base">
                restart_alt
              </span>
              Revenir à la clé système
            </button>
          )}
        </div>
      </section>{" "}
    </div>
  );
};

export default Profile;
