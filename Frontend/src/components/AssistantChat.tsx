import React, { useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  chatWithAssistant,
  type AssistantChatTurn,
  type AssistantLinkDto,
} from "../services/api";

type UiMessage = {
  role: "user" | "assistant";
  content: string;
  links?: AssistantLinkDto[];
};

function idsFromLocation(pathname: string, search: string) {
  const qs = new URLSearchParams(search);
  let scanId = Number(qs.get("scanId") || "");
  const ssl = pathname.match(/^\/ssl-analysis\/(\d+)/);
  if (ssl) scanId = Number(ssl[1]);
  const srv = pathname.match(/^\/server-config\/(\d+)/);
  const serverId = srv ? Number(srv[1]) : NaN;
  return {
    scanId: Number.isFinite(scanId) && scanId > 0 ? scanId : undefined,
    serverId: Number.isFinite(serverId) && serverId > 0 ? serverId : undefined,
  };
}

function contextTitle(pathname: string, scanId?: number, serverId?: number) {
  if (pathname.startsWith("/ssl-analysis")) {
    return scanId ? `SSL · scan #${scanId}` : "Analyse SSL";
  }
  if (pathname.startsWith("/server-config")) {
    return serverId ? `Serveur #${serverId}` : "Serveurs";
  }
  if (pathname.startsWith("/cve-journal") || pathname.startsWith("/pipeline")) {
    return "Journal CVE";
  }
  if (pathname.startsWith("/vulnerabilities")) {
    return scanId ? `Vulnérabilités · scan #${scanId}` : "Vulnérabilités";
  }
  if (pathname.startsWith("/scans")) return "Scans";
  if (pathname.startsWith("/repositories")) return "Dépôts";
  if (pathname.startsWith("/projects")) return "Projets";
  if (pathname.startsWith("/profile")) return "Profil";
  if (pathname.startsWith("/admin")) return "Admin";
  if (pathname === "/") return "Dashboard";
  return "Vulnix";
}

function suggestions(pathname: string, scanId?: number, serverId?: number) {
  if (pathname.startsWith("/ssl-analysis")) {
    return scanId
      ? ["Le certificat est-il bientôt expiré ?", "Quels protocoles TLS sont risqués ?"]
      : ["Comment lancer un scan SSL ?", "Que signifie le grade SSL ?"];
  }
  if (pathname.startsWith("/server-config")) {
    return serverId
      ? ["Quels findings critiques sur ce serveur ?", "Le SSH root est-il ouvert ?"]
      : ["Comment ajouter un serveur ?", "Que vérifie le durcissement ?"];
  }
  if (pathname.startsWith("/cve-journal")) {
    return [
      "Quelles CVE attendent une version chef ?",
      "Comment accepter une déviation ?",
    ];
  }
  if (pathname.startsWith("/vulnerabilities")) {
    return scanId
      ? ["Quelles CVE traiter en priorité ?", "Y a-t-il des CVE CISA KEV ?"]
      : ["Comment ouvrir le rapport d'un scan ?"];
  }
  if (pathname.startsWith("/profile")) {
    return [
      "Comment lier GitLab pour l'auto-fix ?",
      "Où configurer ma clé IA ?",
    ];
  }
  if (pathname.startsWith("/scans") || pathname.startsWith("/repositories")) {
    return ["Comment lancer un scan ?", "Que signifient CRITICAL et HIGH ?"];
  }
  return [
    "Que puis-je faire sur cet écran ?",
    "Comment lier GitLab ?",
  ];
}

function extractApiError(err: unknown, fallback: string) {
  const data = (err as { response?: { data?: unknown } })?.response?.data;
  if (typeof data === "string" && data.trim()) return data;
  if (data && typeof data === "object") {
    const o = data as { message?: string; error?: string; detail?: string };
    if (o.message) return o.message;
    if (o.error) return o.error;
    if (o.detail) return o.detail;
  }
  return fallback;
}

function renderReply(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\([^)]+\))/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} className="font-semibold text-on-surface">
          {part.slice(2, -2)}
        </strong>
      );
    }
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={i}
          className="text-[11px] bg-surface-container-high px-1 py-0.5 rounded text-primary"
        >
          {part.slice(1, -1)}
        </code>
      );
    }
    const md = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (md) {
      const href = md[2];
      if (href.startsWith("/")) {
        return (
          <Link key={i} to={href} className="text-primary underline">
            {md[1]}
          </Link>
        );
      }
      return (
        <a
          key={i}
          href={href}
          target="_blank"
          rel="noopener noreferrer"
          className="text-primary underline"
        >
          {md[1]}
        </a>
      );
    }
    return <React.Fragment key={i}>{part}</React.Fragment>;
  });
}

const AssistantChat: React.FC = () => {
  const location = useLocation();
  const { scanId, serverId } = useMemo(
    () => idsFromLocation(location.pathname, location.search),
    [location.pathname, location.search],
  );
  const label = contextTitle(location.pathname, scanId, serverId);
  const hints = suggestions(location.pathname, scanId, serverId);

  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<UiMessage[]>([
    {
      role: "assistant",
      content:
        "Bonjour, je suis l'assistant Vulnix. Je m'appuie sur l'écran en cours (CVE, SSL, serveurs, journal) pour t'expliquer les résultats et te dire où cliquer. Je ne lance pas de scan ni de commit tout seul.",
    },
  ]);
  const listRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!open) return;
    listRef.current?.scrollTo({ top: listRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, open, busy]);

  useEffect(() => {
    if (!open) return;
    inputRef.current?.focus();
  }, [open]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const send = async (raw: string) => {
    const message = raw.trim();
    if (!message || busy) return;
    setError(null);
    setInput("");
    const nextUser: UiMessage = { role: "user", content: message };
    setMessages((prev) => [...prev, nextUser]);
    setBusy(true);
    try {
      const history: AssistantChatTurn[] = [...messages, nextUser]
        .filter((m) => m.content)
        .slice(-8)
        .map((m) => ({ role: m.role, content: m.content }));
      const res = await chatWithAssistant({
        message,
        page: `${location.pathname}${location.search}`,
        scanId,
        serverId,
        history,
      });
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: res.data.reply,
          links: res.data.links,
        },
      ]);
    } catch (err) {
      setError(
        extractApiError(
          err,
          "Impossible de joindre l'assistant. Réessaie dans un instant.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label={open ? "Fermer l'assistant" : "Ouvrir l'assistant Vulnix"}
        className="fixed bottom-5 right-5 z-[70] w-14 h-14 rounded-[999px] bg-gradient-to-br from-primary to-secondary text-on-primary shadow-lg hover:scale-105 transition-transform flex items-center justify-center"
      >
        <span
          className="material-symbols-outlined text-2xl"
          style={{ fontVariationSettings: "'FILL' 1" }}
        >
          {open ? "close" : "smart_toy"}
        </span>
      </button>

      {open && (
        <div className="fixed bottom-24 right-5 z-[70] w-[min(100vw-1.5rem,400px)] h-[min(72vh,560px)] flex flex-col rounded-2xl border border-outline-variant/20 bg-surface-container-low shadow-2xl overflow-hidden">
          <header className="px-4 py-3 border-b border-outline-variant/15 flex items-start gap-3 bg-surface-container">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-primary to-secondary flex items-center justify-center flex-shrink-0">
              <span
                className="material-symbols-outlined text-on-primary text-lg"
                style={{ fontVariationSettings: "'FILL' 1" }}
              >
                smart_toy
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-headline font-semibold text-on-surface leading-tight">
                Assistant Vulnix
              </p>
              <p className="text-[11px] text-outline truncate mt-0.5">
                Contexte : {label}
              </p>
            </div>
            <button
              type="button"
              title="Nouvelle conversation"
              onClick={() => {
                setMessages([
                  {
                    role: "assistant",
                    content:
                      "Nouvelle conversation. Pose ta question sur cet écran, je m'appuie sur tes données visibles.",
                  },
                ]);
                setError(null);
              }}
              className="text-slate-500 hover:text-primary"
            >
              <span className="material-symbols-outlined text-lg">refresh</span>
            </button>
          </header>

          <div ref={listRef} className="flex-1 overflow-y-auto px-3 py-3 space-y-3">
            {messages.map((m, idx) => (
              <div
                key={idx}
                className={`flex ${m.role === "user" ? "justify-end" : "justify-start"}`}
              >
                <div
                  className={`max-w-[90%] rounded-2xl px-3 py-2 text-[13px] leading-relaxed whitespace-pre-wrap ${
                    m.role === "user"
                      ? "bg-primary/20 text-on-surface rounded-br-md"
                      : "bg-surface-container text-on-surface-variant rounded-bl-md"
                  }`}
                >
                  {renderReply(m.content)}
                  {m.links && m.links.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {m.links.map((l) =>
                        l.href.startsWith("/") ? (
                          <Link
                            key={l.href + l.label}
                            to={l.href}
                            className="text-[11px] px-2 py-0.5 rounded-full bg-surface-container-high text-primary hover:underline"
                          >
                            {l.label}
                          </Link>
                        ) : (
                          <a
                            key={l.href + l.label}
                            href={l.href}
                            className="text-[11px] px-2 py-0.5 rounded-full bg-surface-container-high text-primary"
                          >
                            {l.label}
                          </a>
                        ),
                      )}
                    </div>
                  )}
                </div>
              </div>
            ))}
            {busy && (
              <p className="text-[11px] text-outline px-1 flex items-center gap-1">
                <span className="material-symbols-outlined text-sm animate-spin">
                  progress_activity
                </span>
                Analyse du dossier…
              </p>
            )}
            {error && (
              <p className="text-[12px] text-error bg-error/10 rounded-lg px-3 py-2">
                {error}
              </p>
            )}
          </div>

          {!busy && messages.length < 3 && (
            <div className="px-3 pb-2 flex flex-wrap gap-1.5">
              {hints.map((h) => (
                <button
                  key={h}
                  type="button"
                  onClick={() => void send(h)}
                  className="text-[11px] px-2.5 py-1 rounded-full border border-outline-variant/30 text-outline hover:text-primary hover:border-primary/40"
                >
                  {h}
                </button>
              ))}
            </div>
          )}

          <form
            className="p-3 border-t border-outline-variant/15 flex gap-2 items-end"
            onSubmit={(e) => {
              e.preventDefault();
              void send(input);
            }}
          >
            <textarea
              ref={inputRef}
              rows={1}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send(input);
                }
              }}
              placeholder="Pose une question…"
              className="flex-1 resize-none bg-surface-container rounded-xl px-3 py-2 text-sm text-on-surface outline-none border border-outline-variant/20 focus:border-primary/50 max-h-28"
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className="w-10 h-10 rounded-xl bg-primary text-on-primary disabled:opacity-40 flex items-center justify-center"
              aria-label="Envoyer"
            >
              <span className="material-symbols-outlined text-lg">send</span>
            </button>
          </form>
        </div>
      )}
    </>
  );
};

export default AssistantChat;
