import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  deleteOfficialGuidance,
  getCveJournal,
  getCveJournalRecommendation,
  getCveJournalTimeline,
  getPendingPolicyDeviations,
  approvePolicyDeviation,
  rejectPolicyDeviation,
  upsertOfficialGuidance,
  type CveAuditEventDto,
  type CveJournalEntry,
  type CveJournalIntervention,
  type CveJournalResponse,
  type CveVersionRecommendation,
  type PolicyDeviationDto,
} from "../services/api";
import RejectReasonModal from "../components/RejectReasonModal";

const severityBadge = (severity?: string | null) => {
  switch ((severity || "").toUpperCase()) {
    case "CRITICAL":
      return "bg-error-container text-on-error-container";
    case "HIGH":
      return "bg-secondary-container text-on-secondary-container";
    case "MEDIUM":
      return "bg-surface-variant text-on-surface-variant";
    case "LOW":
      return "bg-tertiary-container text-on-tertiary-container";
    default:
      return "bg-surface-container text-outline";
  }
};

const statusBadge = (status?: string | null) => {
  switch (status) {
    case "DETECTE":
      return "bg-surface-container-highest text-outline";
    case "EVALUE":
      return "bg-amber-500/15 text-amber-300 border border-amber-500/30";
    case "VERSION_OFFICIELLE":
      return "bg-tertiary/15 text-tertiary border border-tertiary/30";
    case "CORRIGE":
      return "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30";
    case "ECART_POLITIQUE":
      return "bg-error/15 text-error border border-error/30";
    case "ACCEPTE_RISQUE":
      return "bg-secondary/15 text-secondary border border-secondary/30";
    default:
      return "bg-surface-container text-outline";
  }
};

const eventLabel = (type?: string | null) => {
  switch (type) {
    case "DETECTION":
      return "Détection";
    case "POLICY_SET":
      return "Politique chef";
    case "POLICY_CLEARED":
      return "Politique retirée";
    case "FIX_APPLIED":
      return "Correctif appliqué";
    case "POLICY_DEVIATION":
      return "Écart politique";
    case "RISK_ACCEPTED":
      return "Risque accepté";
    default:
      return type || "Événement";
  }
};

const extractApiError = (err: any, fallback: string) => {
  const data = err?.response?.data;
  if (typeof data === "string" && data.trim()) return data;
  if (data?.message && typeof data.message === "string") return data.message;
  if (data?.error && typeof data.error === "string") return data.error;
  if (data?.detail && typeof data.detail === "string") return data.detail;
  return fallback;
};

const CveJournal: React.FC = () => {
  // Accès page = permission CVE_JOURNAL = « chef » (pas de rôle système séparé)
  const { user } = useAuth();
  const currentLogin = user?.login || user?.email || null;

  const [data, setData] = useState<CveJournalResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [view, setView] = useState<"catalog" | "interventions">("catalog");
  const [selected, setSelected] = useState<CveJournalEntry | null>(null);
  const [timeline, setTimeline] = useState<CveAuditEventDto[]>([]);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [stableVersion, setStableVersion] = useState("");
  const [comment, setComment] = useState("");
  const [saving, setSaving] = useState(false);
  const [recommendation, setRecommendation] = useState<CveVersionRecommendation | null>(null);
  const [recommendLoading, setRecommendLoading] = useState(false);
  const [recommendError, setRecommendError] = useState<string | null>(null);
  const [pendingDeviations, setPendingDeviations] = useState<PolicyDeviationDto[]>([]);
  const [pendingBusyId, setPendingBusyId] = useState<number | null>(null);
  const [rejectTarget, setRejectTarget] = useState<PolicyDeviationDto | null>(null);

  const load = useCallback(async (keepSelection = true) => {
    setLoading(true);
    setError(null);
    try {
      const res = await getCveJournal();
      setData(res.data);
      if (keepSelection) {
        setSelected((prev) => {
          if (!prev) return null;
          const key = `${prev.cveId ?? ""}|${prev.packageName ?? ""}`;
          const next =
            res.data.catalog.find(
              (c) => `${c.cveId ?? ""}|${c.packageName ?? ""}` === key,
            ) ?? null;
          if (next) {
            setStableVersion(next.officialStableVersion ?? "");
            setComment(next.officialComment ?? "");
          }
          return next;
        });
      }
    } catch (err: any) {
      setError(extractApiError(err, "Impossible de charger le Journal CVE."));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(false);
  }, [load]);

  useEffect(() => {
    let cancelled = false;
    const loadPending = async () => {
      try {
        const res = await getPendingPolicyDeviations();
        if (!cancelled) setPendingDeviations(res.data || []);
      } catch {
        if (!cancelled) setPendingDeviations([]);
      }
    };
    void loadPending();
    const t = setInterval(() => void loadPending(), 30000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const loadTimeline = useCallback(async (entry: CveJournalEntry) => {
    if (!entry.cveId) {
      setTimeline([]);
      return;
    }
    setTimelineLoading(true);
    try {
      const res = await getCveJournalTimeline(entry.cveId, entry.packageName);
      setTimeline(res.data || []);
    } catch {
      setTimeline([]);
    } finally {
      setTimelineLoading(false);
    }
  }, []);

  const loadRecommendation = useCallback(async (entry: CveJournalEntry) => {
    if (!entry.cveId) {
      setRecommendation(null);
      setRecommendError(null);
      return;
    }
    setRecommendLoading(true);
    setRecommendError(null);
    setRecommendation(null);
    try {
      const res = await getCveJournalRecommendation({
        cveId: entry.cveId,
        packageName: entry.packageName,
        fixedVersion: entry.fixedVersion,
        severity: entry.severity,
        description: entry.description,
        ecosystem: entry.ecosystem,
      });
      setRecommendation(res.data);
      setStableVersion((prev) => {
        if (entry.officialStableVersion) return entry.officialStableVersion;
        if (prev.trim()) return prev;
        return res.data.recommendedVersion || "";
      });
      setComment((prev) => {
        if (entry.officialComment) return entry.officialComment;
        if (prev.trim()) return prev;
        return res.data.rationale || "";
      });
    } catch (err: any) {
      setRecommendError(extractApiError(err, "Impossible d’obtenir la recommandation IA."));
    } finally {
      setRecommendLoading(false);
    }
  }, []);

  const filteredCatalog = useMemo(() => {
    const rows = data?.catalog ?? [];
    const q = search.trim().toLowerCase();
    return rows.filter((row) => {
      if (severityFilter !== "ALL" && (row.severity || "").toUpperCase() !== severityFilter) {
        return false;
      }
      if (statusFilter !== "ALL" && row.remediationStatus !== statusFilter) {
        return false;
      }
      if (!q) return true;
      return (
        (row.cveId || "").toLowerCase().includes(q) ||
        (row.packageName || "").toLowerCase().includes(q) ||
        (row.officialStableVersion || "").toLowerCase().includes(q) ||
        (row.remediationStatusLabel || "").toLowerCase().includes(q) ||
        (row.description || "").toLowerCase().includes(q)
      );
    });
  }, [data, search, severityFilter, statusFilter]);

  const filteredInterventions = useMemo(() => {
    const rows = data?.interventions ?? [];
    const q = search.trim().toLowerCase();
    if (!q) return rows;
    return rows.filter(
      (row) =>
        (row.cveId || "").toLowerCase().includes(q) ||
        (row.packageName || "").toLowerCase().includes(q) ||
        (row.createdByLogin || "").toLowerCase().includes(q) ||
        (row.reason || "").toLowerCase().includes(q) ||
        (row.toVersion || "").toLowerCase().includes(q),
    );
  }, [data, search]);

  const openEntry = (entry: CveJournalEntry) => {
    setSelected(entry);
    setStableVersion(entry.officialStableVersion ?? "");
    setComment(entry.officialComment ?? "");
    setMessage(null);
    setError(null);
    setRecommendation(null);
    setRecommendError(null);
    void loadTimeline(entry);
    void loadRecommendation(entry);
  };

  const handleSaveOfficial = async () => {
    if (!selected?.cveId) {
      setError("CVE manquant.");
      return;
    }
    if (!stableVersion.trim()) {
      setError("Indiquez la version stable.");
      return;
    }
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      await upsertOfficialGuidance({
        cveId: selected.cveId,
        packageName: selected.packageName ?? "",
        stableVersion: stableVersion.trim(),
        comment: comment.trim(),
      });
      setMessage("Version officielle enregistrée et liée à votre compte (audit journalisé).");
      await load();
      if (selected.cveId) {
        await loadTimeline({ ...selected, officialStableVersion: stableVersion.trim() });
      }
    } catch (err: any) {
      setError(extractApiError(err, "Échec de l'enregistrement."));
    } finally {
      setSaving(false);
    }
  };

  const handleClearOfficial = async () => {
    if (!selected?.guidanceId) return;
    setSaving(true);
    setError(null);
    try {
      await deleteOfficialGuidance(selected.guidanceId);
      setMessage("Version officielle supprimée.");
      setStableVersion("");
      setComment("");
      await load();
      if (selected.cveId) await loadTimeline(selected);
    } catch (err: any) {
      setError(extractApiError(err, "Échec de la suppression."));
    } finally {
      setSaving(false);
    }
  };

  const byStatus = data?.stats?.byStatus ?? {};

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-3xl font-bold font-headline text-on-surface tracking-tight">
            Journal CVE
          </h1>
          <p className="text-sm text-on-surface-variant mt-1 max-w-2xl">
            Cycle Detect → Decide → Remediate : catalogue, politique chef, interventions
            développeurs et timeline d’audit.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void load(true)}
          className="inline-flex items-center gap-2 rounded-xl border border-outline-variant/30 px-4 py-2 text-sm text-on-surface-variant hover:border-primary/40 hover:text-on-surface"
        >
          <span className="material-symbols-outlined text-base">refresh</span>
          Actualiser
        </button>
      </header>

      {data && (
        <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-6 gap-3">
          {[
            { label: "CVE détectés", value: data.stats.totalCves, icon: "bug_report" },
            { label: "Version chef", value: data.stats.withOfficialGuidance, icon: "verified" },
            { label: "Corrigés", value: byStatus.CORRIGE ?? 0, icon: "check_circle" },
            { label: "Écarts", value: byStatus.ECART_POLITIQUE ?? 0, icon: "gavel" },
            { label: "À évaluer", value: byStatus.EVALUE ?? 0, icon: "priority_high" },
            { label: "Interventions", value: data.stats.interventionCount, icon: "history" },
          ].map((s) => (
            <div
              key={s.label}
              className="rounded-2xl border border-outline-variant/20 bg-surface-container px-4 py-3"
            >
              <div className="flex items-center gap-2 text-outline text-[11px] uppercase tracking-widest">
                <span className="material-symbols-outlined text-sm">{s.icon}</span>
                {s.label}
              </div>
              <p className="text-2xl font-bold text-on-surface mt-1">{s.value}</p>
            </div>
          ))}
        </div>
      )}

      {pendingDeviations.length > 0 && (
        <section className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-3">
          <h2 className="text-sm font-bold text-amber-200 flex items-center gap-2">
            <span className="material-symbols-outlined text-base">gavel</span>
            Écarts en attente de validation ({pendingDeviations.length})
          </h2>
          <p className="text-[11px] text-on-surface-variant">
            Accepter déclenche le commit Git automatiquement avec le compte du développeur demandeur.
          </p>
          <div className="space-y-2">
            {pendingDeviations.map((d) => (
              <div
                key={d.id}
                className="rounded-xl bg-surface-container px-4 py-3 flex flex-col sm:flex-row sm:items-center gap-3 justify-between"
              >
                <div className="min-w-0 text-xs">
                  <p className="font-mono font-semibold text-on-surface">
                    {d.cveId} · {d.packageName}
                  </p>
                  <p className="text-on-surface-variant mt-0.5">
                    <span className="text-error font-mono">{d.proposedVersion}</span>
                    {" ≠ chef "}
                    <span className="text-tertiary font-mono">{d.officialVersion}</span>
                    {" · demandé par "}
                    <span className="text-primary font-medium">{d.requestedByLogin}</span>
                  </p>
                  <p className="text-outline mt-1 line-clamp-2">{d.reason}</p>
                  {d.errorMessage && (
                    <p className="text-error mt-1 text-[11px]">{d.errorMessage}</p>
                  )}
                </div>
                <div className="flex gap-2 shrink-0">
                  <button
                    type="button"
                    disabled={pendingBusyId === d.id}
                    onClick={async () => {
                      setPendingBusyId(d.id);
                      try {
                        const res = await approvePolicyDeviation(d.id);
                        if (res.data?.commitFailed || res.data?.error || res.data?.status === 'COMMIT_FAILED') {
                          setError(res.data.error || res.data.errorMessage || 'Le commit Git a échoué.');
                          return;
                        }
                        setPendingDeviations((prev) => prev.filter((x) => x.id !== d.id));
                        setMessage(
                          `Dérogation acceptée — commit au nom de ${d.requestedByLogin}`
                            + (res.data.commitUrl ? ` : ${res.data.commitUrl}` : ""),
                        );
                      } catch (err: any) {
                        setError(extractApiError(err, "Échec acceptation."));
                      } finally {
                        setPendingBusyId(null);
                      }
                    }}
                    className="rounded-xl bg-tertiary/20 text-tertiary px-3 py-2 text-[11px] font-bold disabled:opacity-50"
                  >
                    Accepter → commit
                  </button>
                  <button
                    type="button"
                    disabled={pendingBusyId === d.id}
                    onClick={() => setRejectTarget(d)}
                    className="rounded-xl bg-error/15 text-error px-3 py-2 text-[11px] font-bold disabled:opacity-50"
                  >
                    Refuser
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="flex flex-wrap gap-2 items-center">
        <div className="flex rounded-xl border border-outline-variant/25 overflow-hidden">
          <button
            type="button"
            onClick={() => setView("catalog")}
            className={`px-4 py-2 text-sm ${view === "catalog" ? "bg-primary/15 text-primary" : "text-outline"}`}
          >
            Catalogue CVE
          </button>
          <button
            type="button"
            onClick={() => setView("interventions")}
            className={`px-4 py-2 text-sm ${view === "interventions" ? "bg-primary/15 text-primary" : "text-outline"}`}
          >
            Interventions dev
          </button>
        </div>
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Rechercher CVE, package, statut, auteur…"
          className="flex-1 min-w-[200px] rounded-xl border border-outline-variant/25 bg-surface-container-high px-4 py-2 text-sm outline-none focus:border-primary/40"
        />
        {view === "catalog" && (
          <>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="rounded-xl border border-outline-variant/25 bg-surface-container-high px-3 py-2 text-sm"
            >
              <option value="ALL">Toutes sévérités</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="rounded-xl border border-outline-variant/25 bg-surface-container-high px-3 py-2 text-sm"
            >
              <option value="ALL">Tous statuts</option>
              <option value="DETECTE">Détecté</option>
              <option value="EVALUE">À évaluer</option>
              <option value="VERSION_OFFICIELLE">Version chef</option>
              <option value="CORRIGE">Corrigé</option>
              <option value="ECART_POLITIQUE">Écart politique</option>
              <option value="ACCEPTE_RISQUE">Risque accepté</option>
            </select>
          </>
        )}
      </div>

      {error && (
        <div className="rounded-xl border border-error/30 bg-error/10 px-4 py-3 text-sm text-error">
          {error}
        </div>
      )}
      {message && (
        <div className="rounded-xl border border-primary/30 bg-primary/10 px-4 py-3 text-sm text-primary">
          {message}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center py-20 text-outline gap-2">
          <span className="material-symbols-outlined animate-spin">progress_activity</span>
          Chargement du journal…
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[1.35fr_1fr] gap-4 items-start">
          <section className="w-full rounded-2xl border border-outline-variant/20 bg-surface-container overflow-hidden">
            {view === "catalog" ? (
              <div className="divide-y divide-outline-variant/15 max-h-[70vh] overflow-y-auto">
                {filteredCatalog.length === 0 && (
                  <p className="p-6 text-sm text-outline">Aucun CVE dans le catalogue.</p>
                )}
                {filteredCatalog.map((entry) => {
                  const active =
                    selected?.cveId === entry.cveId &&
                    (selected?.packageName || "") === (entry.packageName || "");
                  return (
                    <button
                      key={`${entry.cveId}|${entry.packageName}`}
                      type="button"
                      onClick={() => openEntry(entry)}
                      className={`w-full text-left px-4 py-3 hover:bg-surface-container-high transition-colors ${
                        active ? "bg-primary/10 border-l-2 border-primary" : ""
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="font-mono font-semibold text-on-surface truncate">
                            {entry.cveId || "CVE inconnu"}
                          </p>
                          <p className="text-xs text-on-surface-variant truncate mt-0.5">
                            {entry.packageName || "Package non précisé"}
                          </p>
                        </div>
                        <span className={`shrink-0 text-[10px] font-bold px-2 py-0.5 rounded-full ${severityBadge(entry.severity)}`}>
                          {entry.severity || "UNKNOWN"}
                        </span>
                      </div>
                      <div className="mt-2 flex flex-wrap gap-2 text-[10px]">
                        <span className={`rounded-full px-2 py-0.5 ${statusBadge(entry.remediationStatus)}`}>
                          {entry.remediationStatusLabel || entry.remediationStatus || "—"}
                        </span>
                        {entry.officialStableVersion && (
                          <span className="rounded-full bg-tertiary/15 text-tertiary px-2 py-0.5">
                            Chef → {entry.officialStableVersion}
                          </span>
                        )}
                        {entry.hasDeveloperFix && (
                          <span className="rounded-full bg-secondary/15 text-secondary px-2 py-0.5">
                            Fix dev
                          </span>
                        )}
                        {entry.fixedVersion && (
                          <span className="rounded-full bg-surface-container-highest text-outline px-2 py-0.5">
                            Fixed In: {entry.fixedVersion}
                          </span>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            ) : (
              <div className="divide-y divide-outline-variant/15 max-h-[70vh] overflow-y-auto">
                {filteredInterventions.length === 0 && (
                  <p className="p-6 text-sm text-outline">Aucune intervention développeur enregistrée.</p>
                )}
                {filteredInterventions.map((item: CveJournalIntervention) => (
                  <div key={item.id} className="px-4 py-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <p className="font-mono font-semibold text-on-surface">
                          {item.cveId || "—"}
                        </p>
                        <p className="text-xs text-on-surface-variant">
                          {item.packageName || "—"} · {item.fromVersion || "?"} →{" "}
                          <span className="text-tertiary font-semibold">{item.toVersion || "?"}</span>
                        </p>
                      </div>
                      <span className="text-[10px] text-outline shrink-0">
                        {item.createdAt?.replace("T", " ").slice(0, 16)}
                      </span>
                    </div>
                    <p className="mt-2 text-sm text-on-surface-variant">
                      <span className="text-primary font-medium">{item.createdByLogin || "Dev"}</span>
                      {" — "}
                      {item.reason || "Sans commentaire"}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </section>

          <aside className="w-full rounded-2xl border border-outline-variant/20 bg-surface-container p-5 space-y-4 min-h-[320px]">
            {!selected ? (
              <div className="h-full flex flex-col items-center justify-center text-center text-outline py-16">
                <span className="material-symbols-outlined text-4xl mb-2">menu_book</span>
                <p className="text-sm">Sélectionnez un CVE pour lire le détail</p>
                <p className="text-xs mt-1 max-w-xs">
                  Statut, version chef, interventions et timeline d’audit.
                </p>
              </div>
            ) : (
              <>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h2 className="font-mono text-lg font-bold text-on-surface">{selected.cveId}</h2>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${severityBadge(selected.severity)}`}>
                      {selected.severity}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${statusBadge(selected.remediationStatus)}`}>
                      {selected.remediationStatusLabel || selected.remediationStatus}
                    </span>
                  </div>
                  <p className="text-sm text-on-surface-variant mt-1">{selected.packageName || "—"}</p>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="rounded-xl bg-surface-container-high px-3 py-2">
                    <p className="text-outline uppercase tracking-wider text-[9px]">CVSS</p>
                    <p className="font-bold text-on-surface">{selected.cvssScore ?? "—"}</p>
                  </div>
                  <div className="rounded-xl bg-surface-container-high px-3 py-2">
                    <p className="text-outline uppercase tracking-wider text-[9px]">Fixed In (scan)</p>
                    <p className="font-mono font-semibold text-tertiary break-all">
                      {selected.fixedVersion || "—"}
                    </p>
                  </div>
                </div>

                {/* Recommandation IA — affichée directement (pas de bouton) */}
                <div className="rounded-xl border border-primary/30 bg-primary/5 p-3 space-y-2">
                  <div className="flex items-center justify-between gap-2">
                    <h3 className="text-[11px] font-bold uppercase tracking-widest text-primary">
                      Version recommandée (IA)
                    </h3>
                    <span className="text-[10px] text-outline">
                      {recommendLoading
                        ? "Analyse…"
                        : recommendation?.source === "LLM"
                          ? `via ${recommendation.aiProvider || "IA"}`
                          : recommendation?.source === "ERROR"
                            ? "IA indisponible"
                            : ""}
                    </span>
                  </div>
                  {recommendLoading && (
                    <p className="text-xs text-outline flex items-center gap-2">
                      <span className="material-symbols-outlined text-sm animate-spin">progress_activity</span>
                      Analyse métier des versions Fixed In (pas seulement la plus récente)…
                    </p>
                  )}
                  {(recommendError || recommendation?.aiError) && (
                    <p className="text-xs text-error">
                      {recommendError || recommendation?.aiError}
                    </p>
                  )}
                  {!recommendLoading && recommendation?.recommendedVersion && (
                    <>
                      <p className="text-sm">
                        Recommandée :{" "}
                        <span className="font-mono font-bold text-primary text-base">
                          {recommendation.recommendedVersion}
                        </span>
                        <span className="text-[10px] text-outline ml-2">parmi Fixed In</span>
                      </p>
                      {recommendation.rationale && (
                        <p className="text-xs text-on-surface-variant leading-relaxed">
                          {recommendation.rationale}
                        </p>
                      )}
                      {(recommendation.comparedToOthers?.length ?? 0) > 0 && (
                        <div className="space-y-1 pt-1">
                          <p className="text-[10px] uppercase tracking-wider text-outline">
                            Par rapport aux autres Fixed In
                          </p>
                          {recommendation.comparedToOthers!.map((row, i) => (
                            <div
                              key={`${row.version}-${i}`}
                              className="rounded-lg bg-surface-container-high px-2.5 py-1.5 text-[11px]"
                            >
                              <span className="font-mono text-on-surface">{row.version}</span>
                              <span className="text-outline"> — {row.whyNot}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                  {!recommendLoading && !recommendError && !recommendation?.aiError
                    && !recommendation?.recommendedVersion && (
                    <p className="text-xs text-outline">Pas de recommandation (liste Fixed In vide).</p>
                  )}
                </div>

                {selected.description && (
                  <p className="text-xs text-on-surface-variant leading-relaxed line-clamp-3">
                    {selected.description}
                  </p>
                )}

                <div className="rounded-xl border border-tertiary/25 bg-tertiary/5 p-3 space-y-2">
                  <h3 className="text-[11px] font-bold uppercase tracking-widest text-tertiary">
                    Version stable officielle — Source of Truth
                  </h3>
                  <p className="text-[11px] text-on-surface-variant">
                    Tout compte avec la permission Journal CVE peut définir cette version.
                    La modification est liée au compte (comme les interventions développeurs).
                  </p>
                  {selected.officialStableVersion && (
                    <p className="text-sm">
                      Actuelle :{" "}
                      <span className="font-mono font-bold text-on-surface">
                        {selected.officialStableVersion}
                      </span>
                      {selected.officialUpdatedBy && (
                        <span className="text-outline text-xs">
                          {" "}· par {selected.officialUpdatedBy}
                          {selected.officialUpdatedAt
                            ? ` · ${selected.officialUpdatedAt.replace("T", " ").slice(0, 16)}`
                            : ""}
                        </span>
                      )}
                    </p>
                  )}
                  {selected.officialComment && (
                    <p className="text-xs text-on-surface-variant italic">
                      « {selected.officialComment} »
                    </p>
                  )}
                  <div className="space-y-2">
                    <input
                      value={stableVersion}
                      onChange={(e) => setStableVersion(e.target.value)}
                      placeholder="Ex: 10.1.42"
                      className="w-full rounded-xl border border-outline-variant/30 bg-surface-container-lowest px-3 py-2 text-sm font-mono outline-none focus:border-tertiary/50"
                    />
                    <textarea
                      value={comment}
                      onChange={(e) => setComment(e.target.value)}
                      placeholder="Commentaire / raison métier…"
                      rows={3}
                      className="w-full rounded-xl border border-outline-variant/30 bg-surface-container-lowest px-3 py-2 text-sm outline-none focus:border-tertiary/50 resize-none"
                    />
                    {currentLogin && (
                      <p className="text-[10px] text-outline">
                        Sera enregistré sous votre compte :{" "}
                        <span className="text-on-surface font-medium">{currentLogin}</span>
                      </p>
                    )}
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={saving}
                        onClick={() => void handleSaveOfficial()}
                        className="rounded-xl bg-primary px-4 py-2 text-sm font-semibold text-on-primary disabled:opacity-60"
                      >
                        {saving ? "Enregistrement…" : "Enregistrer version officielle"}
                      </button>
                      {selected.guidanceId && (
                        <button
                          type="button"
                          disabled={saving}
                          onClick={() => void handleClearOfficial()}
                          className="rounded-xl border border-outline-variant/30 px-4 py-2 text-sm text-outline hover:text-error"
                        >
                          Supprimer
                        </button>
                      )}
                    </div>
                  </div>
                </div>

                {pendingDeviations.filter(
                  (d) => d.cveId?.toLowerCase() === selected.cveId?.toLowerCase(),
                ).length > 0 && (
                  <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-3 space-y-2">
                    <h3 className="text-[11px] font-bold uppercase tracking-widest text-amber-200 flex items-center gap-1">
                      <span className="material-symbols-outlined text-sm">gavel</span>
                      Écart en attente — validation chef
                    </h3>
                    {pendingDeviations
                      .filter((d) => d.cveId?.toLowerCase() === selected.cveId?.toLowerCase())
                      .map((d) => (
                        <div key={d.id} className="space-y-2">
                          <p className="text-xs text-on-surface-variant">
                            <span className="font-mono text-error">{d.proposedVersion}</span>
                            {" ≠ chef "}
                            <span className="font-mono text-tertiary">{d.officialVersion}</span>
                            {" · demandé par "}
                            <span className="text-primary font-medium">{d.requestedByLogin}</span>
                          </p>
                          <p className="text-[11px] text-outline line-clamp-3">{d.reason}</p>
                          <div className="flex gap-2">
                            <button
                              type="button"
                              disabled={pendingBusyId === d.id}
                              onClick={async () => {
                                setPendingBusyId(d.id);
                                try {
                                  const res = await approvePolicyDeviation(d.id);
                                  if (res.data?.commitFailed || res.data?.error || res.data?.status === 'COMMIT_FAILED') {
                                    setError(res.data.error || res.data.errorMessage || 'Le commit Git a échoué.');
                                    return;
                                  }
                                  setPendingDeviations((prev) => prev.filter((x) => x.id !== d.id));
                                  setMessage(
                                    `Dérogation acceptée — commit au nom de ${d.requestedByLogin}`
                                      + (res.data.commitUrl ? ` : ${res.data.commitUrl}` : ""),
                                  );
                                  void load(false);
                                  void loadTimeline(selected);
                                } catch (err: any) {
                                  setError(extractApiError(err, "Échec acceptation."));
                                } finally {
                                  setPendingBusyId(null);
                                }
                              }}
                              className="flex-1 rounded-xl bg-tertiary/20 text-tertiary px-3 py-2 text-[11px] font-bold disabled:opacity-50"
                            >
                              Accepter → commit
                            </button>
                            <button
                              type="button"
                              disabled={pendingBusyId === d.id}
                              onClick={() => setRejectTarget(d)}
                              className="flex-1 rounded-xl bg-error/15 text-error px-3 py-2 text-[11px] font-bold disabled:opacity-50"
                            >
                              Refuser
                            </button>
                          </div>
                        </div>
                      ))}
                  </div>
                )}

                <div className="space-y-2">
                  <h3 className="text-[11px] font-bold uppercase tracking-widest text-outline">
                    Timeline d’audit
                  </h3>
                  {timelineLoading ? (
                    <p className="text-xs text-outline">Chargement…</p>
                  ) : timeline.length === 0 ? (
                    <p className="text-xs text-outline">Pas encore d’événements d’audit pour ce CVE.</p>
                  ) : (
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {timeline.map((ev, idx) => (
                        <div
                          key={`${ev.id ?? "s"}-${idx}`}
                          className="rounded-xl bg-surface-container-high px-3 py-2 text-xs border-l-2 border-primary/40"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-primary">{eventLabel(ev.eventType)}</span>
                            <span className="text-[10px] text-outline">
                              {ev.createdAt?.replace("T", " ").slice(0, 16)}
                            </span>
                          </div>
                          <p className="text-on-surface-variant mt-1">
                            {ev.actorLogin && <span className="text-on-surface font-medium">{ev.actorLogin} · </span>}
                            {ev.fromVersion && ev.toVersion
                              ? `${ev.fromVersion} → ${ev.toVersion}`
                              : ev.toVersion
                                ? `→ ${ev.toVersion}`
                                : null}
                            {ev.officialVersion ? ` · chef ${ev.officialVersion}` : ""}
                          </p>
                          {ev.message && (
                            <p className="text-outline mt-1 line-clamp-2">{ev.message}</p>
                          )}
                          {ev.synthetic && (
                            <p className="text-[10px] text-outline/70 mt-0.5">reconstruit depuis l’historique</p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <h3 className="text-[11px] font-bold uppercase tracking-widest text-outline">
                    Interventions développeurs
                  </h3>
                  {(selected.developerInterventions?.length ?? 0) === 0 ? (
                    <p className="text-xs text-outline">Pas encore de modification manuelle mémorisée.</p>
                  ) : (
                    selected.developerInterventions!.map((it) => (
                      <div key={it.id} className="rounded-xl bg-surface-container-high px-3 py-2 text-xs">
                        <p className="text-on-surface">
                          <span className="text-primary font-medium">{it.createdByLogin || "Dev"}</span>
                          {" a passé "}
                          <span className="font-mono">{it.fromVersion || "?"}</span>
                          {" → "}
                          <span className="font-mono text-tertiary">{it.toVersion || "?"}</span>
                        </p>
                        <p className="text-on-surface-variant mt-1">{it.reason || "Sans commentaire"}</p>
                      </div>
                    ))
                  )}
                </div>
              </>
            )}
          </aside>
        </div>
      )}

      <RejectReasonModal
        open={!!rejectTarget}
        busy={rejectTarget != null && pendingBusyId === rejectTarget.id}
        title="Refuser la dérogation"
        subtitle={
          rejectTarget
            ? `${rejectTarget.cveId} · ${rejectTarget.packageName} — ${rejectTarget.proposedVersion} ≠ chef ${rejectTarget.officialVersion}. Le développeur (${rejectTarget.requestedByLogin}) sera notifié.`
            : undefined
        }
        onCancel={() => {
          if (pendingBusyId != null) return;
          setRejectTarget(null);
        }}
        onConfirm={(motif) => {
          if (!rejectTarget) return;
          const target = rejectTarget;
          void (async () => {
            setPendingBusyId(target.id);
            try {
              await rejectPolicyDeviation(target.id, motif || undefined);
              setPendingDeviations((prev) => prev.filter((x) => x.id !== target.id));
              setMessage("Dérogation refusée — le développeur a été notifié.");
              setRejectTarget(null);
            } catch (err: any) {
              setError(extractApiError(err, "Échec refus."));
            } finally {
              setPendingBusyId(null);
            }
          })();
        }}
      />
    </div>
  );
};

export default CveJournal;
