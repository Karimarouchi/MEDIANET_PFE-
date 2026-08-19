import React, { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import {
  approvePolicyDeviation,
  clearAllNotifications,
  getNotifications,
  getUnreadNotificationCount,
  markAllNotificationsRead,
  markNotificationRead,
  rejectPolicyDeviation,
  type AppNotificationDto,
} from "../services/api";
import RejectReasonModal from "./RejectReasonModal";

const NotificationBell: React.FC = () => {
  const { hasPermission, user } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<AppNotificationDto[]>([]);
  const [unread, setUnread] = useState(0);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [clearing, setClearing] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [rejectNotif, setRejectNotif] = useState<AppNotificationDto | null>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const isChef = hasPermission("CVE_JOURNAL") || user?.systemRole === "ADMIN";

  const refresh = useCallback(async () => {
    try {
      const [listRes, countRes] = await Promise.all([
        getNotifications(),
        getUnreadNotificationCount(),
      ]);
      setItems(listRes.data || []);
      setUnread(countRes.data?.count ?? 0);
    } catch {
      /* ignore poll errors */
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 20000);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    if (!open) return;
    void refresh();
    const onDoc = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDoc);
    return () => document.removeEventListener("mousedown", onDoc);
  }, [open, refresh]);

  const handleClickNotif = async (n: AppNotificationDto) => {
    if (!n.read) {
      try {
        await markNotificationRead(n.id);
        setUnread((u) => Math.max(0, u - 1));
        setItems((prev) =>
          prev.map((x) => (x.id === n.id ? { ...x, read: true } : x)),
        );
      } catch {
        /* ignore */
      }
    }
    if (n.link) {
      if (n.link.startsWith("http")) {
        window.open(n.link, "_blank", "noopener,noreferrer");
      } else {
        navigate(n.link);
        setOpen(false);
      }
    }
  };

  const handleApprove = async (n: AppNotificationDto) => {
    if (!n.relatedRequestId) return;
    setBusyId(n.id);
    setActionError(null);
    try {
      const res = await approvePolicyDeviation(n.relatedRequestId);
      await refresh();
      if (res.data.commitUrl) {
        window.open(res.data.commitUrl, "_blank", "noopener,noreferrer");
      }
    } catch (err: any) {
      setActionError(
        err?.response?.data?.message
          || err?.response?.data?.error
          || err?.message
          || "Échec de l’acceptation.",
      );
    } finally {
      setBusyId(null);
    }
  };

  const submitReject = async (n: AppNotificationDto, comment: string) => {
    if (!n.relatedRequestId) return;
    setBusyId(n.id);
    setActionError(null);
    try {
      await rejectPolicyDeviation(n.relatedRequestId, comment || undefined);
      setRejectNotif(null);
      await refresh();
    } catch (err: any) {
      setActionError(
        err?.response?.data?.message
          || err?.response?.data?.error
          || err?.message
          || "Échec du refus.",
      );
    } finally {
      setBusyId(null);
    }
  };

  const handleClearAll = async () => {
    if (items.length === 0 || clearing) return;
    setClearing(true);
    setActionError(null);
    try {
      await clearAllNotifications();
      setItems([]);
      setUnread(0);
    } catch (err: any) {
      setActionError(
        err?.response?.data?.message
          || err?.response?.data?.error
          || err?.message
          || "Impossible de supprimer les notifications.",
      );
    } finally {
      setClearing(false);
    }
  };

  return (
    <div className="relative" ref={panelRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-3 px-4 py-2.5 font-headline text-sm font-medium w-full rounded-lg transition-colors duration-200 text-slate-500 hover:bg-surface-container hover:text-primary"
        title="Notifications"
      >
        <span className="relative material-symbols-outlined text-base">
          notifications
          {unread > 0 && (
            <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-error text-on-error text-[9px] font-bold flex items-center justify-center">
              {unread > 99 ? "99+" : unread}
            </span>
          )}
        </span>
        <span>Notifications</span>
      </button>

      {open && (
        <div className="absolute left-full bottom-0 ml-2 w-96 max-h-[70vh] overflow-hidden rounded-2xl border border-outline-variant/30 bg-surface-container shadow-2xl z-[80] flex flex-col">
          <div className="flex items-center justify-between gap-2 px-4 py-3 border-b border-outline-variant/20">
            <p className="text-sm font-bold text-on-surface">Notifications</p>
            <div className="flex items-center gap-3 shrink-0">
              <button
                type="button"
                onClick={() => void markAllNotificationsRead().then(() => refresh())}
                className="text-[10px] text-primary hover:underline disabled:opacity-40"
                disabled={items.length === 0}
              >
                Tout marquer lu
              </button>
              <button
                type="button"
                onClick={() => void handleClearAll()}
                disabled={items.length === 0 || clearing}
                className="text-[10px] text-error/90 hover:underline disabled:opacity-40"
                title="Supprimer toutes les notifications"
              >
                {clearing ? "Suppression…" : "Tout supprimer"}
              </button>
            </div>
          </div>
          {actionError && (
            <p className="px-4 py-2 text-[11px] text-error border-b border-error/20">{actionError}</p>
          )}
          <div className="overflow-y-auto flex-1 divide-y divide-outline-variant/15">
            {items.length === 0 && (
              <p className="p-6 text-xs text-outline text-center">Aucune notification.</p>
            )}
            {items.map((n) => (
              <div
                key={n.id}
                className={`px-4 py-3 ${n.read ? "opacity-70" : "bg-primary/5"}`}
              >
                <button
                  type="button"
                  onClick={() => void handleClickNotif(n)}
                  className="w-full text-left"
                >
                  <p className="text-xs font-semibold text-on-surface">{n.title}</p>
                  <p className="text-[11px] text-on-surface-variant mt-1 line-clamp-3">
                    {n.message}
                  </p>
                  <p className="text-[10px] text-outline mt-1">
                    {n.createdAt?.replace("T", " ").slice(0, 16)}
                    {(n.type === "DEVIATION_APPROVED"
                      || n.type === "DEVIATION_REJECTED"
                      || n.type === "DEVIATION_COMMIT_FAILED") && (
                      <span className="ml-2 text-outline/70">· visible 15 min</span>
                    )}
                    {n.type === "SCAN_COMPLETED" && (
                      <span className="ml-2 text-primary">· rapport du scan</span>
                    )}
                    {n.type === "SCAN_FAILED" && (
                      <span className="ml-2 text-error">· scan en échec</span>
                    )}
                  </p>
                </button>
                {isChef && n.type === "DEVIATION_REQUEST" && n.relatedRequestId && (
                  <div className="flex gap-2 mt-2">
                    <button
                      type="button"
                      disabled={busyId === n.id}
                      onClick={() => void handleApprove(n)}
                      className="flex-1 rounded-lg bg-tertiary/20 text-tertiary text-[11px] font-bold py-1.5 disabled:opacity-50"
                    >
                      {busyId === n.id ? "…" : "Accepter → commit auto"}
                    </button>
                    <button
                      type="button"
                      disabled={busyId === n.id}
                      onClick={() => setRejectNotif(n)}
                      className="flex-1 rounded-lg bg-error/15 text-error text-[11px] font-bold py-1.5 disabled:opacity-50"
                    >
                      Refuser
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <RejectReasonModal
        open={!!rejectNotif}
        busy={rejectNotif != null && busyId === rejectNotif.id}
        title="Refuser la dérogation"
        subtitle={
          rejectNotif
            ? rejectNotif.title || "Le développeur sera notifié. Aucun commit ne sera effectué."
            : undefined
        }
        onCancel={() => {
          if (busyId != null) return;
          setRejectNotif(null);
        }}
        onConfirm={(motif) => {
          if (!rejectNotif) return;
          void submitReject(rejectNotif, motif);
        }}
      />
    </div>
  );
};

export default NotificationBell;
