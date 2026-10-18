import React from "react";
import { DueSslAlert, sslAlertSentence, sslAlertUrgent } from "../utils/sslAlert";

const tone = (urgent: boolean) =>
  urgent ? "border-error/40 bg-error/10 text-error" : "border-amber-500/40 bg-amber-500/10 text-amber-300";

/** Banner at the top of the project page, on every tab, while the alert is due. */
export const SslAlertBanner: React.FC<{ alert: DueSslAlert; onOpenSsl: () => void }> = ({ alert, onOpenSsl }) => {
  const urgent = sslAlertUrgent(alert.daysLeft);
  return (
    <div role="alert" className={`flex flex-wrap items-center justify-between gap-3 rounded-2xl border px-4 py-3 ${tone(urgent)}`}>
      <span className="flex items-center gap-3">
        <span className="material-symbols-outlined text-xl">notification_important</span>
        <span>
          <span className="block text-[10px] font-bold uppercase tracking-widest">Alerte SSL</span>
          <span className="block text-sm text-on-surface">{sslAlertSentence(alert.domain, alert.expiresOn, alert.daysLeft)}</span>
        </span>
      </span>
      <button type="button" onClick={onOpenSsl} className="shrink-0 text-xs font-semibold underline">
        Voir le domaine
      </button>
    </div>
  );
};

/** Window shown when entering the project on the alert day (once a day). */
export const SslAlertDialog: React.FC<{ alert: DueSslAlert; onClose: () => void; onOpenSsl: () => void }> = ({
  alert,
  onClose,
  onOpenSsl,
}) => {
  const urgent = sslAlertUrgent(alert.daysLeft);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="ssl-alert-title"
        onClick={(event) => event.stopPropagation()}
        className={`w-full max-w-md rounded-3xl border bg-surface-container-high p-6 shadow-2xl ${urgent ? "border-error/50" : "border-amber-500/50"}`}
      >
        <div className={`flex items-center gap-2 ${urgent ? "text-error" : "text-amber-300"}`}>
          <span className="material-symbols-outlined text-2xl">notification_important</span>
          <h2 id="ssl-alert-title" className="font-headline text-lg font-bold">Alerte SSL · {alert.domain}</h2>
        </div>
        <p className="mt-4 text-sm text-on-surface">{sslAlertSentence(alert.domain, alert.expiresOn, alert.daysLeft)}</p>
        {alert.daysLeft != null && alert.daysLeft >= 0 && (
          <p className={`mt-4 font-headline text-5xl font-bold ${urgent ? "text-error" : "text-amber-300"}`}>
            {alert.daysLeft} <span className="text-base font-semibold">jour{alert.daysLeft > 1 ? "s" : ""} restant{alert.daysLeft > 1 ? "s" : ""}</span>
          </p>
        )}
        <p className="mt-4 text-xs text-outline">
          Renouvelez le certificat, puis relancez un scan SSL. Pour ne plus voir l'alerte, effacez la date dans la carte « Domaine et SSL ».
        </p>
        <div className="mt-6 flex flex-wrap justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-xl px-4 py-2 text-sm font-semibold text-on-surface-variant hover:text-on-surface">
            J'ai compris
          </button>
          <button
            type="button"
            autoFocus
            onClick={onOpenSsl}
            className="rounded-xl border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-semibold text-primary hover:bg-primary/20"
          >
            Voir le domaine
          </button>
        </div>
      </div>
    </div>
  );
};

/** Dashboard block: every project whose alert day has come. */
export const SslAlertsPanel: React.FC<{ alerts: DueSslAlert[]; onOpen: (clientId: number) => void }> = ({ alerts, onOpen }) => {
  if (alerts.length === 0) return null;
  const urgent = alerts.some((a) => sslAlertUrgent(a.daysLeft));
  return (
    <section role="alert" className={`rounded-2xl border p-4 ${tone(urgent)}`}>
      <p className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-widest">
        <span className="material-symbols-outlined text-base">notification_important</span>
        Alertes SSL · {alerts.length} projet{alerts.length > 1 ? "s" : ""}
      </p>
      <ul className="mt-2 divide-y divide-outline-variant/[0.15]">
        {alerts.map((a) => (
          <li key={a.clientId}>
            <button
              type="button"
              onClick={() => onOpen(a.clientId)}
              className="flex w-full flex-wrap items-center justify-between gap-2 py-2 text-left hover:opacity-90"
            >
              <span className="text-sm text-on-surface">
                <span className="font-semibold">{a.project}</span> · {sslAlertSentence(a.domain, a.expiresOn, a.daysLeft)}
              </span>
              <span className="text-xs font-semibold underline">Ouvrir le projet</span>
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
};
