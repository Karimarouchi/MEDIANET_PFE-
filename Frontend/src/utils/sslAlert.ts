/**
 * SSL expiry alert chosen per project: from the chosen day on, the alert shows in the project (window + banner)
 * and on the dashboard, until the date is cleared or a new SSL scan finds a renewed certificate.
 */

/** Local calendar day as yyyy-MM-dd. */
export function ymdOf(date: Date): string {
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${date.getFullYear()}-${m}-${d}`;
}

function dayOf(ymd?: string | null): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})/.exec((ymd ?? "").trim());
  return match ? new Date(Number(match[1]), Number(match[2]) - 1, Number(match[3])) : null;
}

/** Whole days from today to the given day; negative once past. Null without a date. */
export function daysUntil(ymd?: string | null, today = new Date()): number | null {
  const target = dayOf(ymd);
  if (!target) return null;
  const start = new Date(today.getFullYear(), today.getMonth(), today.getDate());
  return Math.round((target.getTime() - start.getTime()) / 86_400_000);
}

export type DueSslAlert = {
  clientId: number;
  project: string;
  domain: string;
  alertDate: string;
  expiresOn: string | null;
  daysLeft: number | null;
};

type AlertSource = {
  id: number;
  name: string;
  domainName?: string | null;
  sslAlertDate?: string | null;
  sslCertExpiresOn?: string | null;
};

/** Alerts whose day has come (today or earlier), closest expiry first. */
export function dueSslAlerts(clients: AlertSource[], today = new Date()): DueSslAlert[] {
  const out: DueSslAlert[] = [];
  for (const c of clients) {
    const wait = daysUntil(c.sslAlertDate, today);
    if (wait == null || wait > 0) continue;
    out.push({
      clientId: c.id,
      project: c.name,
      domain: c.domainName?.trim() || c.name,
      alertDate: (c.sslAlertDate as string).slice(0, 10),
      expiresOn: c.sslCertExpiresOn ? c.sslCertExpiresOn.slice(0, 10) : null,
      daysLeft: daysUntil(c.sslCertExpiresOn, today),
    });
  }
  return out.sort((a, b) => (a.daysLeft ?? 99_999) - (b.daysLeft ?? 99_999));
}

function frenchDay(ymd: string): string {
  const d = dayOf(ymd);
  return d ? d.toLocaleDateString("fr-FR", { day: "numeric", month: "long", year: "numeric" }) : ymd;
}

/** "Le certificat de x expire le 19 décembre 2026, dans 62 jours." */
export function sslAlertSentence(domain: string, expiresOn: string | null, daysLeft: number | null): string {
  if (!expiresOn) return `Le dernier scan SSL de ${domain} n'indique pas de date d'expiration : relancez un scan SSL.`;
  const when = frenchDay(expiresOn);
  if (daysLeft != null && daysLeft < 0) return `Le certificat de ${domain} a expiré le ${when}.`;
  if (daysLeft === 0) return `Le certificat de ${domain} expire aujourd'hui (${when}).`;
  if (daysLeft === 1) return `Le certificat de ${domain} expire demain (${when}).`;
  return `Le certificat de ${domain} expire le ${when}${daysLeft != null ? `, dans ${daysLeft} jours` : ""}.`;
}

/** Red when 7 days or less remain (or expired), amber otherwise. */
export function sslAlertUrgent(daysLeft: number | null): boolean {
  return daysLeft != null && daysLeft <= 7;
}

const seenKey = (clientId: number) => `vulnix.sslAlertSeen.${clientId}`;

/** The window opens once a day per project; the banner stays. Storage may be unavailable: then it opens each visit. */
export function popupSeenToday(clientId: number, today = new Date()): boolean {
  try {
    return window.localStorage.getItem(seenKey(clientId)) === ymdOf(today);
  } catch {
    return false;
  }
}

export function markPopupSeen(clientId: number, today = new Date()): void {
  try {
    window.localStorage.setItem(seenKey(clientId), ymdOf(today));
  } catch {
    /* private window: the window simply shows again next visit */
  }
}
