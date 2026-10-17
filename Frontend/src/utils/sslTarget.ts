/**
 * Cleans what the user pasted in the SSL field ("https://Site.com:8443/page?x") into "host" or "host:port",
 * with a message when it cannot be scanned. Same rules as the backend (SslTargetGuard), which checks again and
 * also refuses internal addresses.
 */
export type SslTargetCheck =
  | { ok: true; target: string; host: string; port: number; changed: boolean }
  | { ok: false; error: string };

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;

export function normalizeSslTarget(raw: string): SslTargetCheck {
  const input = (raw ?? '').trim();
  if (!input) return { ok: false, error: 'Indiquez un domaine, par exemple exemple.com ou exemple.com:8443.' };
  let s = input.toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  const cut = s.search(/[/?#]/);
  if (cut >= 0) s = s.slice(0, cut);
  if (s.includes('@')) return { ok: false, error: 'Le domaine ne doit pas contenir d\'identifiant (partie avant « @ »).' };
  if (s.startsWith('[') || (s.match(/:/g) ?? []).length > 1) {
    return { ok: false, error: 'Les adresses IPv6 ne sont pas prises en charge : indiquez un nom de domaine.' };
  }
  let port = 443;
  const colon = s.lastIndexOf(':');
  if (colon >= 0) {
    const p = s.slice(colon + 1);
    s = s.slice(0, colon);
    if (!/^\d{1,5}$/.test(p)) return { ok: false, error: `Port invalide : « ${p} ».` };
    port = Number(p);
    if (port < 1 || port > 65535) return { ok: false, error: 'Le port doit être compris entre 1 et 65535.' };
  }
  s = s.replace(/\.+$/, '');
  if (!s) return { ok: false, error: 'Indiquez un domaine, par exemple exemple.com.' };

  if (IPV4.test(s)) {
    if (s.split('.').some((n) => Number(n) > 255)) return { ok: false, error: `Adresse IP invalide : « ${s} ».` };
  } else {
    let ascii = s;
    try {
      // The URL parser applies IDNA (café.fr → xn--caf-dma.fr) like the backend's IDN.toASCII.
      ascii = new URL(`https://${s}`).hostname;
    } catch {
      return { ok: false, error: `Nom de domaine invalide : « ${s} ».` };
    }
    const labels = ascii.split('.');
    if (labels.length < 2) return { ok: false, error: `« ${s} » n'est pas un nom de domaine complet (exemple : site.com).` };
    if (ascii.length > 253 || labels.some((l) => !LABEL.test(l)) || /^\d+$/.test(labels[labels.length - 1])) {
      return { ok: false, error: `Nom de domaine invalide : « ${s} ».` };
    }
    s = ascii;
  }
  const target = port === 443 ? s : `${s}:${port}`;
  return { ok: true, target, host: s, port, changed: target !== input };
}
