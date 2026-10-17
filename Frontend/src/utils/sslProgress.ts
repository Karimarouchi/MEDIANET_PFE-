/**
 * Progress of an SSL scan read from its log lines ("[1/6] sslyze...", "[3/6] testssl.sh (timeout 600s)..."),
 * so the page can show "step 3 of 8 — testssl.sh, up to 10 min" instead of a raw log only. The scanner is unchanged.
 */
export type SslStep = { key: string; label: string; maxSeconds: number };

/** Order and time limit of each tool in scanner-image/scripts/run_ssl_scans.sh. */
export const SSL_STEPS: SslStep[] = [
  { key: 'sslyze', label: 'SSLyze (protocoles et suites)', maxSeconds: 180 },
  { key: 'sslscan', label: 'sslscan', maxSeconds: 120 },
  { key: 'testssl', label: 'testssl.sh (vulnérabilités)', maxSeconds: 600 },
  { key: 'nmap-enum', label: 'Nmap ssl-enum-ciphers', maxSeconds: 120 },
  { key: 'nmap-hb', label: 'Nmap Heartbleed', maxSeconds: 90 },
  { key: 'nikto', label: 'Nikto (serveur web)', maxSeconds: 600 },
  { key: 'whatweb', label: 'WhatWeb', maxSeconds: 60 },
  { key: 'summary', label: 'Certificat, en-têtes et synthèse', maxSeconds: 30 },
];

const MARKERS: Array<[RegExp, string]> = [
  [/\[1\/6\]\s*sslyze/i, 'sslyze'],
  [/\[2\/6\]\s*sslscan/i, 'sslscan'],
  [/\[3\/6\]\s*testssl/i, 'testssl'],
  [/\[4\/6\]\s*nmap/i, 'nmap-enum'],
  [/\[4b\/6\]\s*nmap/i, 'nmap-hb'],
  [/\[5\/6\]\s*nikto/i, 'nikto'],
  [/\[6\/6\]\s*whatweb/i, 'whatweb'],
  [/\[\+\]\s*Checking certificate/i, 'summary'],
];

export type SslProgress = {
  /** 0-based index of the step running, -1 before the first one. */
  index: number;
  step: SslStep | null;
  /** 0-100, counting finished steps by their time limit (testssl and nikto weigh most). */
  percent: number;
  /** Worst-case remaining time in seconds, from the time limits of the steps not finished. */
  maxRemainingSeconds: number;
  done: boolean;
  /** Waiting for a free scan worker (no tool started yet). */
  queued: boolean;
};

const TOTAL = SSL_STEPS.reduce((s, x) => s + x.maxSeconds, 0);

export function sslProgressFromLogs(lines: string[], finished = false): SslProgress {
  let index = -1;
  for (const line of lines) {
    for (const [re, key] of MARKERS) {
      if (re.test(line)) {
        const i = SSL_STEPS.findIndex((s) => s.key === key);
        if (i > index) index = i;
      }
    }
  }
  const done = finished || lines.some((l) => /SSL summary:/i.test(l));
  if (done) {
    return { index: SSL_STEPS.length - 1, step: null, percent: 100, maxRemainingSeconds: 0, done: true, queued: false };
  }
  const queued = index < 0 && lines.some((l) => /\[QUEUE\] Scan en file/.test(l))
    && !lines.some((l) => /\[QUEUE\] Scan pris en charge/.test(l));
  const before = SSL_STEPS.slice(0, Math.max(0, index)).reduce((s, x) => s + x.maxSeconds, 0);
  const remaining = SSL_STEPS.slice(Math.max(0, index)).reduce((s, x) => s + x.maxSeconds, 0);
  return {
    index,
    step: index >= 0 ? SSL_STEPS[index] : null,
    percent: Math.min(99, Math.round((before / TOTAL) * 100)),
    maxRemainingSeconds: remaining,
    done: false,
    queued,
  };
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} s`;
  const m = Math.round(seconds / 60);
  return `${m} min`;
}
