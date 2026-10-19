// Reads CI step output (Vitest, Jest, Maven/Surefire, pytest, Vulnix gate) into results anyone can read.

// eslint-disable-next-line no-control-regex -- ESC is exactly what these patterns look for
const ANSI = /\x1b\[[0-9;]*m/g;
// eslint-disable-next-line no-control-regex
const SGR = /\x1b\[([0-9;]*)m/g;

export function stripAnsi(line: string): string {
  return line.replace(ANSI, "");
}

export type AnsiSpan = { text: string; className: string };

const FG: Record<number, string> = {
  30: "text-slate-400", 31: "text-red-400", 32: "text-green-400", 33: "text-amber-300", 34: "text-sky-400",
  35: "text-fuchsia-300", 36: "text-cyan-300", 37: "text-slate-200",
  90: "text-slate-500", 91: "text-red-300", 92: "text-green-300", 93: "text-amber-200", 94: "text-sky-300",
  95: "text-fuchsia-200", 96: "text-cyan-200", 97: "text-white",
};
const BG: Record<number, string> = {
  41: "bg-red-900/70 text-white", 42: "bg-green-900/70 text-white", 43: "bg-amber-900/70 text-white",
  44: "bg-sky-900/70 text-white", 45: "bg-fuchsia-900/70 text-white", 46: "bg-cyan-900/70 text-white",
};

/** A log line cut into coloured pieces instead of showing the raw "[33m" codes. */
export function ansiSpans(line: string): AnsiSpan[] {
  const out: AnsiSpan[] = [];
  let fg = "";
  let bg = "";
  let bold = false;
  let dim = false;
  let last = 0;
  const push = (text: string) => {
    if (!text) return;
    out.push({ text, className: [fg, bg, bold ? "font-bold" : "", dim ? "opacity-70" : ""].filter(Boolean).join(" ") });
  };
  SGR.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = SGR.exec(line)) !== null) {
    push(line.slice(last, m.index));
    last = m.index + m[0].length;
    for (const code of (m[1] || "0").split(";").map(Number)) {
      if (code === 0) { fg = ""; bg = ""; bold = false; dim = false; }
      else if (code === 1) bold = true;
      else if (code === 2) dim = true;
      else if (code === 22) { bold = false; dim = false; }
      else if (code === 39) fg = "";
      else if (code === 49) bg = "";
      else if (FG[code]) fg = FG[code];
      else if (BG[code]) bg = BG[code];
    }
  }
  push(line.slice(last));
  return out;
}

/** Lines worth a red mark in the output: failures, errors, blocking findings. */
export function isErrorLine(line: string): boolean {
  const l = stripAnsi(line).trim();
  return /^(FAIL\b|×|✗|✕|●|npm (ERR!|error)|\[ERROR\]|\[FATAL\]|FAILED\b|E\s{2,}|BLOQUANT\b|Error:|error TS\d+|Barriere Vulnix : ECHEC)/.test(l)
    || /\b(\d+) failed\b/.test(l);
}

export type FailedTest = { file: string | null; name: string; reason: string | null };

/** Testing-library / assertion messages in plain French; anything else is kept as it is (shortened). */
export function frenchReason(raw: string | null): string | null {
  if (!raw) return null;
  const r = stripAnsi(raw).trim().replace(/^\w*Error:\s*/, "");
  let m = /Found multiple elements with the (?:text|role|label text): (.+?)(?:\.|$)/.exec(r);
  if (m) return `« ${m[1].trim()} » apparaît plusieurs fois à l'écran, alors que le test en attend un seul.`;
  m = /Unable to find an accessible element with the role "(.+?)" and name "(.+?)"/.exec(r);
  if (m) return `Aucun élément « ${m[1]} » nommé exactement « ${m[2]} » à l'écran.`;
  m = /Unable to find an element with the (?:text|label text|placeholder text|display value): (.+?)(?:\.|$)/.exec(r);
  if (m) return `« ${m[1].trim()} » n'est pas affiché à l'écran.`;
  m = /expected:? <?(.+?)>? but was:? <?(.+?)>?$/.exec(r);
  if (m) return `Valeur attendue ${m[1]}, valeur obtenue ${m[2]}.`;
  m = /^expected (.+?) to (?:be|equal|deeply equal|strictly equal) (.+)$/.exec(r);
  if (m) return `Valeur obtenue ${m[1]}, valeur attendue ${m[2]}.`;
  if (/Timeout|timed out/i.test(r)) return "Le test a dépassé le temps imparti.";
  return r.length > 180 ? `${r.slice(0, 180)}…` : r;
}

const REASON_LINE = /^(\w*Error\b|AssertionError|expected\b|Expected\b|→|Unable to find|Found multiple|Received\b)/;

/** Tests that failed in a step's output, with the first explanation found for each. */
export function failedTests(raw: string[]): FailedTest[] {
  const lines = raw.map(stripAnsi);
  const out: FailedTest[] = [];
  const seen = new Set<string>();
  const add = (file: string | null, name: string, reason: string | null) => {
    const key = `${file ?? ""}|${name}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ file, name, reason: frenchReason(reason) });
  };
  const reasonAfter = (i: number) => {
    let fallback: string | null = null;
    for (let j = i + 1; j < Math.min(lines.length, i + 16); j++) {
      const t = lines[j].trim();
      // Jest: "Expected: 200" then "Received: 401" says more than "expect(received).toBe(expected)".
      const exp = /^Expected:?\s+(.+)$/.exec(t);
      const rec = exp && lines.slice(j + 1, j + 4).map((x) => /^\s*Received:?\s+(.+)$/.exec(x)).find(Boolean);
      if (exp && rec) return `expected: ${exp[1]} but was: ${rec[1]}`;
      if (/^(FAIL|●)\s/.test(t)) break;
      if (!fallback && /^expect\(/.test(t)) fallback = t;
      if (t && !/^expect\(/.test(t) && REASON_LINE.test(t)) return t.replace(/^→\s*/, "");
    }
    return fallback;
  };

  let jestFile: string | null = null;
  lines.forEach((l, i) => {
    const t = l.trim();
    // Vitest: "FAIL  src/a.test.jsx > Suite > test name"
    let m = /^FAIL\s+(\S+)\s+>\s+(.+)$/.exec(t);
    if (m) return add(m[1], m[2].replace(/\s+>\s+/g, " › "), reasonAfter(i));
    // Jest: "FAIL src/a.test.tsx" then "● Suite › test name"
    m = /^FAIL\s+(\S+\.\w+)\s*(\(.*\))?$/.exec(t);
    if (m) { jestFile = m[1]; return; }
    m = /^●\s+(.+›.+)$/.exec(t);
    if (m && !/Console$/.test(m[1])) return add(jestFile, m[1].trim(), reasonAfter(i));
    // Maven Surefire summary: "[ERROR]   FooTest.bar:42 expected: <1> but was: <2>"
    m = /^\[ERROR\]\s{2,}(\w+)\.(\w+)(?::(\d+))?\s*(?:»\s*)?(.*)$/.exec(l);
    if (m && /Test/.test(m[1])) return add(`${m[1]}.java${m[3] ? `:${m[3]}` : ""}`, `${m[1]} › ${m[2]}`, m[4] || null);
    // pytest: "FAILED tests/test_a.py::test_b - AssertionError: msg"
    m = /^FAILED\s+(\S+?)::(\S+)(?:\s+-\s+(.*))?$/.exec(t);
    if (m) return add(m[1], m[2].replace(/::/g, " › "), m[3] || null);
  });
  return out;
}

export type VulnixFinding = { severity: string; cve: string; pkg: string; kev: boolean };
export type VulnixReport = {
  passed: boolean | null;
  blocking: VulnixFinding[];
  accepted: number;
  reportUrl: string | null;
};

/** The Vulnix gate step: blocking findings, accepted exceptions, verdict and report link. */
export function vulnixReport(raw: string[]): VulnixReport {
  const blocking: VulnixFinding[] = [];
  let accepted = 0;
  let reportUrl: string | null = null;
  let passed: boolean | null = null;
  for (const l of raw.map(stripAnsi)) {
    let m = /^\s*BLOQUANT\s+(\S+)\s+(\S+)\s*(.*?)\s*$/.exec(l);
    if (m) {
      const kev = /\(KEV\)$/.test(m[3]);
      blocking.push({ severity: m[1].toUpperCase(), cve: m[2], pkg: m[3].replace(/\s*\(KEV\)$/, ""), kev });
      continue;
    }
    m = /^\s*(\d+) vulnerabilite\(s\) acceptee\(s\)/.exec(l);
    if (m) { accepted = Number(m[1]); continue; }
    m = /^Rapport : (\S+)/.exec(l);
    if (m && m[1] !== "None") { reportUrl = m[1]; continue; }
    if (/^Barriere Vulnix : OK/.test(l)) passed = true;
    if (/^Barriere Vulnix : ECHEC/.test(l)) passed = false;
  }
  return { passed, blocking, accepted, reportUrl };
}

const SEVERITY_FR: Record<string, [string, string]> = {
  CRITICAL: ["critique", "critiques"], HIGH: ["élevée", "élevées"], MEDIUM: ["moyenne", "moyennes"], LOW: ["faible", "faibles"],
};

/** "104 vulnérabilités bloquantes : 12 critiques, 90 élevées, dont 2 exploitées (KEV)". */
export function vulnixSummary(r: VulnixReport): string | null {
  if (r.passed === true) {
    return r.accepted > 0
      ? `Aucune vulnérabilité bloquante (${r.accepted} acceptée${r.accepted > 1 ? "s" : ""} par une exception validée).`
      : "Aucune vulnérabilité bloquante.";
  }
  if (r.blocking.length === 0) return null;
  const counts = new Map<string, number>();
  for (const f of r.blocking) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
  const parts = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    .filter((s) => counts.get(s))
    .map((s) => `${counts.get(s)} ${SEVERITY_FR[s][counts.get(s)! > 1 ? 1 : 0]}`);
  const kev = r.blocking.filter((f) => f.kev).length;
  const n = r.blocking.length;
  return `${n} vulnérabilité${n > 1 ? "s" : ""} bloquante${n > 1 ? "s" : ""} : ${parts.join(", ")}`
    + (kev ? `, dont ${kev} activement exploitée${kev > 1 ? "s" : ""} (KEV)` : "") + ".";
}

/** Packages that carry the most blocking findings, to know what to update first. */
export function topPackages(r: VulnixReport, limit = 5): { pkg: string; count: number }[] {
  const by = new Map<string, number>();
  for (const f of r.blocking) if (f.pkg) by.set(f.pkg, (by.get(f.pkg) ?? 0) + 1);
  return Array.from(by.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit).map(([pkg, count]) => ({ pkg, count }));
}
