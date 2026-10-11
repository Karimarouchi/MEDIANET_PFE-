import { computeProgress, formatIdle, parseLogLine, STAGES, type LogEntry } from "./scanLog";

const T0 = new Date(2026, 9, 11, 1, 0, 0);
const feed = (lines: string[]): LogEntry[] => lines.map((l, i) => parseLogLine(l, new Date(T0.getTime() + i * 1000)));

describe("parseLogLine", () => {
  test("tags get their own source, the scanner's UTC stamp is dropped", () => {
    expect(parseLogLine("[SBOM] 1325 packages").source).toBe("sbom");
    expect(parseLogLine("[NVD] Enrichissement de 4 CVE").source).toBe("nvd");
    expect(parseLogLine("[OSV] GHSA-xxx : 404").source).toBe("nvd");
    expect(parseLogLine("[EPSS] 2008 CVE(s) enrichies").source).toBe("risk");
    expect(parseLogLine("[SUPPLY-CHAIN] Terminé").source).toBe("ml");
    expect(parseLogLine("[SECRETS] Tri par le modèle").source).toBe("ml");
    expect(parseLogLine("[ERROR] boom").source).toBe("error");
    const e = parseLogLine("[2026-10-10T23:56:21Z] [1/6] gitleaks — secret scanning...");
    expect(e.text).toBe("[1/6] gitleaks — secret scanning...");
    expect(e.source).toBe("secrets");
  });

  test("scanner lines without tag are coloured by tool", () => {
    expect(parseLogLine("[2026-10-10T23:57:56Z] [2/6] semgrep — static analysis...").source).toBe("sast");
    expect(parseLogLine("[2026-10-11T00:01:08Z] trivy: 199 CVEs found").source).toBe("cve");
    expect(parseLogLine("[2026-10-11T00:00:45Z] [3b] maven-cyclonedx — SBOM ready").source).toBe("sbom");
    expect(parseLogLine("something else").source).toBe("other");
  });
});

describe("computeProgress", () => {
  const LOG = [
    "[2026-10-10T23:56:20Z] Cloning into '/workspace/repo'...",
    "[2026-10-10T23:56:21Z] [1/6] gitleaks — secret scanning...",
    "[2026-10-10T23:56:26Z] credsweeper — second secret detector...",
    "[2026-10-10T23:57:56Z] [2/6] semgrep — static analysis...",
    "[2026-10-10T23:59:55Z] [3/6] syft — SBOM generation...",
    "[2026-10-11T00:01:08Z] trivy: 199 CVEs found",
    "[2026-10-11T00:01:09Z] [4b] trivy SBOM: 1325 packages",
  ];

  test("stages before the current one are done, the current one is active, the rest wait", () => {
    const p = computeProgress(feed(LOG), false, T0.getTime() + 8000);
    const state = Object.fromEntries(p.stages.map((s) => [s.def.id, s.state]));
    expect(state.clone).toBe("done");
    expect(state.secrets).toBe("done");
    expect(state.sast).toBe("done");
    expect(state.cve).toBe("active");
    expect(state.enrich).toBe("pending");
    expect(state.ml).toBe("pending");
    expect(p.percent).toBeGreaterThan(40);
    expect(p.percent).toBeLessThan(100);
  });

  test("never reaches 100 % before the completion marker: the ML stage ends the scan", () => {
    const withMl = feed([...LOG, "[NVD] Enrichissement de 4 CVE", "[SUPPLY-CHAIN] Terminé : 377 analysées — 1 connu(s) malveillant(s), 0 confiance élevée, 2 à vérifier."]);
    const running = computeProgress(withMl, false);
    expect(running.percent).toBeLessThan(100);
    expect(running.stages.find((s) => s.def.id === "ml")!.state).toBe("active");
    const done = computeProgress(withMl, true);
    expect(done.percent).toBe(100);
    expect(done.stages.every((s) => s.state === "done")).toBe(true);
  });

  test("counters follow the log", () => {
    const p = computeProgress(
      feed([...LOG, "[INFO] TruffleHog — 8 secret(s) found", "[SUPPLY-CHAIN] Terminé : 377 analysées — 1 connu(s) malveillant(s), 0 confiance élevée, 2 à vérifier."]),
      false,
    );
    expect(p.counters.cves).toBe(199);
    expect(p.counters.packages).toBe(1325);
    expect(p.counters.secrets).toBe(8);
    expect(p.counters.suspects).toBe(3);
    expect(computeProgress([], false).counters.cves).toBeNull();
  });

  test("an empty log has nothing done and 0 %", () => {
    const p = computeProgress([], false);
    expect(p.percent).toBe(0);
    expect(p.stages.every((s) => s.state === "pending")).toBe(true);
    expect(p.stages).toHaveLength(STAGES.length);
  });
});

test("silence is only reported after 20 s", () => {
  expect(formatIdle(5000)).toBeNull();
  expect(formatIdle(40_000)).toBe("40 s");
  expect(formatIdle(300_000)).toBe("5 min");
  expect(formatIdle(null)).toBeNull();
});
