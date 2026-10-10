import { buildDependencyRows, countViews, defaultView, filterRows, reasonLine } from "./dependencyView";

const pkg = (name: string, type = "npm") => ({ id: name, name, version: "1.0.0", type, language: "", purl: `pkg:${type}/${name}@1.0.0`, license: "MIT", location: "" });
const cve = (packageName: string, severity: string, extra: Record<string, unknown> = {}) =>
  ({ id: 1, cveId: "CVE-1", packageName, severity, fixedVersion: null, ...extra } as any);
const brief = (tier: string) => ({ tier } as any);

const build = (tiers: Record<string, string> = {}) =>
  buildDependencyRows(
    [pkg("clean"), pkg("low"), pkg("high"), pkg("crit"), pkg("kev"), pkg("evil"), pkg("maybe")],
    [
      cve("low", "LOW"),
      cve("high", "HIGH", { fixedVersion: "2.0.0" }),
      cve("crit", "CRITICAL"),
      cve("crit", "MEDIUM", { fixedVersion: "3.1.0" }),
      cve("kev", "HIGH", { kevListed: true }),
    ],
    (p) => (tiers[p.name] ? brief(tiers[p.name]) : null),
    () => null,
    () => true
  );

test("sorts malicious first, then critical/KEV CVEs, then the rest", () => {
  const order = build({ evil: "KNOWN_MALICIOUS", maybe: "REVIEW" }).map((r) => r.pkg.name);
  expect(order).toEqual(["evil", "crit", "kev", "high", "maybe", "low", "clean"]);
});

test("critical view counts malicious, critical and exploited, not plain HIGH", () => {
  const rows = build({ evil: "KNOWN_MALICIOUS" });
  const counts = countViews(rows);
  expect(counts).toEqual({ critical: 3, cve: 4, suspect: 1, all: 7 });
  expect(filterRows(rows, "critical", "", "").map((r) => r.pkg.name)).toEqual(["evil", "crit", "kev"]);
});

test("default view falls back when nothing is critical", () => {
  expect(defaultView({ critical: 0, cve: 2, suspect: 0, all: 5 })).toBe("cve");
  expect(defaultView({ critical: 0, cve: 0, suspect: 0, all: 5 })).toBe("all");
});

test("fix comes from the most severe CVE that has one, and search filters", () => {
  const rows = build();
  expect(rows.find((r) => r.pkg.name === "crit")?.fixedVersion).toBe("3.1.0");
  expect(filterRows(rows, "all", "HIG", "").map((r) => r.pkg.name)).toEqual(["high"]);
  expect(filterRows(rows, "all", "", "pypi")).toEqual([]);
});

test("reason line is a plain sentence", () => {
  const r = build().find((x) => x.pkg.name === "kev")!;
  expect(reasonLine(r)).toContain("exploitée activement");
  expect(reasonLine(build().find((x) => x.pkg.name === "clean")!)).toBe("");
});
