import type { CveDto } from "../services/api";
import { directParent, majorOf, remediationPlan, urgencyOf } from "./remediation";

const cve = (over: Partial<CveDto>): CveDto =>
  ({
    id: 1, cveId: "CVE-2026-0001", packageName: "lodash", packageVersion: "4.17.10", severity: "HIGH", cvssScore: 7.5,
    fixedVersion: "4.17.21", ecosystem: "npm", directOrTransitive: "DIRECT", dependencyScope: "runtime",
    exploitAvailable: false, kevListed: false, epssScore: 0.01, fixAvailable: true, ...over,
  }) as CveDto;

describe("urgency", () => {
  test("actively exploited is urgent, whatever the score", () => {
    expect(urgencyOf(cve({ kevListed: true, severity: "MEDIUM" })).urgency).toBe("URGENT");
  });
  test("public exploit + high severity is urgent; critical alone is high priority", () => {
    expect(urgencyOf(cve({ exploitAvailable: true })).urgency).toBe("URGENT");
    expect(urgencyOf(cve({ severity: "CRITICAL" })).urgency).toBe("HIGH");
    expect(urgencyOf(cve({ epssScore: 0.8, severity: "MEDIUM" })).urgency).toBe("HIGH");
  });
  test("a dev-only tool or a low severity is low priority", () => {
    expect(urgencyOf(cve({ dependencyScope: "dev" })).urgency).toBe("LOW");
    expect(urgencyOf(cve({ severity: "LOW" })).urgency).toBe("LOW");
    expect(urgencyOf(cve({})).urgency).toBe("NORMAL");
  });
});

describe("remediationPlan", () => {
  test("direct dependency with a fix: update command for its ecosystem", () => {
    const p = remediationPlan(cve({}));
    expect(p.kind).toBe("update-direct");
    expect(p.steps[0].code).toBe("npm install lodash@4.17.21");
    const py = remediationPlan(cve({ ecosystem: "pypi", packageName: "django", fixedVersion: "4.2.7", packageVersion: "4.2.1" }));
    expect(py.steps[0].code).toContain('pip install "django>=4.2.7"');
  });

  test("major upgrade warns about breaking changes and offers a backport alternative", () => {
    const p = remediationPlan(cve({ packageVersion: "1.2.9", fixedVersion: "2.0.1" }));
    expect(p.kind).toBe("update-major");
    expect(p.steps.some((s) => /majeure/.test(s.text))).toBe(true);
    expect(p.alternatives[0]).toMatch(/rétroporté/);
  });

  test("transitive dependency: names the parent and forces the version instead of a plain update", () => {
    const p = remediationPlan(cve({
      packageName: "follow-redirects", packageVersion: "1.5.0", fixedVersion: "1.15.6",
      directOrTransitive: "TRANSITIVE", dependencyPath: "app → axios → follow-redirects",
    }));
    expect(p.kind).toBe("override-transitive");
    expect(p.steps[0].text).toContain("axios");
    expect(p.steps[1].code).toBe('"overrides": { "follow-redirects": "1.15.6" }');
  });

  test("maven transitive: dependencyManagement snippet with group and artifact", () => {
    const p = remediationPlan(cve({
      ecosystem: "maven", packageName: "org.springframework:spring-webmvc", packageVersion: "6.1.6", fixedVersion: "6.1.14",
      directOrTransitive: "TRANSITIVE",
    }));
    expect(p.steps.find((s) => s.code)?.code).toContain("<artifactId>spring-webmvc</artifactId>");
  });

  test("no fixed version: workaround steps, never an invented version", () => {
    const p = remediationPlan(cve({ fixedVersion: null, fixAvailable: false }));
    expect(p.kind).toBe("no-fix");
    expect(p.steps.some((s) => s.code)).toBe(false);
    expect(p.steps[0].text).toMatch(/Aucune version corrigée/);
    expect(p.alternatives[0]).toMatch(/alternative maintenue/);
  });

  test("direct/transitive unknown: the indirect-dependency way out is offered too", () => {
    const p = remediationPlan(cve({ directOrTransitive: "UNKNOWN" }));
    expect(p.kind).toBe("update-direct");
    expect(p.steps.some((s) => s.code?.includes('"overrides"'))).toBe(true);
    // a known direct dependency does not get it
    expect(remediationPlan(cve({ directOrTransitive: "DIRECT" })).steps.some((s) => s.code?.includes("overrides"))).toBe(false);
  });

  test("no version information at all is not presented as 'no fix published'", () => {
    const p = remediationPlan(cve({ packageVersion: "", fixedVersion: null, fixAvailable: undefined }));
    expect(p.kind).toBe("no-fix");
    expect(p.steps[0].text).toMatch(/ni la version installée ni la version corrigée/);
  });

  test("dev-only dependency: documented exception, no urgency", () => {
    const p = remediationPlan(cve({ dependencyScope: "dev" }));
    expect(p.kind).toBe("dev-only");
    expect(p.urgency).toBe("LOW");
    expect(p.steps.some((s) => /exception/.test(s.text))).toBe(true);
  });

  test("but an actively exploited dev dependency is still handled as a normal fix", () => {
    expect(remediationPlan(cve({ dependencyScope: "dev", kevListed: true })).kind).toBe("update-direct");
  });

  test("system package: image / apt update, not a package-manager version bump", () => {
    const p = remediationPlan(cve({ ecosystem: "deb", packageName: "libc6", packageVersion: "2.31-0ubuntu9.17", fixedVersion: "2.31-0ubuntu9.18" }));
    expect(p.kind).toBe("system-package");
    expect(p.steps[0].code).toContain("apt-get");
  });

  test("fix version given by the caller (policy / preferred) wins over the raw list", () => {
    expect(remediationPlan(cve({ fixedVersion: "4.17.21, 5.0.0" }), "4.17.21").steps[0].code).toBe("npm install lodash@4.17.21");
  });
});

test("helpers", () => {
  expect(majorOf("v2.3.1")).toBe(2);
  expect(majorOf("")).toBeNull();
  expect(directParent("app → axios → follow-redirects", "follow-redirects")).toBe("axios");
  expect(directParent("app → lodash", "lodash")).toBeNull();
  expect(directParent(null)).toBeNull();
});

describe("code usage (does the project import the package?)", () => {
  test("a direct dependency that nothing imports: removing it is the first fix", () => {
    const p = remediationPlan(cve({ codeUsage: "NOT_IMPORTED", directOrTransitive: "DIRECT" }));
    expect(p.kind).toBe("remove-unused");
    expect(p.steps[1].code).toBe("npm uninstall lodash");
    expect(p.steps.some((s) => /tests/.test(s.text))).toBe(true);
  });

  test("not imported and direct/transitive unknown: normal plan, with a note that it is probably indirect", () => {
    const p = remediationPlan(cve({ codeUsage: "NOT_IMPORTED", directOrTransitive: "UNKNOWN" }));
    expect(p.kind).toBe("update-direct");
    expect(p.steps[0].text).toMatch(/probablement une dépendance indirecte/);
    expect(p.steps.some((s) => s.code === "npm install lodash@4.17.21")).toBe(true);
    expect(p.steps.some((s) => s.code?.includes("overrides"))).toBe(true);
  });

  test("a transitive dependency with no import gets no note: nothing to say", () => {
    const p = remediationPlan(cve({ codeUsage: "UNKNOWN", directOrTransitive: "TRANSITIVE", dependencyPath: "app → axios → lodash" }));
    expect(p.steps[0].text).not.toMatch(/import/);
  });

  test("imported by production code: the plan says it is potentially reachable, with the files", () => {
    const p = remediationPlan(cve({ codeUsage: "YES", usageFiles: ["src/api.js"] }));
    expect(p.kind).toBe("update-direct");
    expect(p.steps[0].text).toMatch(/potentiellement atteignable/);
    expect(p.steps[0].text).toContain("src/api.js");
  });

  test("a package the project imports itself is direct: no 'maybe indirect' hint", () => {
    const p = remediationPlan(cve({ codeUsage: "YES", directOrTransitive: "UNKNOWN", usageFiles: ["server.js"] }));
    expect(p.steps.some((s) => s.code?.includes("overrides"))).toBe(false);
  });

  test("imported only by tests: low priority, like a dev dependency, unless exploited", () => {
    const p = remediationPlan(cve({ codeUsage: "TEST_ONLY", usageFiles: ["test/a.test.js"] }));
    expect(p.urgency).toBe("LOW");
    expect(p.kind).toBe("dev-only");
    expect(remediationPlan(cve({ codeUsage: "TEST_ONLY", kevListed: true })).urgency).toBe("URGENT");
  });

  test("a system package or an unsupported ecosystem is never told to 'uninstall'", () => {
    expect(remediationPlan(cve({ ecosystem: "deb", packageName: "libc6", codeUsage: "NOT_IMPORTED" })).kind).toBe("system-package");
    expect(remediationPlan(cve({ ecosystem: "nuget", codeUsage: "NOT_IMPORTED" })).kind).not.toBe("remove-unused");
  });

  test("unknown usage changes nothing", () => {
    expect(remediationPlan(cve({ codeUsage: "UNKNOWN" })).steps[0].code).toBe("npm install lodash@4.17.21");
  });
});
