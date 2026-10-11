import type { CveDto } from "../services/api";
import { codeFix, languageOf, matchRule } from "./codeFix";

const f = (over: Partial<CveDto>): CveDto =>
  ({ id: 1, cveId: "x", packageName: "", severity: "ERROR", filePath: "app/server.js", ...over }) as CveDto;

test("language comes from the file extension", () => {
  expect(languageOf("a/b.ts")).toBe("js");
  expect(languageOf("a/b.py")).toBe("py");
  expect(languageOf("a/B.java")).toBe("java");
  expect(languageOf("docker-compose.yml")).toBe("other");
  expect(languageOf(null)).toBe("other");
});

describe("rules matched on real Semgrep findings (NodeGoat scan)", () => {
  const cases: [string, Partial<CveDto>][] = [
    ["codei", { cweId: "CWE-95", packageName: "javascript.browser.security.eval-detected.eval-detected" }],
    ["secret", { cweId: "CWE-798", packageName: "generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash" }],
    ["redirect", { cweId: "CWE-601", packageName: "javascript.express.security.audit.express-open-redirect.express-open-redirect" }],
    ["csrf", { cweId: "CWE-352", packageName: "javascript.express.security.audit.express-check-csurf-middleware-usage" }],
    ["csrf", { cweId: null, packageName: "python.django.security.django-no-csrf-token.django-no-csrf-token" }],
    ["cookie", { cweId: "CWE-522", packageName: "javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-httponly" }],
    ["http", { cweId: "CWE-319", packageName: "html.security.plaintext-http-link.plaintext-http-link" }],
    ["http", { cweId: null, packageName: "problem-based-packs.insecure-transport.js-node.using-http-server.using-http-server" }],
    ["ci-pin", { cweId: "CWE-1357", packageName: "yaml.github-actions.security.github-actions-mutable-action-tag" }],
    ["container", { cweId: "CWE-732", packageName: "yaml.docker-compose.security.no-new-privileges.no-new-privileges" }],
  ];
  test.each(cases)("%s", (id, over) => {
    expect(codeFix(f(over as Partial<CveDto>))?.id).toBe(id);
  });
});

test("CWE number matching does not confuse CWE-79 with CWE-798", () => {
  expect(matchRule({ cveId: "x", cweId: "CWE-798", packageName: "" })?.id).toBe("secret");
  expect(matchRule({ cveId: "x", cweId: "CWE-79", packageName: "" })?.id).toBe("xss");
  expect(matchRule({ cveId: "x", cweId: "CWE-22", packageName: "" })?.id).toBe("path");
});

test("the example follows the language of the flagged file", () => {
  const js = codeFix(f({ cweId: "CWE-89", filePath: "a/db.js" }))!;
  expect(js.bad).toContain("db.query");
  const py = codeFix(f({ cweId: "CWE-89", filePath: "a/db.py" }))!;
  expect(py.good).toContain("%s");
  const java = codeFix(f({ cweId: "CWE-89", filePath: "A.java" }))!;
  expect(java.good).toContain("PreparedStatement");
});

test("a rule without example for that language still gives steps, never an example from another one", () => {
  const r = codeFix(f({ cweId: "CWE-89", filePath: "a/db.go" }))!;
  expect(r.steps.length).toBeGreaterThan(0);
  expect(r.bad).toBeUndefined();
  const yaml = codeFix(f({ cweId: "CWE-1357", filePath: ".github/workflows/t.yaml" }))!;
  expect(yaml.good).toContain("@b4ffde65");
});

test("an unknown rule returns null so the generic text is used", () => {
  expect(codeFix(f({ cweId: "CWE-9999", packageName: "something.unrelated" }))).toBeNull();
});
