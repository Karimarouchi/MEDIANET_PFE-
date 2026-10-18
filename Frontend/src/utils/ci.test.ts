import { ciDuration, ciStatus, ciStepLabel, isCiActive } from "./ci";

describe("ci display", () => {
  it("labels the steps Vulnix writes", () => {
    expect(ciStepLabel("maven-backend")).toEqual({ title: "Maven · backend", detail: "tests + compilation (mvn verify)" });
    expect(ciStepLabel("npm-frontend").title).toBe("npm · frontend");
    expect(ciStepLabel("maven").title).toBe("Maven");
    expect(ciStepLabel("vulnix-scan").title).toBe("Scan Vulnix");
    expect(ciStepLabel("clone").title).toBe("Récupération du code");
    expect(ciStepLabel("custom")).toEqual({ title: "custom" });
  });

  it("knows which pipelines are still moving", () => {
    expect(isCiActive("running")).toBe(true);
    expect(isCiActive("pending")).toBe(true);
    expect(isCiActive("failure")).toBe(false);
    expect(ciStatus("failure").label).toBe("Échec");
    expect(ciStatus("running").spin).toBe(true);
  });

  it("formats durations", () => {
    expect(ciDuration(null, null)).toBe("—");
    expect(ciDuration(100, 145)).toBe("45 s");
    expect(ciDuration(100, 225)).toBe("2 min 05 s");
    expect(ciDuration(100, null, 170)).toBe("en cours · 1 min 10 s");
  });
});

describe("ci outcomes", () => {
  const { ciStepOutcome, ciBlocking } = require("./ci");

  it("reads Maven results", () => {
    expect(ciStepOutcome("maven-backend", "success", ["[INFO] Tests run: 12, Failures: 0, Errors: 0, Skipped: 1"]))
      .toEqual({ tone: "ok", text: "12 test(s) réussi(s), 1 ignoré(s)." });
    expect(ciStepOutcome("maven-backend", "failure", ["[ERROR] Tests run: 5, Failures: 2, Errors: 0, Skipped: 0"]).text)
      .toBe("2 test(s) en échec sur 5.");
    expect(ciStepOutcome("maven-backend", "success", ["[INFO] BUILD SUCCESS"]))
      .toEqual({ tone: "warn", text: "Compilé, mais aucun test unitaire dans le projet." });
    expect(ciStepOutcome("maven", "failure", ["[ERROR] COMPILATION ERROR :"]).text).toBe("Erreur de compilation.");
  });

  it("reads npm and the Vulnix gate", () => {
    expect(ciStepOutcome("npm-frontend", "success", ["+ npm install", "+ npm run lint", "+ npm run build"]))
      .toEqual({ tone: "warn", text: "Installation + lint, build réussis. Aucun test exécuté." });
    expect(ciStepOutcome("npm-frontend", "success", ["+ npm run test --workspaces --if-present", " Test Files  3 passed (3)", "+ npm run build"]))
      .toEqual({ tone: "ok", text: "Installation + test, build réussis." });
    expect(ciStepOutcome("npm-frontend", "failure", ["npm error Missing script: \"lint\""]).text).toBe("npm : Missing script: \"lint\"");
    expect(ciStepOutcome("vulnix-scan", "failure", ["  BLOQUANT CRITICAL CVE-1 x", "Barriere Vulnix : ECHEC, 1 vulnerabilite(s) bloquante(s) (critique, elevee ou KEV)."]))
      .toEqual({ tone: "bad", text: "ECHEC, 1 vulnerabilite(s) bloquante(s) (critique, elevee ou KEV)." });
  });

  it("explains a Docker pull failure", () => {
    expect(ciStepOutcome("vulnix-scan", "failure", [], "Error response from daemon: No such image: python:3.12-alpine").text)
      .toMatch(/Image Docker de l'étape non téléchargée/);
  });

  it("points at the first failed step", () => {
    const steps = [
      { id: 1, name: "clone", state: "success", error: null },
      { id: 2, name: "maven-backend", state: "success", error: null },
      { id: 3, name: "vulnix-scan", state: "failure", error: null },
    ];
    expect(ciBlocking("failure", steps, [], { 3: ["Barriere Vulnix : ECHEC, 2 vulnerabilite(s) bloquante(s)"] }))
      .toEqual({ stepId: 3, where: "Scan Vulnix", why: "ECHEC, 2 vulnerabilite(s) bloquante(s)" });
    expect(ciBlocking("error", [], ["Insufficient trust level to use `extra_hosts`"], {}))
      .toEqual({ stepId: null, where: "Configuration du pipeline", why: "Insufficient trust level to use `extra_hosts`" });
    expect(ciBlocking("success", steps, [], {})).toBeNull();
  });
});

describe("ci failure reasons", () => {
  const { ciStepOutcome } = require("./ci");
  it("explains a Maven download failure instead of showing a help link", () => {
    const lines = [
      "[FATAL] Non-resolvable parent POM for tn.antigone:finace:1.0.0: Could not transfer artifact org.springframework.boot:spring-boot-starter-parent:pom:3.3.5 from/to central: repo.maven.apache.org: No address associated with hostname",
      "[ERROR] [Help 2] http://cwiki.apache.org/confluence/display/MAVEN/UnresolvableModelException",
    ];
    expect(ciStepOutcome("maven-backend", "failure", lines).text).toMatch(/n'a pas pu télécharger les dépendances/);
  });
  it("names the file of a compilation error", () => {
    expect(ciStepOutcome("maven-backend", "failure", ["[ERROR] COMPILATION ERROR :", "[ERROR] /w/src/main/java/tn/x/AuthService.java:[12,5] cannot find symbol"]).text)
      .toBe("Erreur de compilation : AuthService.java:[12,5] cannot find symbol");
  });
  it("keeps the first real error, not the trailing help links", () => {
    expect(ciStepOutcome("gradle", "failure", ["[ERROR] Failed to execute goal x", "[ERROR] [Help 1] http://cwiki"]).text)
      .toBe("Failed to execute goal x");
  });
});

describe("ciTestCount", () => {
  const { ciTestCount } = require("./ci");
  it("reads the Maven summary, not the per-class lines", () => {
    expect(ciTestCount([
      "[INFO] Tests run: 20, Failures: 0, Errors: 0, Skipped: 0, Time elapsed: 0.393 s -- in tn.x.AuthServiceTest",
      "[INFO] Tests run: 46, Failures: 0, Errors: 0, Skipped: 0",
    ])).toEqual({ passed: 46, failed: 0 });
    expect(ciTestCount(["[ERROR] Tests run: 5, Failures: 1, Errors: 1, Skipped: 1"])).toEqual({ passed: 2, failed: 2 });
  });
  it("reads Vitest and Jest, and adds workspaces", () => {
    expect(ciTestCount(["      Tests  12 passed | 1 failed (13)", "      Tests  4 passed (4)"])).toEqual({ passed: 16, failed: 1 });
    expect(ciTestCount(["Tests:       3 failed, 215 passed, 218 total"])).toEqual({ passed: 215, failed: 3 });
  });
  it("no test ran", () => {
    expect(ciTestCount(["[INFO] BUILD SUCCESS"])).toBeNull();
  });
});

describe("cdNodeFor", () => {
  const { cdNodeFor } = require("./ci");
  const target = (last: object | null, automatic = true) => ({ serverName: "prod", automatic, branch: "main", last });
  const p = (number: number, status: string) => ({ number, status, branch: "main" });
  it("no automatic deployment: no CD card", () => {
    expect(cdNodeFor(p(3, "success"), [target(null, false)])).toBeNull();
  });
  it("red pipeline moves nothing", () => {
    expect(cdNodeFor(p(3, "failure"), [target(null)]).title).toBe("Pas de déploiement");
  });
  it("follows the deploy started by this pipeline", () => {
    const run = (status: string) => ({ status, commitSha: "abcdef1234", pipelineNumber: 3, finishedAt: null });
    expect(cdNodeFor(p(3, "success"), [target(run("SUCCESS"))])).toEqual({ tone: "ok", title: "En production", text: "prod · abcdef12" });
    expect(cdNodeFor(p(3, "success"), [target(run("ROLLED_BACK"))]).tone).toBe("warn");
    expect(cdNodeFor(p(3, "success"), [target(run("RUNNING"))]).tone).toBe("running");
    expect(cdNodeFor(p(3, "success"), [target(null)]).text).toMatch(/Démarrage/);
  });
});

describe("cdNodeFor approval and backup", () => {
  const { cdNodeFor } = require("./ci");
  const p = { number: 3, status: "success", branch: "main" };
  const t = (status: string) => [{ serverName: "prod", automatic: true, branch: "main", last: { status, commitSha: "abcdef12", pipelineNumber: 3, finishedAt: null } }];
  it("waiting, refused, backup failed", () => {
    expect(cdNodeFor(p, t("PENDING_APPROVAL")).title).toBe("En attente d'accord");
    expect(cdNodeFor(p, t("REFUSED")).text).toBe("Déploiement refusé.");
    expect(cdNodeFor(p, t("BACKUP_FAILED"))).toEqual({ tone: "bad", title: "Sauvegarde impossible", text: "Rien n'a été déployé." });
  });
});
