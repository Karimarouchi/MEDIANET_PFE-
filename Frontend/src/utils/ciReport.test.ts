import { ansiSpans, failedTests, frenchReason, isErrorLine, stripAnsi, topPackages, vulnixReport, vulnixSummary } from "./ciReport";

const E = "\x1b";

// Excerpt of a real Vitest failure (Stage-PFE-rania back-office), colour codes included.
const vitest = [
  ` ${E}[31m❯${E}[39m src/components/ui/CustomSelect.test.jsx ${E}[2m(${E}[22m${E}[2m2 tests${E}[22m${E}[2m | ${E}[22m${E}[31m1 failed${E}[39m${E}[2m)${E}[22m`,
  `${E}[31m   ${E}[31m×${E}[31m CustomSelect${E}[2m > ${E}[22mfalls back to the placeholder when nothing matches${E}[39m`,
  `${E}[41m${E}[1m FAIL ${E}[22m${E}[49m src/components/CategoryStorefrontPreview.test.jsx${E}[2m > ${E}[22mCategoryStorefrontPreview${E}[2m > ${E}[22minserts the current category into the menu at the chosen position`,
  `${E}[31m${E}[1mTestingLibraryElementError${E}[22m${E}[39m: Found multiple elements with the text: Huiles`,
  "",
  `${E}[41m${E}[1m FAIL ${E}[22m${E}[49m src/components/ui/CustomSelect.test.jsx${E}[2m > ${E}[22mCustomSelect${E}[2m > ${E}[22mfalls back to the placeholder when nothing matches`,
  `${E}[31m${E}[1mTestingLibraryElementError${E}[22m: Unable to find an accessible element with the role "button" and name "Choisir un statut"`,
  `${E}[2m      Tests ${E}[22m ${E}[1m${E}[31m3 failed${E}[39m${E}[22m${E}[2m | ${E}[22m${E}[1m${E}[32m55 passed${E}[39m${E}[22m${E}[90m (58)${E}[39m`,
];

describe("ciReport", () => {
  it("removes and renders colour codes", () => {
    expect(stripAnsi(vitest[0])).toBe(" ❯ src/components/ui/CustomSelect.test.jsx (2 tests | 1 failed)");
    const spans = ansiSpans(`${E}[31mrouge${E}[39m normal ${E}[1m${E}[32mvert${E}[0m`);
    expect(spans).toEqual([
      { text: "rouge", className: "text-red-400" },
      { text: " normal ", className: "" },
      { text: "vert", className: "text-green-400 font-bold" },
    ]);
  });

  it("lists the failed tests with the reason in plain French", () => {
    expect(failedTests(vitest)).toEqual([
      {
        file: "src/components/CategoryStorefrontPreview.test.jsx",
        name: "CategoryStorefrontPreview › inserts the current category into the menu at the chosen position",
        reason: "« Huiles » apparaît plusieurs fois à l'écran, alors que le test en attend un seul.",
      },
      {
        file: "src/components/ui/CustomSelect.test.jsx",
        name: "CustomSelect › falls back to the placeholder when nothing matches",
        reason: "Aucun élément « button » nommé exactement « Choisir un statut » à l'écran.",
      },
    ]);
  });

  it("reads Jest, Maven and pytest failures too", () => {
    expect(failedTests(["FAIL src/a.test.tsx", "  ● Login › shows the error", "", "    expect(received).toBe(expected)", "",
      "    Expected: \"Mot de passe incorrect\"", "    Received: \"Erreur\""])[0])
      .toEqual({ file: "src/a.test.tsx", name: "Login › shows the error", reason: "Valeur attendue \"Mot de passe incorrect\", valeur obtenue \"Erreur\"." });
    expect(failedTests(["FAIL src/b.test.tsx", "  ● Menu › opens", "    expect(received).toBeTruthy()"])[0].reason)
      .toBe("expect(received).toBeTruthy()");
    expect(failedTests(["[ERROR] Failures: ", "[ERROR]   UserServiceTest.login:42 expected: <200> but was: <401>"])[0])
      .toEqual({ file: "UserServiceTest.java:42", name: "UserServiceTest › login", reason: "Valeur attendue 200, valeur obtenue 401." });
    expect(failedTests(["FAILED tests/test_api.py::test_health - AssertionError: assert 500 == 200"])[0])
      .toEqual({ file: "tests/test_api.py", name: "test_health", reason: "assert 500 == 200" });
  });

  it("marks error lines", () => {
    expect(isErrorLine(vitest[2])).toBe(true);
    expect(isErrorLine(vitest[7])).toBe(true);
    expect(isErrorLine("npm warn deprecated glob@7.2.3")).toBe(false);
    expect(isErrorLine("  ✓ src/data/sectors.test.js (5 tests)")).toBe(false);
  });

  it("summarises the Vulnix gate", () => {
    const r = vulnixReport([
      "Scan Vulnix #3 du commit 898e9b3f92ab",
      "  BLOQUANT CRITICAL  CVE-2024-1      lodash (KEV)",
      "  BLOQUANT HIGH      CVE-2024-2      lodash",
      "  BLOQUANT HIGH      CVE-2024-3      axios",
      "  2 vulnerabilite(s) acceptee(s) par une exception validee.",
      "Rapport : https://pfe.example.com/projects/2",
      "Barriere Vulnix : ECHEC, 3 vulnerabilite(s) bloquante(s) (critique, elevee ou KEV).",
    ]);
    expect(r.passed).toBe(false);
    expect(r.accepted).toBe(2);
    expect(r.reportUrl).toBe("https://pfe.example.com/projects/2");
    expect(vulnixSummary(r)).toBe("3 vulnérabilités bloquantes : 1 critique, 2 élevées, dont 1 activement exploitée (KEV).");
    expect(topPackages(r)).toEqual([{ pkg: "lodash", count: 2 }, { pkg: "axios", count: 1 }]);
    expect(vulnixSummary(vulnixReport(["Barriere Vulnix : OK, aucune vulnerabilite bloquante."]))).toBe("Aucune vulnérabilité bloquante.");
  });

  it("keeps unknown reasons, shortened", () => {
    expect(frenchReason("Error: " + "x".repeat(300))!.length).toBe(181);
    expect(frenchReason(null)).toBeNull();
  });
});
