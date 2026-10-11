import { riskExplanation } from "./ReleaseReadinessPanel";
import type { ReleaseReadinessDto } from "../services/api";

const base: ReleaseReadinessDto = { clientId: 1, openFindingCount: 10, blockingCount: 3, scannedRepoCount: 1, priorities: [] };

describe("riskExplanation", () => {
  test("no deadline: asks for one", () => {
    expect(riskExplanation({ ...base, delayRisk: null })).toMatch(/Renseignez une date/);
  });
  test("passed deadline", () => {
    expect(riskExplanation({ ...base, delayRisk: "ELEVE", daysRemaining: -2 })).toMatch(/dépassée/);
  });
  test("no blocker: nothing stops the delivery", () => {
    expect(riskExplanation({ ...base, blockingCount: 0, delayRisk: "FAIBLE", daysRemaining: 20 })).toMatch(/Aucun bloqueur/);
  });
  test("high risk says why: few days left, or an exploited CVE with a short margin", () => {
    expect(riskExplanation({ ...base, delayRisk: "ELEVE", daysRemaining: 5 })).toMatch(/il ne reste que 5 j/);
    expect(riskExplanation({ ...base, delayRisk: "ELEVE", daysRemaining: 12, kevBlockingCount: 1 })).toMatch(/exploité\(s\) activement/);
  });
  test("medium risk: blockers to handle before the date", () => {
    expect(riskExplanation({ ...base, delayRisk: "MOYEN", daysRemaining: 31 })).toMatch(/3 bloqueur\(s\).*31 j/);
  });
  test("never mentions a duration estimate", () => {
    for (const r of ["FAIBLE", "MOYEN", "ELEVE"]) {
      expect(riskExplanation({ ...base, delayRisk: r, daysRemaining: 10 })).not.toMatch(/estim/i);
    }
  });
});
