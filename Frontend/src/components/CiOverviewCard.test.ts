import { uptimeSummary } from "./CiOverviewCard";

const m = (name: string, status: string, uptime24h: number | null, message: string | null = null) =>
  ({ id: 1, name, status, uptime24h, lastCheck: null, message });

describe("uptimeSummary", () => {
  it("unavailable, switched off or unreachable", () => {
    expect(uptimeSummary(null).hint).toBe("surveillance indisponible");
    expect(uptimeSummary({ configured: false, reachable: false, domains: [], monitors: [] }).hint).toBe("surveillance désactivée");
    expect(uptimeSummary({ configured: true, reachable: false, domains: [], monitors: [] }).value).toBe("?");
  });
  it("a project without domain is told to add one", () => {
    expect(uptimeSummary({ configured: true, reachable: true, domains: [], monitors: [] }).hint).toBe("ajoutez un domaine au projet");
  });
  it("no monitor named after the domain (Uptime Kuma mode)", () => {
    expect(uptimeSummary({ configured: true, reachable: true, domains: ["courtlinker.com"], monitors: [] }).hint)
      .toBe("aucun moniteur nommé courtlinker.com");
  });
  it("first check not done yet", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["a.com"], monitors: [m("a.com", "PENDING", null)] as never });
    expect(s).toEqual({ value: "—", hint: "première vérification en cours", tone: "text-outline" });
  });
  it("a site down is shown first", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["courtlinker.com"], monitors: [m("courtlinker.com", "DOWN", 0)] as never });
    expect(s).toEqual({ value: "0 %", hint: "hors ligne : courtlinker.com", tone: "text-error" });
  });
  it("all up", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["a.com"], monitors: [m("a.com", "UP", 0.9995)] as never });
    expect(s.value).toBe("100 %");
    expect(s.hint).toBe("1 site(s) en ligne · 24 h");
    expect(s.tone).toBe("text-tertiary");
  });
  it("only the sites really up are counted", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["a.com", "b.com"],
      monitors: [m("a.com", "UP", 1), m("b.local", "UNKNOWN", null, "adresse non publique : non surveillée")] as never });
    expect(s.hint).toBe("1 site(s) en ligne · 24 h");
  });
  it("a site that cannot be watched says why", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["b.local"],
      monitors: [m("b.local", "UNKNOWN", null, "adresse non publique : non surveillée")] as never });
    expect(s).toEqual({ value: "—", hint: "adresse non publique : non surveillée", tone: "text-outline" });
  });
});
