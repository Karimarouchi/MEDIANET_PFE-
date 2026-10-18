import { uptimeSummary } from "./CiOverviewCard";

const m = (name: string, status: string, uptime24h: number | null) => ({ id: 1, name, status, uptime24h, lastCheck: null, message: null });

describe("uptimeSummary", () => {
  it("not configured or unreachable", () => {
    expect(uptimeSummary(null).hint).toBe("Uptime Kuma non configuré");
    expect(uptimeSummary({ configured: true, reachable: false, domains: [], monitors: [] }).value).toBe("?");
  });
  it("no monitor named after the domain", () => {
    expect(uptimeSummary({ configured: true, reachable: true, domains: ["courtlinker.com"], monitors: [] }).hint)
      .toBe("aucun moniteur nommé courtlinker.com");
  });
  it("a site down is shown first", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["courtlinker.com"], monitors: [m("courtlinker.com", "DOWN", 0)] as never });
    expect(s).toEqual({ value: "0 %", hint: "hors ligne : courtlinker.com", tone: "text-error" });
  });
  it("all up", () => {
    const s = uptimeSummary({ configured: true, reachable: true, domains: ["a.com"], monitors: [m("a.com", "UP", 0.9995)] as never });
    expect(s.value).toBe("100 %");
    expect(s.tone).toBe("text-tertiary");
  });
});
