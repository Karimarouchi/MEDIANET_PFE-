import { alertDateAllowed, readCertExpiry, reposByRole, roleLabel, solutionRoleOf, sslAlertDue, type SolutionRole } from "./ProjectOverviewDashboard";
import type { RepositoryDto } from "../services/api";

const repo = (id: number, name: string): RepositoryDto =>
  ({ id, repoUrl: `https://git.example/${name}` }) as RepositoryDto;

describe("solution roles on the project overview", () => {
  const repos = [repo(1, "front-app"), repo(2, "api"), repo(3, "legacy")];
  const roles: Partial<Record<number, SolutionRole>> = { 1: "FRONT", 2: "BACK" };

  it("puts a repository without a chosen role in Autre", () => {
    const groups = reposByRole(repos, roles);
    expect(groups.FRONT.map((item) => item.id)).toEqual([1]);
    expect(groups.BACK.map((item) => item.id)).toEqual([2]);
    expect(groups.DATABASE).toEqual([]);
    expect(groups.OTHER.map((item) => item.id)).toEqual([3]);
    expect(solutionRoleOf(roles, 3)).toBe("OTHER");
  });

  it("reads the certificate expiry and accepts an alert only up to that day", () => {
    const cert = readCertExpiry({
      certExpired: false,
      certDaysLeft: 87,
      certNotAfterStr: "—",
      certificateDetail: { notAfter: "2027-03-12T00:00:00Z", daysRemaining: 87, expired: false },
    });
    expect(cert.expiresOn).toBe("2027-03-12");
    expect(cert.daysLeft).toBe(87);
    expect(alertDateAllowed("2027-02-01", cert.expiresOn)).toBe(true);
    expect(alertDateAllowed("2027-03-13", cert.expiresOn)).toBe(false);
    expect(sslAlertDue("2026-10-01", new Date(2026, 9, 17))).toBe(true);
    expect(sslAlertDue("2027-02-01", new Date(2026, 9, 17))).toBe(false);
  });

  it("labels the four roles in French", () => {
    expect(roleLabel("FRONT")).toBe("Front");
    expect(roleLabel("BACK")).toBe("Back");
    expect(roleLabel("DATABASE")).toBe("Base de données");
    expect(roleLabel("OTHER")).toBe("Autre");
  });
});
