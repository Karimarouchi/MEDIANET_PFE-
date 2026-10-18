import { formatBytes, restoreCommand } from "./cd";

describe("cd helpers", () => {
  it("formats sizes in French", () => {
    expect(formatBytes(500)).toBe("500 o");
    expect(formatBytes(48213)).toBe("47,1 Ko");
    expect(formatBytes(2_500_000_000)).toBe("2,33 Go");
  });
  it("restore command stops the other services, restores, restarts", () => {
    const c = restoreCommand("/opt/antigone/app", "db", "/opt/antigone/app/.vulnix-backups/avant-ab12.dump");
    expect(c.split("\n")).toEqual([
      "cd '/opt/antigone/app'",
      "docker compose stop $(docker compose config --services | grep -vx 'db')",
      `docker compose exec -T 'db' sh -c 'pg_restore -U "\${POSTGRES_USER:-postgres}" -d "\${POSTGRES_DB:-$POSTGRES_USER}" --clean --if-exists' < '/opt/antigone/app/.vulnix-backups/avant-ab12.dump'`,
      "docker compose up -d",
    ]);
  });
});
