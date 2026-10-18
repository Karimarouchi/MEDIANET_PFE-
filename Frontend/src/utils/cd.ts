/** Continuous deployment helpers shared by the CI/CD tab and the project overview. */

/** "47 Ko", "1,2 Mo", "2,33 Go" (base 1024, French decimals). */
export function formatBytes(bytes: number | null | undefined): string {
  const b = bytes ?? 0;
  if (b < 1024) return `${b} o`;
  const units = ["Ko", "Mo", "Go", "To"];
  let v = b / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toLocaleString("fr-FR", { maximumFractionDigits: v < 10 ? 2 : v < 100 ? 1 : 0 })} ${units[i]}`;
}

function sq(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

/**
 * Command to restore a backup on the server, shown to copy (restoring a database is a manual decision).
 * Stops the other services first so nothing writes during the restore, then starts them again.
 */
export function restoreCommand(path: string, service: string, file: string): string {
  return [
    `cd ${sq(path)}`,
    `docker compose stop $(docker compose config --services | grep -vx ${sq(service)})`,
    `docker compose exec -T ${sq(service)} sh -c 'pg_restore -U "\${POSTGRES_USER:-postgres}" -d "\${POSTGRES_DB:-$POSTGRES_USER}" --clean --if-exists' < ${sq(file)}`,
    `docker compose up -d`,
  ].join("\n");
}
