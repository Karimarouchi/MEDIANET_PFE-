/** Display rules of the CI tab: Woodpecker statuses and the step names written by Vulnix (CiPipelineGenerator). */

export function isCiActive(status: string): boolean {
  return status === "pending" || status === "running" || status === "blocked";
}

export function ciStatus(status: string): { label: string; icon: string; className: string; spin?: boolean } {
  switch (status) {
    case "success":
      return { label: "Réussi", icon: "check_circle", className: "bg-tertiary/15 text-tertiary" };
    case "failure":
      return { label: "Échec", icon: "cancel", className: "bg-error/15 text-error" };
    case "error":
      return { label: "Erreur", icon: "error", className: "bg-error/15 text-error" };
    case "killed":
      return { label: "Arrêté", icon: "stop_circle", className: "bg-surface-variant text-on-surface-variant" };
    case "running":
      return { label: "En cours", icon: "progress_activity", className: "bg-primary/15 text-primary", spin: true };
    case "pending":
      return { label: "En attente", icon: "schedule", className: "bg-surface-variant text-on-surface-variant" };
    case "skipped":
      return { label: "Ignoré", icon: "redo", className: "bg-surface-variant text-outline" };
    case "blocked":
      return { label: "À approuver", icon: "front_hand", className: "bg-amber-500/15 text-amber-300" };
    case "planned":
      return { label: "Prévue", icon: "radio_button_unchecked", className: "bg-surface-variant text-on-surface-variant" };
    case "declined":
      return { label: "Refusé", icon: "block", className: "bg-surface-variant text-outline" };
    default:
      return { label: status || "—", icon: "help", className: "bg-surface-variant text-outline" };
  }
}

/** "maven-backend" → Back-end Maven, "npm-frontend" → npm in Frontend, "vulnix-scan" → Vulnix gate. */
export function ciStepLabel(name: string): { title: string; detail?: string } {
  if (name === "clone") return { title: "Récupération du code", detail: "git clone du commit" };
  if (name === "vulnix-scan") return { title: "Scan Vulnix", detail: "CVE, secrets, code · barrière critique / élevée / KEV" };
  if (name === "vulnix-config") return { title: "Configuration Vulnix", detail: "le pipeline n'a pas pu être écrit" };
  const m = /^(maven|gradle|npm|python|php)(?:-(.+))?$/.exec(name);
  if (!m) return { title: name };
  const where = m[2] ? ` · ${m[2]}` : "";
  switch (m[1]) {
    case "maven":
      return { title: `Maven${where}`, detail: "tests + compilation (mvn verify)" };
    case "gradle":
      return { title: `Gradle${where}`, detail: "tests + compilation (gradle build)" };
    case "npm":
      return { title: `npm${where}`, detail: "installation, tests, lint, build" };
    case "python":
      return { title: `Python${where}`, detail: "dépendances + pytest" };
    default:
      return { title: `PHP${where}`, detail: "composer install + phpunit" };
  }
}

/** "2 min 05 s", "45 s", "en cours 1 min 10 s" or "—" (unix seconds). */
export function ciDuration(started: number | null, finished: number | null, now = Date.now() / 1000): string {
  if (!started) return "—";
  const end = finished || now;
  const total = Math.max(0, Math.round(end - started));
  const text = total < 60 ? `${total} s` : `${Math.floor(total / 60)} min ${String(total % 60).padStart(2, "0")} s`;
  return finished ? text : `en cours · ${text}`;
}

/** warn: the step passed but proves little (no test ran). */
export type StepOutcome = { tone: "ok" | "warn" | "bad" | "info"; text: string };

/** Docker / Woodpecker step error → plain French. */
export function ciStepError(error: string): string {
  if (/No such image|pull access denied|manifest unknown|failed to resolve reference/i.test(error)) {
    return "Image Docker de l'étape non téléchargée (Docker Hub injoignable ou image inconnue).";
  }
  if (/deadline exceeded|timeout/i.test(error)) return "Délai dépassé.";
  if (/exit code (\d+)/i.test(error)) return `La commande a échoué (${error}).`;
  return error;
}

const lastMatch = (lines: string[], re: RegExp) => [...lines].reverse().find((l) => re.test(l));

/** One-line result of a finished step, read from its output (Maven, npm, Vulnix gate…). */
export function ciStepOutcome(name: string, state: string, lines: string[], error?: string | null): StepOutcome | null {
  if (state === "pending" || state === "running") return null;
  if (state === "skipped") return { tone: "info", text: "Non exécutée (une étape précédente a échoué)." };
  if (state === "killed") return { tone: "info", text: "Arrêtée." };
  if (error && state !== "success") return { tone: "bad", text: ciStepError(error) };
  const ok = state === "success";

  if (name === "clone") return ok ? { tone: "ok", text: "Code du commit récupéré." } : { tone: "bad", text: "Clonage impossible." };

  if (name === "vulnix-scan") {
    const verdict = lastMatch(lines, /^Barriere Vulnix/);
    const refused = lastMatch(lines, /^(Vulnix a refuse|Vulnix injoignable|Jeton Vulnix absent|Le scan Vulnix a fini|Le scan depasse)/);
    if (refused) return { tone: "bad", text: refused };
    if (verdict) return { tone: ok ? "ok" : "bad", text: verdict.replace(/^Barriere Vulnix : /, "") };
  }

  if (name.startsWith("maven") || name.startsWith("gradle")) {
    if (lines.some((l) => /No address associated with hostname|Could not transfer artifact|Temporary failure in name resolution|UnknownHostException/.test(l))) {
      return { tone: "bad", text: "Maven n'a pas pu télécharger les dépendances (réseau ou DNS du conteneur). Relancez la CI." };
    }
    if (lines.some((l) => /COMPILATION ERROR/.test(l))) {
      const where = lines.find((l) => /^\[ERROR\] \/.+\.java:\[\d+/.test(l));
      return { tone: "bad", text: where ? `Erreur de compilation : ${where.replace(/^\[ERROR\] .*\/(\w+\.java)/, "$1")}` : "Erreur de compilation." };
    }
    const tests = lastMatch(lines, /Tests run: \d+, Failures: \d+, Errors: \d+/);
    if (tests) {
      const m = /Tests run: (\d+), Failures: (\d+), Errors: (\d+)(?:, Skipped: (\d+))?/.exec(tests)!;
      const failed = Number(m[2]) + Number(m[3]);
      return failed > 0
        ? { tone: "bad", text: `${failed} test(s) en échec sur ${m[1]}.` }
        : { tone: ok ? "ok" : "bad", text: `${m[1]} test(s) réussi(s)${m[4] && m[4] !== "0" ? `, ${m[4]} ignoré(s)` : ""}.` };
    }
    if (ok) return { tone: "warn", text: "Compilé, mais aucun test unitaire dans le projet." };
  }

  if (name.startsWith("npm")) {
    const err = lines.find((l) => /^npm (ERR!|error)/.test(l.trim()));
    if (!ok && err) return { tone: "bad", text: err.trim().replace(/^npm (ERR!|error)\s*/, "npm : ") };
    if (ok) {
      const ran = lines.filter((l) => /^\+ npm run (test|lint|build)\b/.test(l)).map((l) => l.replace(/^\+ npm run (\w+).*/, "$1"));
      const testsRan = lines.some((l) => /\b(Tests?|Test Files)\s+\d+ passed|\d+ (tests?|specs?) passed|✓/i.test(l));
      const text = ran.length ? `Installation + ${ran.join(", ")} réussis.` : "Installation réussie.";
      return testsRan ? { tone: "ok", text } : { tone: "warn", text: `${text} Aucun test exécuté.` };
    }
  }

  if (ok) return { tone: "ok", text: "Réussie." };
  // Maven and others end with help links: the first real error says more than the last line.
  const firstError = lines.find((l) => /^\[(ERROR|FATAL)\]\s+\S/.test(l) && !/\[Help \d\]|^\[ERROR\]\s*$|re-run Maven|full stack trace|following articles/i.test(l));
  if (firstError) return { tone: "bad", text: firstError.replace(/^\[(ERROR|FATAL)\]\s+(\[ERROR\]\s+)?/, "").slice(0, 200) };
  const last = lastMatch(lines, /\S/);
  return { tone: "bad", text: last ? last.trim().slice(0, 200) : "Échec sans sortie." };
}

/** Where and why the pipeline stopped: first failed step, or a pipeline-level error (bad config). */
export function ciBlocking(
  status: string,
  steps: { id: number; name: string; state: string; error: string | null }[],
  errors: string[],
  linesByStep: Record<number, string[]>,
): { stepId: number | null; where: string; why: string } | null {
  if (status === "success" || isCiActive(status) || status === "killed") return null;
  const failed = steps.find((s) => s.state === "failure" || s.state === "error");
  if (failed) {
    const outcome = ciStepOutcome(failed.name, failed.state, linesByStep[failed.id] ?? [], failed.error);
    return { stepId: failed.id, where: ciStepLabel(failed.name).title, why: outcome?.text ?? "Échec." };
  }
  if (errors.length > 0) return { stepId: null, where: "Configuration du pipeline", why: errors[0] };
  return { stepId: null, where: "Pipeline", why: "Échec sans étape en erreur." };
}

/** Tests counted in a step's output: Maven/Gradle summary, Vitest or Jest. Null when no test ran. */
export function ciTestCount(lines: string[]): { passed: number; failed: number } | null {
  let passed = 0;
  let failed = 0;
  let found = false;
  for (const raw of lines) {
    const l = raw.replace(/\x1b\[[0-9;]*m/g, "");
    // Maven/Gradle overall summary (per-class lines end with "-- in <Class>" and are skipped).
    const mvn = /Tests run: (\d+), Failures: (\d+), Errors: (\d+)(?:, Skipped: (\d+))?\s*$/.exec(l);
    if (mvn && !/ -- in /.test(l)) {
      const run = Number(mvn[1]);
      const bad = Number(mvn[2]) + Number(mvn[3]);
      passed += run - bad - Number(mvn[4] ?? 0);
      failed += bad;
      found = true;
      continue;
    }
    // Vitest "Tests  12 passed | 1 failed (13)" / Jest "Tests:       3 failed, 215 passed, 218 total".
    if (/^\s*Tests:?\s+\d/.test(l)) {
      const p = /(\d+) passed/.exec(l);
      const f = /(\d+) failed/.exec(l);
      if (p || f) {
        passed += p ? Number(p[1]) : 0;
        failed += f ? Number(f[1]) : 0;
        found = true;
      }
    }
  }
  return found ? { passed, failed } : null;
}

type CdRunLike = { status: string; commitSha: string | null; pipelineNumber: number | null; finishedAt: string | null };
type CdTargetLike = { serverName: string; automatic: boolean; last: CdRunLike | null };

/**
 * The "Déploiement" card after a pipeline's result: the deploy this pipeline started, or why nothing moved.
 * Null when the repository has no automatic deployment (no CD to show).
 */
export function cdNodeFor(
  pipeline: { number: number; status: string; branch: string },
  targets: (CdTargetLike & { branch?: string | null })[],
): { tone: "ok" | "warn" | "bad" | "info" | "running"; title: string; text: string } | null {
  const auto = targets.filter((t) => t.automatic && (t.branch || "main") === pipeline.branch);
  if (auto.length === 0) return null;
  const servers = auto.map((t) => t.serverName).join(", ");
  const runs = auto.map((t) => t.last).filter((r): r is CdRunLike => r != null && r.pipelineNumber === pipeline.number);
  if (runs.length === 0) {
    if (isCiActive(pipeline.status)) return { tone: "info", title: "Déploiement", text: `En attente du résultat · ${servers}` };
    if (pipeline.status === "success") return { tone: "running", title: "Déploiement", text: `Démarrage sur ${servers}…` };
    return { tone: "info", title: "Pas de déploiement", text: "Pipeline non vert : rien n'a bougé sur le serveur." };
  }
  if (runs.some((r) => r.status === "PENDING_APPROVAL")) return { tone: "info", title: "En attente d'accord", text: "Bouton Déployer ci-dessous." };
  if (runs.some((r) => r.status === "RUNNING")) return { tone: "running", title: "Déploiement en cours", text: servers };
  if (runs.some((r) => r.status === "BACKUP_FAILED")) return { tone: "bad", title: "Sauvegarde impossible", text: "Rien n'a été déployé." };
  if (runs.every((r) => r.status === "REFUSED" || r.status === "SUPERSEDED")) {
    return { tone: "info", title: "Non déployé", text: runs[0].status === "REFUSED" ? "Déploiement refusé." : "Remplacé par un pipeline plus récent." };
  }
  if (runs.some((r) => r.status === "FAILED")) return { tone: "bad", title: "Déploiement échoué", text: "Voir le journal de déploiement ci-dessous." };
  if (runs.some((r) => r.status === "ROLLED_BACK")) return { tone: "warn", title: "Version précédente remise", text: "La nouvelle version ne répondait pas." };
  return { tone: "ok", title: "En production", text: `${servers} · ${runs[0].commitSha?.slice(0, 8) ?? ""}` };
}
