import type { CveDto } from "../services/api";

/**
 * What to actually DO about a vulnerable dependency. "Update the version" is the usual answer, not the only one:
 * no fixed version, a major upgrade, a transitive dependency, a system package, a dev-only tool or a false positive
 * each need another action. Pure function so it can be unit-tested.
 */

export type PlanKind =
  | "update-direct"
  | "update-major"
  | "override-transitive"
  | "system-package"
  | "no-fix"
  | "dev-only";

export type Urgency = "URGENT" | "HIGH" | "NORMAL" | "LOW";

export interface PlanStep {
  text: string;
  /** shell command or manifest snippet to copy, when there is one */
  code?: string;
}

export interface RemediationPlan {
  kind: PlanKind;
  urgency: Urgency;
  urgencyReason: string;
  title: string;
  steps: PlanStep[];
  /** other options when the main one is not possible (e.g. cannot upgrade now) */
  alternatives: string[];
}

const SYSTEM_ECOSYSTEMS = new Set(["deb", "rpm", "apk", "alpine", "debian", "ubuntu"]);

export function majorOf(version?: string | null): number | null {
  const m = /(\d+)/.exec((version ?? "").replace(/^[^\d]*/, ""));
  return m ? Number(m[1]) : null;
}

export function isSystemPackage(c: CveDto): boolean {
  const eco = (c.ecosystem ?? "").toLowerCase();
  const type = (c.componentType ?? "").toLowerCase();
  const purl = (c.purl ?? "").toLowerCase();
  return SYSTEM_ECOSYSTEMS.has(eco) || type === "operating-system" || type === "container"
    || purl.startsWith("pkg:deb/") || purl.startsWith("pkg:rpm/") || purl.startsWith("pkg:apk/");
}

export function isDevOnly(c: CveDto): boolean {
  const scope = (c.dependencyScope ?? "").toLowerCase();
  return scope === "dev" || scope === "test" || scope === "development";
}

export function urgencyOf(c: CveDto): { urgency: Urgency; reason: string } {
  const sev = (c.severity ?? "").toUpperCase();
  if (c.kevListed) return { urgency: "URGENT", reason: "exploitée activement dans le monde réel (liste CISA KEV)" };
  if (c.exploitAvailable && (sev === "CRITICAL" || sev === "HIGH"))
    return { urgency: "URGENT", reason: "un exploit public existe et la gravité est élevée" };
  if (sev === "CRITICAL" || (c.epssScore ?? 0) >= 0.5)
    return { urgency: "HIGH", reason: sev === "CRITICAL" ? "gravité critique" : "forte probabilité d'exploitation (EPSS)" };
  if (isDevOnly(c)) return { urgency: "LOW", reason: "outil de développement ou de test, absent de la production" };
  if (sev === "LOW") return { urgency: "LOW", reason: "gravité faible" };
  return { urgency: "NORMAL", reason: "à planifier dans le cycle normal de maintenance" };
}

/** Last package before the vulnerable one in "app → parent → vulnerable": the direct dependency to act on. */
export function directParent(path?: string | null, vulnerable?: string | null): string | null {
  if (!path) return null;
  const parts = path.split(/→|->|>/).map((p) => p.trim()).filter(Boolean);
  if (parts.length < 3) return null;
  const idx = vulnerable ? parts.findIndex((p) => p.toLowerCase() === vulnerable.toLowerCase()) : -1;
  const vulnIdx = idx > 0 ? idx : parts.length - 1;
  return parts[1] && vulnIdx > 1 ? parts[1] : null;
}

function updateSnippet(eco: string, name: string, version: string): PlanStep {
  switch (eco) {
    case "npm":
      return { text: "Mettez la dépendance à jour, puis régénérez le fichier de verrouillage :", code: `npm install ${name}@${version}` };
    case "pypi":
    case "pip":
      return { text: "Relevez la version minimale :", code: `pip install "${name}>=${version}"   # puis mettez à jour requirements.txt` };
    case "golang":
    case "go":
      return { text: "Mettez le module à jour :", code: `go get ${name}@v${version.replace(/^v/, "")} && go mod tidy` };
    case "cargo":
    case "crates":
      return { text: "Mettez la crate à jour :", code: `cargo update -p ${name} --precise ${version}` };
    case "maven":
      return { text: `Dans pom.xml, passez la version de ${name} à ${version} :`, code: `<version>${version}</version>` };
    default:
      return { text: `Passez ${name} à la version ${version} dans le fichier de dépendances du projet.` };
  }
}

function overrideSnippet(eco: string, name: string, version: string, parent: string | null): PlanStep {
  switch (eco) {
    case "npm":
      return {
        text: `Forcez la version sans attendre ${parent ?? "le paquet parent"} (package.json, puis npm install) :`,
        code: `"overrides": { "${name}": "${version}" }`,
      };
    case "maven": {
      const [group, artifact] = name.includes(":") ? name.split(":") : ["…", name];
      return {
        text: "Forcez la version dans dependencyManagement (pom.xml) :",
        code: `<dependencyManagement><dependencies><dependency>\n  <groupId>${group}</groupId><artifactId>${artifact}</artifactId>\n  <version>${version}</version>\n</dependency></dependencies></dependencyManagement>`,
      };
    }
    case "pypi":
    case "pip":
      return { text: "Ajoutez une contrainte (constraints.txt) :", code: `${name}>=${version}` };
    case "golang":
    case "go":
      return { text: "Forcez le module (go.mod) :", code: `require ${name} v${version.replace(/^v/, "")}` };
    default:
      return { text: `Forcez ${name} à ${version} avec le mécanisme de votre gestionnaire (overrides, constraints…).` };
  }
}

export function remediationPlan(c: CveDto, fixVersion?: string | null): RemediationPlan {
  const { urgency, reason } = urgencyOf(c);
  const name = c.packageName || c.componentName || "ce paquet";
  const eco = (c.ecosystem ?? "").toLowerCase();
  const installed = c.packageVersion || c.componentVersion || "";
  const fix = (fixVersion ?? c.fixedVersion ?? "").trim() || null;
  const transitive = (c.directOrTransitive ?? "").toUpperCase() === "TRANSITIVE";
  const parent = directParent(c.dependencyPath, name);
  const verify: PlanStep = { text: "Relancez un scan pour confirmer que la vulnérabilité a disparu." };

  // 1. system / container package
  if (isSystemPackage(c)) {
    const steps: PlanStep[] = fix
      ? [
          { text: `Mettez à jour l'image de base ou le paquet système vers ${fix} :`, code: "apt-get update && apt-get install --only-upgrade " + name },
          { text: "Reconstruisez l'image Docker avec une base à jour (tag récent, pas `latest` figé depuis des mois)." },
        ]
      : [
          { text: "Aucun correctif publié pour votre distribution : consultez le suivi de sécurité de la distribution (Debian / Ubuntu security tracker)." },
          { text: "Si la version de base est ancienne, passez à une version de distribution encore supportée." },
        ];
    return {
      kind: "system-package", urgency, urgencyReason: reason,
      title: fix ? "Mettre à jour le paquet système / l'image" : "Pas de correctif pour ce paquet système",
      steps: [...steps, verify],
      alternatives: ["Si le service concerné n'est pas lancé dans le conteneur, supprimez le paquet de l'image."],
    };
  }

  // 2. dev/test only, no actual production exposure
  if (isDevOnly(c) && !c.kevListed) {
    return {
      kind: "dev-only", urgency, urgencyReason: reason,
      title: "Dépendance de développement : faible risque en production",
      steps: [
        ...(fix ? [updateSnippet(eco, name, fix)] : [{ text: "Aucun correctif publié : surveillez la sortie d'une version corrigée." }]),
        { text: "Si vous ne la mettez pas à jour, documentez l'exception (« outil de build uniquement, absent de l'image de production ») et revoyez-la à chaque version." },
        verify,
      ],
      alternatives: ["Vérifiez que cette dépendance n'est pas aussi livrée en production (scope `runtime`)."],
    };
  }

  // 3. fixed version exists
  if (fix) {
    const a = majorOf(installed);
    const b = majorOf(fix.split(/[,;|/]/)[0]);
    const major = a != null && b != null && b > a;
    const main: PlanStep = transitive ? overrideSnippet(eco, name, fix.split(/[,;|/]/)[0].trim(), parent) : updateSnippet(eco, name, fix.split(/[,;|/]/)[0].trim());
    const steps: PlanStep[] = [];
    if (transitive) {
      steps.push({
        text: parent
          ? `${name} est une dépendance indirecte, tirée par « ${parent} » : commencez par vérifier si une version récente de « ${parent} » embarque déjà le correctif.`
          : `${name} est une dépendance indirecte : cherchez le paquet parent qui la tire (chemin dans la fiche).`,
      });
    }
    steps.push(main);
    if ((c.directOrTransitive ?? "UNKNOWN").toUpperCase() === "UNKNOWN" && !transitive && ["npm", "maven", "pypi", "pip", "golang", "go"].includes(eco)) {
      // the scanners did not say whether it is direct: give the way out for the indirect case too
      const forced = overrideSnippet(eco, name, fix.split(/[,;|/]/)[0].trim(), null);
      steps.push({ text: `Si ${name} n'est pas listé dans votre fichier de dépendances, c'est une dépendance indirecte : la commande ci-dessus ne suffira pas. ${forced.text}`, code: forced.code });
    }
    if (major) steps.push({ text: `Changement de version majeure (${installed} → ${fix.split(/[,;|/]/)[0].trim()}) : lisez les notes de version et lancez vos tests avant de livrer.` });
    steps.push(verify);
    return {
      kind: major ? "update-major" : transitive ? "override-transitive" : "update-direct",
      urgency, urgencyReason: reason,
      title: transitive ? "Forcer la version de la dépendance indirecte" : major ? "Mise à jour avec changement majeur" : "Mettre à jour la dépendance",
      steps,
      alternatives: major
        ? ["Si la migration est trop lourde maintenant : cherchez un correctif rétroporté sur votre branche, et planifiez la migration."]
        : transitive ? ["Mettre à jour le paquet parent est préférable à long terme (l'override est à retirer ensuite)."] : [],
    };
  }

  // 4. no fixed version
  const unknownVersions = !installed;
  const steps: PlanStep[] = [
    {
      text: unknownVersions
        ? `Les scanners n'ont fourni ni la version installée ni la version corrigée de ${name} : consultez l'avis de sécurité de cette CVE pour savoir si un correctif existe.`
        : `Aucune version corrigée publiée pour ${name}. Vérifiez l'avis de sécurité du projet : un contournement y est souvent décrit.`,
    },
    { text: "Désactivez ou isolez la fonctionnalité touchée (option de configuration, route, module non utilisé)." },
    { text: "Limitez l'exposition : filtrage des entrées, règle de pare-feu applicatif (WAF), accès réseau restreint." },
  ];
  if (urgency === "LOW" || urgency === "NORMAL") {
    steps.push({ text: "Si le code vulnérable n'est pas appelé par votre application, documentez une exception (« risque accepté ») avec une date de revue." });
  }
  steps.push({ text: "Surveillez la sortie d'un correctif (alerte sur l'avis), et relancez un scan régulièrement." });
  return {
    kind: "no-fix", urgency, urgencyReason: reason,
    title: unknownVersions ? "Version corrigée inconnue : vérifier l'avis, sinon contourner" : "Pas de correctif : contourner ou réduire le risque",
    steps,
    alternatives: ["Remplacez la bibliothèque par une alternative maintenue si le projet est abandonné."],
  };
}

export const URGENCY_LABEL: Record<Urgency, { label: string; cls: string }> = {
  URGENT: { label: "Urgent", cls: "bg-error-container text-on-error-container" },
  HIGH: { label: "Prioritaire", cls: "bg-orange-500/20 text-orange-300" },
  NORMAL: { label: "À planifier", cls: "bg-surface-variant text-on-surface-variant" },
  LOW: { label: "Faible priorité", cls: "bg-tertiary-container text-on-tertiary-container" },
};
