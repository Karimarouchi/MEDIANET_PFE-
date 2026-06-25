export type AccessPermission =
  | "DASHBOARD"
  | "REPOSITORIES"
  | "PROJECTS"
  | "SCANS"
  | "VULNERABILITIES"
  | "SSL_ANALYSIS"
  | "SERVER_CONFIG"
  | "PIPELINE"
  | "PROFILE"
  | "ADMIN_USERS"
  | "ADMIN_ROLES"
  | "ADMIN_PROJECTS";

export type PermissionDefinition = {
  key: AccessPermission;
  label: string;
  description: string;
  section: "Core" | "Administration";
};

export const permissionCatalog: PermissionDefinition[] = [
  {
    key: "DASHBOARD",
    label: "Dashboard",
    description: "Acces au tableau de bord principal.",
    section: "Core",
  },
  {
    key: "REPOSITORIES",
    label: "Repositories",
    description: "Consultation et suivi des depots lies.",
    section: "Core",
  },
  {
    key: "PROJECTS",
    label: "Projects",
    description:
      "Acces aux projets et a leurs depots, scans et planifications.",
    section: "Core",
  },
  {
    key: "SCANS",
    label: "Scans",
    description: "Lancement et suivi des scans techniques.",
    section: "Core",
  },
  {
    key: "VULNERABILITIES",
    label: "Vulnerabilities",
    description: "Acces aux resultats CVE et correctifs.",
    section: "Core",
  },
  {
    key: "SSL_ANALYSIS",
    label: "SSL Analysis",
    description: "Consultation des analyses SSL/TLS.",
    section: "Core",
  },
  {
    key: "SERVER_CONFIG",
    label: "Server Config",
    description: "Visibilite sur la configuration serveur.",
    section: "Core",
  },
  {
    key: "PIPELINE",
    label: "Pipeline",
    description: "Suivi des pipelines et executions.",
    section: "Core",
  },
  {
    key: "PROFILE",
    label: "Profile",
    description: "Acces au profil utilisateur et aux liaisons Git.",
    section: "Core",
  },
  {
    key: "ADMIN_USERS",
    label: "Admin · Utilisateurs",
    description: "Creation, edition, suspension et suppression des comptes.",
    section: "Administration",
  },
  {
    key: "ADMIN_ROLES",
    label: "Admin · Roles",
    description: "Creation des roles et edition des permissions.",
    section: "Administration",
  },
  {
    key: "ADMIN_PROJECTS",
    label: "Admin · Projets",
    description: "Gestion des dossiers projets et affectations.",
    section: "Administration",
  },
];

export const permissionLabelMap = permissionCatalog.reduce<
  Record<string, PermissionDefinition>
>((acc, entry) => {
  acc[entry.key] = entry;
  return acc;
}, {});

export const adminPermissionKeys: AccessPermission[] = [
  "ADMIN_USERS",
  "ADMIN_ROLES",
  "ADMIN_PROJECTS",
];

export const defaultPermissionsBySystemRole: Record<
  "ADMIN" | "EMPLOYEE",
  AccessPermission[]
> = {
  ADMIN: permissionCatalog.map((entry) => entry.key),
  EMPLOYEE: permissionCatalog
    .filter((entry) => entry.section === "Core")
    .map((entry) => entry.key),
};

const routePermissionOrder: Array<{
  path: string;
  permission: AccessPermission;
}> = [
  { path: "/", permission: "DASHBOARD" },
  { path: "/repositories", permission: "REPOSITORIES" },
  { path: "/projects", permission: "PROJECTS" },
  { path: "/scans", permission: "SCANS" },
  { path: "/vulnerabilities", permission: "VULNERABILITIES" },
  { path: "/ssl-analysis", permission: "SSL_ANALYSIS" },
  { path: "/server-config", permission: "SERVER_CONFIG" },
  { path: "/pipeline", permission: "PIPELINE" },
  { path: "/profile", permission: "PROFILE" },
  { path: "/admin/users", permission: "ADMIN_USERS" },
  { path: "/admin/roles", permission: "ADMIN_ROLES" },
  { path: "/admin/projects", permission: "ADMIN_PROJECTS" },
];

export const hasPermission = (
  permissions: string[] | undefined,
  permission: string,
) => Array.isArray(permissions) && permissions.includes(permission);

export const hasAnyPermission = (
  permissions: string[] | undefined,
  required: string[],
) => required.some((permission) => hasPermission(permissions, permission));

export const getFirstAllowedRoute = (permissions: string[] | undefined) =>
  routePermissionOrder.find((entry) =>
    hasPermission(permissions, entry.permission),
  )?.path ?? "/login";
