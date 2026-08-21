import axios from "axios";

/**
 * Origine API optionnelle (ex: https://api.example.com).
 * Laisser vide en prod derrière nginx qui proxy /api → backend (recommandé).
 */
export const API_ORIGIN = (process.env.REACT_APP_API_ORIGIN || "").replace(/\/$/, "");

/** Construit une URL API absolue ou relative selon la config. */
export function apiUrl(path: string): string {
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${API_ORIGIN}${p}`;
}

const API = axios.create({
  baseURL: apiUrl("/api"),
  withCredentials: true,
});

let refreshPromise: Promise<void> | null = null;

async function refreshAccessCookie(): Promise<void> {
  if (!refreshPromise) {
    refreshPromise = axios
      .post(apiUrl("/api/auth/refresh"), null, { withCredentials: true })
      .then(() => undefined)
      .finally(() => {
        refreshPromise = null;
      });
  }
  return refreshPromise;
}

API.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error?.config as
      | (typeof error.config & { _retry?: boolean })
      | undefined;
    const status = error?.response?.status;
    const url = String(original?.url ?? "");
    const skipRefresh =
      url.includes("/auth/login") ||
      url.includes("/auth/refresh") ||
      url.includes("/auth/logout");

    if (status === 401 && original && !original._retry && !skipRefresh) {
      original._retry = true;
      try {
        await refreshAccessCookie();
        return API(original);
      } catch {
        localStorage.removeItem("vulnix_token");
      }
    }
    return Promise.reject(error);
  },
);

export interface ScanRequest {
  repoUrl: string;
  branch?: string;
  scanMode?: string;
  targetDomain?: string;
  dastTargetUrl?: string;
  dockerImage?: string;
  containerPort?: number;
  /** Idée 3 — OS cible : e.g. "ubuntu:22.04", "alpine:3.18", "windows:2022" */
  targetOs?: string;
  /** Idée 2 — OpenSCAP compliance profile: "CIS_L1", "CIS_L2", "NIST_800-53", "PCI_DSS" */
  complianceProfile?: string;
}

export interface ScanResponse {
  scanId: number;
  repoId: number;
}

export interface CveDto {
  id: number;
  cveId: string;
  packageName: string;
  packageVersion: string;
  severity: string;
  cvssScore: number | null;
  fixedVersion: string | null;
  description: string | null;
  dataSource: string | null;
  source: string;
  filePath: string | null;
  lineNumber: number | null;
  exploitAvailable: boolean;
  exploitUrl: string | null;
  kevListed: boolean;
  kevDateAdded: string | null;
  kevRansomware: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
  confirmedBy: number;
  sources: string | null;
  /** Idée 3 — OS cible : "WINDOWS", "LINUX", "CROSS_PLATFORM" (from NVD CPE data) */
  affectedOs: string | null;
  // ── SBOM enrichment fields ──────────────────────────────────────────────
  /** Exact component name from SBOM */
  componentName: string | null;
  /** Exact component version from SBOM */
  componentVersion: string | null;
  /** Component type: "library", "framework", "container", etc. */
  componentType: string | null;
  /** Package ecosystem: "npm", "maven", "pypi", "golang", etc. */
  ecosystem: string | null;
  /** Package manager: "npm", "mvn", "pip", "cargo", etc. */
  packageManager: string | null;
  /** Dependency scope: "runtime", "dev", "test", "optional", "unknown" */
  dependencyScope: string | null;
  /** "DIRECT", "TRANSITIVE", or "UNKNOWN" */
  directOrTransitive: string | null;
  /** Depth from project root (1 = direct) */
  dependencyDepth: number | null;
  /** Human-readable dependency path e.g. "frontend-rh → axios → follow-redirects" */
  dependencyPath: string | null;
  /** Package URL e.g. "pkg:npm/axios@0.21.1" */
  purl: string | null;
  /** BOM reference from the SBOM document */
  bomRef: string | null;
  /** Manifest file path e.g. "frontend-rh/package-lock.json" */
  manifestFile: string | null;
  /** Module name derived from manifestFile */
  moduleName: string | null;
  /** Confidence of the direct/transitive classification: "HIGH", "MEDIUM", "LOW" */
  dependencyConfidence: string | null;
}

export interface RepositoryDto {
  id: number;
  repoUrl: string;
  gitProvider?: string;
  branch: string;
  scanMode: string;
  targetDomain: string;
  clientIds?: number[];
  clientNames?: string[];
  createdAt: string;
  lastScannedAt: string;
}

export interface ScanResultDto {
  id: number;
  repoId: number;
  repoUrl: string;
  gitProvider?: string;
  branch: string;
  scanMode: string;
  targetDomain: string;
  clientIds?: number[];
  clientNames?: string[];
  status: string;
  startedAt: string;
  finishedAt: string;
  ecosystemsDetected: string;
  toolsExecuted: string;
  cveCount: number;
  secretCount: number;
}

export interface SecretDto {
  id: number;
  ruleId: string;
  description: string;
  file: string;
  startLine: number;
  endLine: number;
  author: string;
  date: string;
  commit: string;
  maskedMatch: string | null;
}

export interface SastDto {
  checkId: string;
  file: string;
  line: number | null;
  message: string;
  severity: string;
  owaspCategory: string;
}

// Start a scan
export const startScan = (data: ScanRequest) =>
  API.post<ScanResponse>("/scans", data);

// Get CVEs for a scan
export const getCvesByScan = (scanId: number) =>
  API.get<CveDto[]>(`/scans/${scanId}/cves`);

// Get all repositories
export const getRepositories = () => API.get<RepositoryDto[]>("/repositories");

// Get all scans
export const getAllScans = () => API.get<ScanResultDto[]>("/scans");

// Get scan history for a repo
export const getScansByRepo = (repoId: number) =>
  API.get<ScanResultDto[]>(`/repositories/${repoId}/scans`);

// Get CVEs from latest scan of a repo
export const getCvesByRepo = (repoId: number) =>
  API.get<CveDto[]>(`/repositories/${repoId}/cves`);

// Get secrets for a scan
export const getSecretsByScan = (scanId: number) =>
  API.get<SecretDto[]>(`/scans/${scanId}/secrets`);

// Get SAST findings for a scan
export const getSastByScan = (scanId: number) =>
  API.get<SastDto[]>(`/scans/${scanId}/sast`);

// Get SBOM components for a scan
export interface SbomComponent {
  id: string;
  name: string;
  version: string;
  type: string;
  language: string;
  purl: string;
  license: string;
  location: string;
}

export const getSbomByScan = (scanId: number) =>
  API.get<SbomComponent[]>(`/scans/${scanId}/sbom`);

// Idée 2 — Get OpenSCAP compliance results for a scan
export interface ComplianceFinding {
  ruleId: string;
  title: string;
  result: "pass" | "fail" | "error" | "unknown";
  severity: "high" | "medium" | "low" | "informational";
  description: string;
  profile: string;
}

export interface ComplianceResponse {
  available: boolean;
  profile?: string;
  findings: ComplianceFinding[];
  summary: {
    totalRules: number;
    pass: number;
    fail: number;
    score: number;
    highFail: number;
    mediumFail: number;
  };
}

export const getComplianceResults = (scanId: number) =>
  API.get<ComplianceResponse>(`/scans/${scanId}/compliance`);

// Stop a running scan
export const stopScan = (scanId: number) => API.post(`/scans/${scanId}/stop`);

// Delete a scan
export const deleteScan = (scanId: number) => API.delete(`/scans/${scanId}`);

// ── Auto-Fix programmatique ───────────────────────────────────────────────────

export interface FixPreviewRequest {
  repoFullName: string;
  packageName: string;
  currentVersion: string;
  fixedVersion: string;
  cveId: string;
  filePath: string | null;
  source: string | null;
  provider?: "GITHUB" | "GITLAB";
  branch?: string | null;
}

export interface HumanKnowledgeDto {
  id: number;
  cveId?: string | null;
  packageName: string;
  ecosystem?: string | null;
  fromVersion?: string | null;
  toVersion?: string | null;
  filePath?: string | null;
  repoFullName?: string | null;
  reason: string;
  createdByLogin?: string | null;
  usageCount: number;
  successCount: number;
  failCount: number;
  status: string;
  createdAt?: string | null;
  lastUsedAt?: string | null;
}

export interface LlmFixAdvice {
  recommendation: "AI" | "HUMAN" | "NEEDS_REVIEW" | string;
  confidence: number;
  summary: string;
  why: string;
  risks?: string;
  humanStillValid?: boolean;
  source?: string;
}

export interface FixPreviewResponse {
  originalLines: string[];
  fixedLines: string[];
  fixedContent: string;
  filePath: string;
  sha: string;
  // npm lock file — also patched so the next scan doesn't flag the same CVE
  lockFilePath?: string | null;
  lockFileSha?: string | null;
  lockFileContent?: string | null;
  // Assisted-fix agent memory
  hasHumanKnowledge?: boolean;
  humanKnowledge?: HumanKnowledgeDto | null;
  humanFixedContent?: string | null;
  humanFixedLines?: string[] | null;
  llmAdvice?: LlmFixAdvice | null;
  // Sprint A — chef policy
  officialStableVersion?: string | null;
  officialComment?: string | null;
  policySource?: "CHEF" | "SCAN" | string | null;
  policyPreferredVersion?: string | null;
}

export interface FixApplyRequest {
  repoFullName: string;
  filePath: string;
  sha: string;
  fixedContent: string;
  commitMessage: string;
  provider?: "GITHUB" | "GITLAB";
  branch?: string | null;
  // optional lock file fields — when present, the lock file is also committed
  lockFilePath?: string | null;
  lockFileSha?: string | null;
  lockFileContent?: string | null;
  // Assisted-fix agent
  developerEdited?: boolean;
  memorize?: boolean;
  reason?: string | null;
  chosenSource?: "AI" | "HUMAN" | string;
  knowledgeId?: number | null;
  aiFixedContent?: string | null;
  packageName?: string | null;
  currentVersion?: string | null;
  fixedVersion?: string | null;
  cveId?: string | null;
  source?: string | null;
  riskAccepted?: boolean;
}

export interface FixApplyResponse {
  commitUrl?: string;
  sha?: string;
  knowledgeId?: number;
  knowledgeSaved?: boolean;
  status?: "COMMITTED" | "PENDING_APPROVAL" | string;
  requestId?: number;
  message?: string;
  proposedVersion?: string;
  officialVersion?: string;
  requestedByLogin?: string;
  chosenSource?: string;
}

export interface AppNotificationDto {
  id: number;
  type?: string | null;
  title?: string | null;
  message?: string | null;
  link?: string | null;
  relatedRequestId?: number | null;
  read?: boolean;
  createdAt?: string | null;
}

export interface PolicyDeviationDto {
  id: number;
  cveId?: string | null;
  packageName?: string | null;
  officialVersion?: string | null;
  proposedVersion?: string | null;
  currentVersion?: string | null;
  reason?: string | null;
  status?: string | null;
  requestedByLogin?: string | null;
  reviewedByLogin?: string | null;
  reviewComment?: string | null;
  repoFullName?: string | null;
  filePath?: string | null;
  branch?: string | null;
  commitUrl?: string | null;
  commitMessage?: string | null;
  errorMessage?: string | null;
  error?: string | null;
  commitFailed?: boolean;
  createdAt?: string | null;
  reviewedAt?: string | null;
}

export interface GitRepoDto {
  name: string;
  fullName: string;
  description: string;
  language: string;
  private?: boolean;
  isPrivate?: boolean;
  stars: number;
  htmlUrl: string;
  updatedAt: string;
  provider: "GITHUB" | "GITLAB" | string;
}

export interface UserDto {
  id: number;
  login: string;
  name: string;
  avatarUrl: string;
  email: string;
  role: string;
  systemRole: "ADMIN" | "EMPLOYEE" | string;
  accessRoleId?: number | null;
  accessRoleKey?: string | null;
  permissions: string[];
  suspended: boolean;
  primaryProvider: "GITHUB" | "GITLAB" | "LOCAL" | string;
  hasGithubLinked: boolean;
  hasGitlabLinked: boolean;
  gitlabUrl?: string | null;
  hasLocalPassword: boolean;
  createdAt?: string;
  aiProvider?: string | null; // "GEMINI" | "CLAUDE" | "OPENAI" | null
  aiModel?: string | null; // model name or null
  hasCustomAiKey?: boolean; // true if user has set their own key
}

export interface AccessRoleDto {
  id: number;
  roleKey: string;
  name: string;
  description: string | null;
  baseRole: "ADMIN" | "EMPLOYEE" | string;
  systemRole: boolean;
  permissions: string[];
}

export interface LocalLoginResponse {
  user: UserDto;
}

export interface ClientDto {
  id: number;
  name: string;
  company?: string;
  domainName?: string;
  email?: string;
  createdById?: number;
  createdByLogin?: string;
  employeeIds: number[];
  employeeLogins: string[];
  repositoryIds: number[];
  repositoryUrls: string[];
  createdAt?: string;
}

export interface CreateClientRequest {
  name: string;
  company?: string;
  domainName?: string;
  email?: string;
}

export interface UpdateClientRequest {
  name?: string;
  company?: string;
  domainName?: string;
  email?: string;
}

export interface CiTokenDto {
  id: number;
  name: string;
  tokenPrefix: string;
  clientId: number;
  clientName?: string;
  repositoryIds: number[];
  repositoryUrls: string[];
  scopes: string[];
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  revokedAt?: string | null;
  createdAt?: string;
  active: boolean;
  revealable?: boolean;
}

export interface CiTokenCreatedDto extends CiTokenDto {
  token: string;
}

export interface CreateCiTokenRequest {
  name: string;
  clientId: number;
  repositoryIds: number[];
  expiresInDays?: number;
}

export interface ServerNodeRequest {
  name: string;
  host: string;
  port: number;
  username: string;
  nodeType: string;
  authMethod: "PASSWORD" | "PRIVATE_KEY";
  environment?: string;
  templateKey?: string;
  owner?: string;
  clientName?: string;
  projectName?: string;
  runbookUrl?: string;
  tags?: string[];
  notes?: string;
  password?: string;
  privateKey?: string;
  privateKeyPassphrase?: string;
  description?: string;
}

export interface ServerNodeDto {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  nodeType: string;
  environment?: string | null;
  templateKey?: string | null;
  owner?: string | null;
  clientName?: string | null;
  projectName?: string | null;
  runbookUrl?: string | null;
  tags: string[];
  notes?: string | null;
  description?: string | null;
  lastScannedAt?: string | null;
  latestStatus?: string | null;
  criticalCount: number;
  warningCount: number;
  infoCount: number;
  osName?: string | null;
  kernelVersion?: string | null;
  firewallStatus?: string | null;
}

export interface PortExposureDto {
  portNumber: number;
  protocol: string;
  bindAddress: string;
  processName: string;
  serviceName: string;
  exposureLevel: string;
  state: string;
}

export interface PortRecommendationDto {
  portNumber: number;
  protocol: string;
  serviceName: string;
  /** Explication du risque de sécurité (en français) */
  riskReason: string;
  /** Commande Linux pour désactiver ce port/service */
  disableCommand: string;
  /** CRITICAL | WARNING | INFO */
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | string;
}

export interface ServiceStatusDto {
  serviceName: string;
  state: string;
  subState: string;
  enabledStatus: string;
}

export interface HardeningFindingDto {
  id: number;
  category: string;
  severity: "CRITICAL" | "WARNING" | "INFO" | string;
  title: string;
  description: string;
  recommendation: string;
  detectedValue?: string | null;
}

export interface ConfigSnapshotDto {
  id: number;
  status: string;
  collectedAt: string;
  summary: string;
  criticalCount: number;
  warningCount: number;
  infoCount: number;
  driftChanges: string[];
}

export interface ServerNodeDetailDto {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  nodeType: string;
  authMethod: string;
  environment?: string | null;
  templateKey?: string | null;
  owner?: string | null;
  clientName?: string | null;
  projectName?: string | null;
  runbookUrl?: string | null;
  tags: string[];
  notes?: string | null;
  description?: string | null;
  lastScannedAt?: string | null;
  latestStatus?: string | null;
  hostname?: string | null;
  osName?: string | null;
  kernelVersion?: string | null;
  cpuSummary?: string | null;
  memorySummary?: string | null;
  diskSummary?: string | null;
  firewallStatus?: string | null;
  sshRootLogin?: string | null;
  dockerSummary?: string | null;
  certificateSummary?: string | null;
  summary?: string | null;
  journalExcerpt?: string | null;
  criticalCount: number;
  warningCount: number;
  infoCount: number;
  driftChanges: string[];
  ports: PortExposureDto[];
  services: ServiceStatusDto[];
  findings: HardeningFindingDto[];
  recentSnapshots: ConfigSnapshotDto[];
}

export interface CveJournalIntervention {
  id: number;
  cveId?: string | null;
  packageName?: string | null;
  fromVersion?: string | null;
  toVersion?: string | null;
  reason?: string | null;
  createdByLogin?: string | null;
  repoFullName?: string | null;
  status?: string | null;
  usageCount?: number;
  createdAt?: string | null;
}

export interface CveJournalEntry {
  cveId?: string | null;
  packageName?: string | null;
  severity?: string | null;
  cvssScore?: number | null;
  epssScore?: number | null;
  fixedVersion?: string | null;
  source?: string | null;
  ecosystem?: string | null;
  description?: string | null;
  detectionCount?: number;
  kevListed?: boolean;
  exploitAvailable?: boolean;
  officialStableVersion?: string | null;
  officialComment?: string | null;
  officialUpdatedBy?: string | null;
  officialUpdatedById?: number | null;
  officialUpdatedAt?: string | null;
  guidanceId?: number | null;
  developerInterventions?: CveJournalIntervention[];
  hasDeveloperFix?: boolean;
  hasOfficialGuidance?: boolean;
  remediationStatus?: string | null;
  remediationStatusLabel?: string | null;
  policySource?: "CHEF" | "SCAN" | string | null;
  preferredFixVersion?: string | null;
}

export interface CveJournalResponse {
  catalog: CveJournalEntry[];
  interventions: CveJournalIntervention[];
  stats: {
    totalCves: number;
    withOfficialGuidance: number;
    withDeveloperFix: number;
    interventionCount: number;
    byStatus?: Record<string, number>;
  };
}

export interface CveJournalPolicy {
  cveId?: string;
  packageName?: string | null;
  officialStableVersion?: string | null;
  officialComment?: string | null;
  officialUpdatedBy?: string | null;
  guidanceId?: number | null;
  policySource?: "CHEF" | string | null;
}

export interface CveAuditEventDto {
  id?: number | null;
  cveId?: string | null;
  packageName?: string | null;
  eventType?: string | null;
  actorLogin?: string | null;
  fromVersion?: string | null;
  toVersion?: string | null;
  officialVersion?: string | null;
  repoFullName?: string | null;
  message?: string | null;
  createdAt?: string | null;
  synthetic?: boolean;
}

export interface CveVersionRecommendation {
  cveId?: string | null;
  packageName?: string | null;
  candidates?: string[];
  recommendedVersion?: string | null;
  rationale?: string | null;
  comparedToOthers?: Array<{ version?: string; whyNot?: string }>;
  source?: "LLM" | "HEURISTIC" | "NONE" | "ERROR" | string | null;
  aiProvider?: string | null;
  aiError?: string | null;
}

export interface OfficialGuidanceRequest {
  cveId: string;
  packageName?: string;
  stableVersion: string;
  comment?: string;
}

/** Auth is cookie-based (HttpOnly); keep helper for call sites that pass headers. */
const authHeaders = () => ({});

export const requestFix = (data: FixPreviewRequest) =>
  API.post<FixPreviewResponse>("/autofix/preview", data, {
    headers: authHeaders(),
  });

export const applyFix = (data: FixApplyRequest) =>
  API.post<FixApplyResponse>("/autofix/apply", data, {
    headers: authHeaders(),
  });

export interface VersionValidationResult {
  packageName?: string;
  cveId?: string;
  currentVersion?: string | null;
  recommendedVersion?: string | null;
  chosenVersion?: string | null;
  verdict: "OK" | "RISKY" | "UNKNOWN" | string;
  riskLevel?: "LOW" | "MEDIUM" | "HIGH" | string;
  title?: string;
  summary?: string;
  details?: string[];
  advice?: string;
  canProceed?: boolean;
  source?: string;
}

export const validateFixVersion = (data: {
  packageName: string;
  currentVersion?: string | null;
  recommendedVersion?: string | null;
  chosenVersion?: string | null;
  cveId?: string | null;
  ecosystem?: string | null;
  filePath?: string | null;
  fixedContent?: string | null;
}) =>
  API.post<VersionValidationResult>("/autofix/validate-version", data, {
    headers: authHeaders(),
  });

export const getGithubRepos = () => API.get<GitRepoDto[]>("/auth/github/repos");

export const getGithubLinkUrl = () =>
  API.get<{ url: string }>("/auth/github/link-url");

export const getGitlabProjects = () =>
  API.get<GitRepoDto[]>("/auth/gitlab/projects");

export const getGitlabLinkUrl = () =>
  API.get<{ url: string }>("/auth/gitlab/link-url");

export const linkProviderToken = (
  provider: "GITHUB" | "GITLAB",
  token: string,
  gitlabUrl?: string,
) => API.post<UserDto>("/auth/link-token", { provider, token, gitlabUrl });

export interface ProviderTokenStatus {
  linked: boolean;
  tokenKind?: string;
  maskedToken?: string | null;
  valid?: boolean;
  warning?: string | null;
  error?: string | null;
  githubLogin?: string | null;
  githubName?: string | null;
  scopes?: string | null;
  hasRepoScope?: boolean;
  repoFullName?: string | null;
  canPush?: boolean;
  pushError?: string | null;
  permissions?: Record<string, boolean> | null;
  gitlabUrl?: string | null;
  gitlabLogin?: string | null;
}

export interface TokensStatusResponse {
  github: ProviderTokenStatus;
  gitlab: ProviderTokenStatus;
}

export const getTokensStatus = (repoFullName?: string | null) =>
  API.get<TokensStatusResponse>("/users/me/git-tokens", {
    params: repoFullName ? { repoFullName } : undefined,
  });

export const unlinkGithubToken = () => API.delete<UserDto>("/users/me/github-token");

export const unlinkGitlabToken = () => API.delete<UserDto>("/users/me/gitlab-token");

export const loginWithEmail = (email: string, password: string) =>
  API.post<LocalLoginResponse>("/auth/login", { email, password });

export const getUsers = () => API.get<UserDto[]>("/users");

export const createUser = (data: {
  login: string;
  name: string;
  email: string;
  password: string;
  accessRoleId: number | null;
  role?: string;
}) => API.post<UserDto>("/users", data);

export const updateUser = (
  id: number,
  data: {
    login: string;
    name: string;
    email: string;
    password?: string;
    accessRoleId: number | null;
    role?: string;
  },
) => API.put<UserDto>(`/users/${id}`, data);

export const updateUserRole = (
  id: number,
  accessRoleId: number,
  role?: string,
) => API.put<UserDto>(`/users/${id}/role`, { accessRoleId, role });

export const updateUserSuspension = (id: number, suspended: boolean) =>
  API.put<UserDto>(`/users/${id}/suspension`, { suspended });

export const deleteUser = (id: number) => API.delete(`/users/${id}`);

export const getAccessRoles = () => API.get<AccessRoleDto[]>("/access-roles");

export const createAccessRole = (data: {
  name: string;
  description: string;
  baseRole: string;
  permissions: string[];
}) => API.post<AccessRoleDto>("/access-roles", data);

export const updateAccessRole = (
  id: number,
  data: {
    name: string;
    description: string;
    baseRole: string;
    permissions: string[];
  },
) => API.put<AccessRoleDto>(`/access-roles/${id}`, data);

export const deleteAccessRole = (id: number) =>
  API.delete(`/access-roles/${id}`);

export const getClients = () => API.get<ClientDto[]>("/clients");

export const getServerNodes = () => API.get<ServerNodeDto[]>("/servers");

export const createServerNode = (data: ServerNodeRequest) =>
  API.post<ServerNodeDto>("/servers", data);

export const updateServerNode = (id: number, data: ServerNodeRequest) =>
  API.put<ServerNodeDto>(`/servers/${id}`, data);

export const deleteServerNode = (id: number) => API.delete(`/servers/${id}`);

export const getServerNode = (id: number) =>
  API.get<ServerNodeDetailDto>(`/servers/${id}`);

export const getLiveServerNode = (id: number) =>
  API.post<ServerNodeDetailDto>(`/servers/${id}/live`);

export const scanServerNode = (id: number) =>
  API.post<ServerNodeDetailDto>(`/servers/${id}/scan`);

/** Génère des recommandations IA pour les ports exposés du dernier scan du serveur */
export const getPortRecommendations = (id: number) =>
  API.post<PortRecommendationDto[]>(`/servers/${id}/port-recommendations`);

export const getServerFindings = (id: number) =>
  API.get<HardeningFindingDto[]>(`/servers/${id}/findings`);

export const getCveJournal = () =>
  API.get<CveJournalResponse>("/cve-journal");

export const getCveJournalPolicy = (cveId: string, packageName?: string | null) =>
  API.get<CveJournalPolicy>("/cve-journal/policy", {
    params: { cveId, packageName: packageName ?? "" },
  });

export const getCveJournalTimeline = (cveId: string, packageName?: string | null) =>
  API.get<CveAuditEventDto[]>("/cve-journal/timeline", {
    params: { cveId, packageName: packageName ?? "" },
  });

export const getCveJournalRecommendation = (params: {
  cveId: string;
  packageName?: string | null;
  fixedVersion?: string | null;
  severity?: string | null;
  description?: string | null;
  ecosystem?: string | null;
}) =>
  API.post<CveVersionRecommendation>("/cve-journal/recommend", {
    cveId: params.cveId,
    packageName: params.packageName ?? "",
    fixedVersion: params.fixedVersion ?? "",
    severity: params.severity ?? "",
    description: params.description ?? "",
    ecosystem: params.ecosystem ?? "",
  });

export const upsertOfficialGuidance = (data: OfficialGuidanceRequest) =>
  API.put<{
    id: number;
    cveId: string;
    packageName?: string;
    stableVersion: string;
    comment?: string;
    updatedByLogin?: string;
    updatedAt?: string;
  }>("/cve-journal/official", data);

export const deleteOfficialGuidance = (id: number) =>
  API.delete(`/cve-journal/official/${id}`);

export const getNotifications = () =>
  API.get<AppNotificationDto[]>("/notifications");

export const getUnreadNotificationCount = () =>
  API.get<{ count: number }>("/notifications/unread-count");

export const markNotificationRead = (id: number) =>
  API.post(`/notifications/${id}/read`);

export const markAllNotificationsRead = () =>
  API.post("/notifications/read-all");

export const clearAllNotifications = () =>
  API.post("/notifications/clear-all");

export const getPendingPolicyDeviations = () =>
  API.get<PolicyDeviationDto[]>("/policy-deviations/pending");

export const approvePolicyDeviation = (id: number, comment?: string) =>
  API.post<PolicyDeviationDto>(`/policy-deviations/${id}/approve`, { comment: comment ?? null });

export const rejectPolicyDeviation = (id: number, comment?: string) =>
  API.post<PolicyDeviationDto>(`/policy-deviations/${id}/reject`, { comment: comment ?? null });

export const getClient = (id: number) => API.get<ClientDto>(`/clients/${id}`);

export const createClient = (data: {
  name: string;
  company: string;
  domainName?: string;
  email: string;
}) => API.post<ClientDto>("/clients", data);

export const updateClient = (
  id: number,
  data: { name: string; company: string; domainName?: string; email: string },
) => API.put<ClientDto>(`/clients/${id}`, data);

export const assignEmployeeToClient = (id: number, employeeId: number) =>
  API.post<ClientDto>(`/clients/${id}/assign-employee`, { employeeId });

export const assignRepositoryToClient = (id: number, repositoryId: number) =>
  API.post<ClientDto>(`/clients/${id}/assign-repo`, { repositoryId });

export const removeRepositoryFromClient = (id: number, repoId: number) =>
  API.delete(`/clients/${id}/repos/${repoId}`);

export const listCiTokens = (clientId: number) =>
  API.get<CiTokenDto[]>("/admin/ci-tokens", { params: { clientId } });

export const createCiToken = (data: CreateCiTokenRequest) =>
  API.post<CiTokenCreatedDto>("/admin/ci-tokens", data);

export const revokeCiToken = (id: number) =>
  API.delete<CiTokenDto>(`/admin/ci-tokens/${id}`);

export const revealCiToken = (id: number) =>
  API.get<CiTokenCreatedDto>(`/admin/ci-tokens/${id}/secret`);

export const deleteCiTokenPermanently = (id: number) =>
  API.delete(`/admin/ci-tokens/${id}/permanent`);

// ── SSL Analysis ─────────────────────────────────────────────────────────────

export type TlsProtocolStatus = 'ENABLED' | 'DISABLED' | 'NOT_TESTED' | 'INCONCLUSIVE';
export type TlsCipherStrength = 'STRONG' | 'WEAK' | 'FORBIDDEN';

export interface TlsCipherSuiteDto {
  ianaName: string;
  opensslName?: string;
  encryption?: string;
  keyExchange?: string;
  keySize?: number;
  forwardSecrecy: boolean;
  aead: boolean;
  strength: TlsCipherStrength;
}

export interface TlsProtocolDetailDto {
  id: string;
  label: string;
  status: TlsProtocolStatus;
  handshakeOk?: boolean | null;
  acceptedCount?: number;
  weakCount?: number;
  forbiddenCount?: number;
  forwardSecrecy?: boolean | null;
  aead?: boolean | null;
  compression?: boolean | null;
  secureRenegotiation?: boolean | null;
  endpoint?: string | null;
  ip?: string | null;
  port?: number | null;
  sni?: string | null;
  tool?: string | null;
  toolVersion?: string | null;
  scannedAt?: string | null;
  confidence?: string | null;
  evidence?: string | null;
  ciphers?: TlsCipherSuiteDto[];
}

export interface CertNameDto {
  commonName?: string | null;
  organization?: string | null;
  country?: string | null;
  countryName?: string | null;
  rfc4514?: string | null;
}

export interface CertSanEntryDto {
  type: string;
  value: string;
  matchStatus?: string | null;
}

export interface CertChainEntryDto {
  type: string;
  subject?: CertNameDto | null;
  issuer?: CertNameDto | null;
  serialNumber?: string | null;
  notAfter?: string | null;
  signatureAlgorithm?: string | null;
  sha256Fingerprint?: string | null;
  status?: string | null;
  pem?: string | null;
}

export interface CertTrustStoreDto {
  platform: string;
  status: string;
  storeVersion?: string | null;
  validationError?: string | null;
}

export interface CertificateDetailDto {
  validityStatus?: string | null;
  notBefore?: string | null;
  notAfter?: string | null;
  totalValidityDays?: number | null;
  daysRemaining?: number | null;
  percentRemaining?: number | null;
  recommendedRenewalDate?: string | null;
  expired?: boolean | null;
  commonName?: string | null;
  testedHostname?: string | null;
  hostnameMatch?: string | null;
  wildcard?: boolean | null;
  sans?: CertSanEntryDto[];
  publicKeyAlgorithm?: string | null;
  keyType?: string | null;
  keySize?: number | null;
  curveName?: string | null;
  signatureAlgorithm?: string | null;
  hashAlgorithm?: string | null;
  securityLevel?: string | null;
  weakKey?: boolean | null;
  obsoleteSignature?: boolean | null;
  chainComplete?: boolean | null;
  chainOrderValid?: boolean | null;
  intermediatePresent?: boolean | null;
  rootRecognized?: boolean | null;
  selfSigned?: boolean | null;
  validationError?: string | null;
  chain?: CertChainEntryDto[];
  ocspUrlStatus?: string | null;
  ocspUrl?: string | null;
  ocspResponseStatus?: string | null;
  revocationStatus?: string | null;
  ocspStaplingStatus?: string | null;
  crlUrlStatus?: string | null;
  crlUrl?: string | null;
  transparencyStatus?: string | null;
  sctCount?: number | null;
  ctLogs?: string | null;
  mustStaple?: boolean | null;
  keyUsage?: string | null;
  extendedKeyUsage?: string | null;
  serverAuth?: boolean | null;
  clientAuth?: boolean | null;
  basicConstraints?: string | null;
  isCa?: boolean | null;
  trustStores?: CertTrustStoreDto[];
  endpoint?: string | null;
  ip?: string | null;
  port?: number | null;
  sni?: string | null;
  scannedAt?: string | null;
  scanDuration?: string | null;
  tool?: string | null;
  toolVersion?: string | null;
  confidence?: string | null;
  sha256Fingerprint?: string | null;
  serialNumber?: string | null;
  leafPem?: string | null;
  ev?: boolean | null;
}

export interface SslResultDto {
  domain: string;
  grade: string;
  scanStatus: string;
  source: string;
  // Protocols
  tls10: boolean;
  tls11: boolean;
  tls12: boolean;
  tls13: boolean;
  /** Detailed matrix from SSLyze (or Kali fallback) — 6 entries when present */
  tlsProtocols?: TlsProtocolDetailDto[];
  certificateDetail?: CertificateDetailDto | null;
  // Vulnerabilities
  heartbleed: boolean;
  /** Preuve brute Heartbleed (sslscan / nmap / testssl). */
  heartbleedEvidence?: string | null;
  sweet32: boolean;
  has3des: boolean;
  crime: boolean;
  poodle: boolean;
  beast: boolean;
  robot: boolean;
  freak: boolean;
  logjam: boolean;
  rc4: boolean;
  drown: boolean;
  // Certificate
  certExpired: boolean;
  certDaysLeft: number;
  certIssuer: string;
  certSubject: string;
  chainComplete: boolean;
  certSignatureAlg: string;
  certKeySize: string;
  certNotBefore: string;
  certNotAfterStr: string;
  certSerialNumber: string;
  certEv: boolean;
  certWildcard: boolean;
  certTransparency: boolean;
  certSansCount: number;
  // Headers
  hsts: boolean;
  ocspStapling: boolean;
  xFrameOptions: boolean;
  xContentTypeOptions: boolean;
  contentSecurityPolicy: boolean;
  /** Present when only CSP-Report-Only is set (does not block XSS). */
  cspReportOnly?: boolean;
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
  crossOriginOpenerPolicy?: boolean;
  crossOriginResourcePolicy?: boolean;
  crossOriginEmbedderPolicy?: boolean;
  hstsValue?: string | null;
  cspValue?: string | null;
  xFrameOptionsValue?: string | null;
  xContentTypeOptionsValue?: string | null;
  referrerPolicyValue?: string | null;
  permissionsPolicyValue?: string | null;
  crossOriginOpenerPolicyValue?: string | null;
  crossOriginResourcePolicyValue?: string | null;
  crossOriginEmbedderPolicyValue?: string | null;
  headersCheckedUrl?: string | null;
  headersHttpStatus?: number | null;
  headersLiveChecked?: boolean;
  // SSL Labs external scan
  ssllabsGrade: string;
  ssllabsStatus: string; // 'PENDING' | 'READY' | 'ERROR' | 'TIMEOUT' | 'DISABLED'
  ssllabsIpAddress: string;
  ssllabsHasWarnings: boolean;
  ssllabsForwardSecrecy: boolean;
  ssllabsDrown: boolean;
  // Censys Platform API
  censysGrade: string;
  censysStatus: string; // 'PENDING' | 'READY' | 'ERROR' | 'DISABLED'
  censysIpAddress: string;
  censysDaysLeft: number;
  censysExpired: boolean;
  censysCertValid: boolean;
  censysIssuer: string;
  censysKeySize: string;
  censysValidationLevel: string; // 'DV' | 'OV' | 'EV'
  censysCtPresent: boolean;
  censysSansCount: number;
  censysOpenPorts: string;
  // SSLyze (local parse of sslyze.json from Kali scan)
  sslyzeGrade: string;
  sslyzeStatus: string; // 'PENDING' | 'READY' | 'ERROR'
  sslyzeIpAddress: string;
  sslyzeSupportsSSL20: boolean;
  sslyzeSupportsSSL30: boolean;
  sslyzeSupportsTLS10: boolean;
  sslyzeSupportsTLS11: boolean;
  sslyzeSupportsTLS12: boolean;
  sslyzeSupportsTLS13: boolean;
  sslyzeHeartbleed: boolean;
  sslyzeRobot: boolean;
  sslyzeCcsInjection: boolean;
  sslyzeCompression: boolean;
  sslyzeInsecureRenegotiation: boolean;
  sslyzeCertSubject: string;
  sslyzeCertIssuer: string;
  sslyzeKeySize: number;
  sslyzeChainTrusted: boolean;
  sslyzeOcspStapling: boolean;
  sslyzeDaysLeft: number;
  sslyzeCipherCount: number;
  sslyzeVersion?: string | null;
  sslyzeScanStarted?: string | null;
  sslyzeSni?: string | null;
  sslyzePort?: number | null;
  // Combined (weighted fusion of all sources)
  combinedGrade: string;
  sourcesReady: number;
  sourcesTotal: number;
}

export const startSslScan = (domain: string) =>
  API.post<ScanResponse>("/ssl/scan", { domain });

export const getSslResult = (scanId: number) =>
  API.get<SslResultDto>(`/ssl/scan/${scanId}/result`).then(res => {
    // Jackson may emit xframeOptions / xcontentTypeOptions without @JsonProperty
    const d = res.data as SslResultDto & {
      xframeOptions?: boolean;
      xcontentTypeOptions?: boolean;
    };
    if (d.xFrameOptions === undefined && d.xframeOptions !== undefined) {
      d.xFrameOptions = d.xframeOptions;
    }
    if (d.xContentTypeOptions === undefined && d.xcontentTypeOptions !== undefined) {
      d.xContentTypeOptions = d.xcontentTypeOptions;
    }
    return res;
  });

// ── AI Summary ────────────────────────────────────────────────────────────────

export const getAiSummary = (scanId: number) =>
  API.get<{ summary: string }>(`/scans/${scanId}/ai-summary`);

export const getSslAiAnalysis = (context: Record<string, unknown>) =>
  API.post<{ summary: string; keyRisks: string[]; recommendations: string[] }>(
    "/ssl/ai-analysis",
    context,
  );

// ── Scheduled Scans ──────────────────────────────────────────────────────────

export type ScheduleType = "ONCE" | "WEEKLY" | "EVERY_15_DAYS" | "MONTHLY";
export type ScheduledScanStatus =
  | "ACTIVE"
  | "PAUSED"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED";

export interface ScheduledScan {
  id: number;
  repositoryId: number;
  repositoryName: string;
  repoUrl: string;
  branch?: string;
  scanMode: string;
  targetDomain?: string;
  dastTargetUrl?: string;
  scheduleType: ScheduleType;
  startAt: string;
  nextRunAt: string;
  lastRunAt?: string;
  timezone: string;
  status: ScheduledScanStatus;
  enabled: boolean;
  runCount: number;
  lastScanId?: number;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScheduledScanCreateRequest {
  repositoryId?: number;
  repositoryName: string;
  repoUrl: string;
  branch?: string;
  scanMode: string;
  targetDomain?: string;
  dastTargetUrl?: string;
  scheduleType: ScheduleType;
  startAt: string; // "yyyy-MM-ddTHH:mm:ss"
  timezone: string; // IANA e.g. "Africa/Tunis"
}

export const createScheduledScan = (data: ScheduledScanCreateRequest) =>
  API.post<ScheduledScan>("/scheduled-scans", data);

export const getScheduledScans = () =>
  API.get<ScheduledScan[]>("/scheduled-scans");

export const getRepositoryScheduledScans = (repositoryId: number) =>
  API.get<ScheduledScan[]>(`/repositories/${repositoryId}/scheduled-scans`);

export const getScheduledSummary = () =>
  API.get<Record<string, ScheduledScan>>("/repositories/scheduled-summary");

export const updateScheduledScan = (
  id: number,
  data: Partial<ScheduledScanCreateRequest>,
) => API.put<ScheduledScan>(`/scheduled-scans/${id}`, data);

export const pauseScheduledScan = (id: number) =>
  API.patch<ScheduledScan>(`/scheduled-scans/${id}/pause`);

export const resumeScheduledScan = (id: number) =>
  API.patch<ScheduledScan>(`/scheduled-scans/${id}/resume`);

export const deleteScheduledScan = (id: number) =>
  API.delete(`/scheduled-scans/${id}`);

// ── AI Settings ──────────────────────────────────────────────────────────────

export interface AiSettingsRequest {
  aiProvider: string; // "GEMINI" | "CLAUDE" | "OPENAI"
  aiModel: string; // e.g., "gemini-1.5-pro", "claude-opus-4-5", "gpt-4o"
  aiApiKey: string; // the user's personal API key
}

export const updateAiSettings = (data: AiSettingsRequest) =>
  API.patch<UserDto>("/users/me/ai-settings", data);

export const clearAiSettings = () =>
  API.delete<UserDto>("/users/me/ai-settings");

// ── Assistant Vulnix ─────────────────────────────────────────────────────────

export interface AssistantChatTurn {
  role: "user" | "assistant";
  content: string;
}

export interface AssistantLinkDto {
  label: string;
  href: string;
}

export interface AssistantChatRequest {
  message: string;
  page?: string;
  scanId?: number;
  serverId?: number;
  history?: AssistantChatTurn[];
}

export interface AssistantChatResponse {
  reply: string;
  contextLabel: string;
  links: AssistantLinkDto[];
  usedAi: boolean;
}

export const chatWithAssistant = (data: AssistantChatRequest) =>
  API.post<AssistantChatResponse>("/assistant/chat", data);

export default API;
