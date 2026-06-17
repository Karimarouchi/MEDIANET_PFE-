import axios from 'axios';

const API = axios.create({
  baseURL: '/api',
});

// Automatically attach the JWT token to every request
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('vulnix_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

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
  API.post<ScanResponse>('/scans', data);

// Get CVEs for a scan
export const getCvesByScan = (scanId: number) =>
  API.get<CveDto[]>(`/scans/${scanId}/cves`);

// Get all repositories
export const getRepositories = () =>
  API.get<RepositoryDto[]>('/repositories');

// Get all scans
export const getAllScans = () =>
  API.get<ScanResultDto[]>('/scans');

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
  result: 'pass' | 'fail' | 'error' | 'unknown';
  severity: 'high' | 'medium' | 'low' | 'informational';
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
export const stopScan = (scanId: number) =>
  API.post(`/scans/${scanId}/stop`);

// Delete a scan
export const deleteScan = (scanId: number) =>
  API.delete(`/scans/${scanId}`);

// ── Auto-Fix programmatique ───────────────────────────────────────────────────

export interface FixPreviewRequest {
  repoFullName: string;
  packageName: string;
  currentVersion: string;
  fixedVersion: string;
  cveId: string;
  filePath: string | null;
  source: string | null;
  provider?: 'GITHUB' | 'GITLAB';
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
}

export interface FixApplyRequest {
  repoFullName: string;
  filePath: string;
  sha: string;
  fixedContent: string;
  commitMessage: string;
  provider?: 'GITHUB' | 'GITLAB';
  branch?: string | null;
  // optional lock file fields — when present, the lock file is also committed
  lockFilePath?: string | null;
  lockFileSha?: string | null;
  lockFileContent?: string | null;
}

export interface FixApplyResponse {
  commitUrl: string;
  sha: string;
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
  provider: 'GITHUB' | 'GITLAB' | string;
}

export interface UserDto {
  id: number;
  login: string;
  name: string;
  avatarUrl: string;
  email: string;
  role: string;
  systemRole: 'ADMIN' | 'EMPLOYEE' | string;
  accessRoleId?: number | null;
  accessRoleKey?: string | null;
  permissions: string[];
  suspended: boolean;
  primaryProvider: 'GITHUB' | 'GITLAB' | 'LOCAL' | string;
  hasGithubLinked: boolean;
  hasGitlabLinked: boolean;
  hasLocalPassword: boolean;
  createdAt?: string;
}

export interface AccessRoleDto {
  id: number;
  roleKey: string;
  name: string;
  description: string | null;
  baseRole: 'ADMIN' | 'EMPLOYEE' | string;
  systemRole: boolean;
  permissions: string[];
}

export interface LocalLoginResponse {
  token: string;
  user: UserDto;
}

export interface ClientDto {
  id: number;
  name: string;
  company: string;
  email: string;
  createdById: number | null;
  createdByLogin: string | null;
  employeeIds: number[];
  employeeLogins: string[];
  repositoryIds: number[];
  repositoryUrls: string[];
  createdAt?: string;
}

export interface ServerNodeRequest {
  name: string;
  host: string;
  port: number;
  username: string;
  nodeType: string;
  authMethod: 'PASSWORD' | 'PRIVATE_KEY';
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

export interface ServiceStatusDto {
  serviceName: string;
  state: string;
  subState: string;
  enabledStatus: string;
}

export interface HardeningFindingDto {
  id: number;
  category: string;
  severity: 'CRITICAL' | 'WARNING' | 'INFO' | string;
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

export interface PipelineDefinitionRequest {
  name?: string;
  description?: string;
  repositoryId?: number | null;
  repoUrl?: string;
  branch?: string;
  runnerServerId?: number | null;
  stagingServerId?: number | null;
  productionServerId?: number | null;
  workspacePath?: string;
  buildCommand?: string;
  testCommand?: string;
  dockerBuildCommand?: string;
  containerScanCommand?: string;
  stagingDeployCommand?: string;
  dastCommand?: string;
  productionDeployCommand?: string;
  approvalRequired?: boolean;
  failOnCritical?: boolean;
  failOnSecrets?: boolean;
  active?: boolean;
}

export interface PipelineStageRunDto {
  id: number;
  stageType: string;
  title: string;
  stageOrder: number;
  status: string;
  details?: string | null;
  logOutput?: string | null;
  relatedScanId?: number | null;
  startedAt?: string | null;
  finishedAt?: string | null;
}

export interface DockerHubCredentialDto {
  username?: string | null;
  hasToken: boolean;
}

export interface DockerHubCredentialRequest {
  username?: string;
  token?: string;
}

export interface PipelinePresetDto {
  name: string;
  description?: string | null;
  repoUrl?: string | null;
  branch?: string | null;
  workspacePath?: string | null;
  buildCommand?: string | null;
  testCommand?: string | null;
  dockerBuildCommand?: string | null;
  containerScanCommand?: string | null;
  stagingDeployCommand?: string | null;
  dastCommand?: string | null;
  productionDeployCommand?: string | null;
  approvalRequired: boolean;
  failOnCritical: boolean;
  failOnSecrets: boolean;
  active: boolean;
  imagePrefix?: string | null;
  dockerHubUsername?: string | null;
  detectedComponents: string[];
  summary?: string | null;
}

export interface PipelineRunDto {
  id: number;
  pipelineId: number;
  pipelineName: string;
  status: string;
  currentStage?: string | null;
  approvalRequired: boolean;
  securityScanId?: number | null;
  summary?: string | null;
  triggeredByLogin?: string | null;
  approvedByLogin?: string | null;
  startedAt?: string | null;
  finishedAt?: string | null;
  approvedAt?: string | null;
  stages: PipelineStageRunDto[];
}

export interface PipelineLogEventDto {
  type: 'snapshot' | 'log' | 'complete' | string;
  runId: number;
  stageId?: number | null;
  stageType?: string | null;
  message?: string | null;
  run?: PipelineRunDto | null;
  timestamp?: string | null;
}

export interface PipelineDefinitionDto {
  id: number;
  name: string;
  description?: string | null;
  repositoryId?: number | null;
  repositoryLabel?: string | null;
  repoUrl?: string | null;
  branch?: string | null;
  sourceProvider?: string | null;
  runnerServerId?: number | null;
  runnerServerName?: string | null;
  stagingServerId?: number | null;
  stagingServerName?: string | null;
  productionServerId?: number | null;
  productionServerName?: string | null;
  workspacePath?: string | null;
  buildCommand?: string | null;
  testCommand?: string | null;
  dockerBuildCommand?: string | null;
  containerScanCommand?: string | null;
  stagingDeployCommand?: string | null;
  dastCommand?: string | null;
  productionDeployCommand?: string | null;
  approvalRequired: boolean;
  failOnCritical: boolean;
  failOnSecrets: boolean;
  active: boolean;
  createdAt?: string | null;
  updatedAt?: string | null;
  lastRunAt?: string | null;
  lastRun?: PipelineRunDto | null;
  // Security gate
  securityScanStatus?: string | null;   // PENDING | RUNNING | COMPLETED | FAILED
  criticalCveCount?: number | null;
  scanResultId?: number | null;
}

const authHeaders = () => {
  const token = localStorage.getItem('vulnix_token');
  return token ? { Authorization: `Bearer ${token}` } : {};
};

export const requestFix = (data: FixPreviewRequest) =>
  API.post<FixPreviewResponse>('/autofix/preview', data, { headers: authHeaders() });

export const applyFix = (data: FixApplyRequest) =>
  API.post<FixApplyResponse>('/autofix/apply', data, { headers: authHeaders() });

export const getGithubRepos = () =>
  API.get<GitRepoDto[]>('/auth/github/repos');

export const getGithubLinkUrl = () =>
  API.get<{ url: string }>('/auth/github/link-url');

export const getGitlabProjects = () =>
  API.get<GitRepoDto[]>('/auth/gitlab/projects');

export const getGitlabLinkUrl = () =>
  API.get<{ url: string }>('/auth/gitlab/link-url');

export const linkProviderToken = (provider: 'GITHUB' | 'GITLAB', token: string) =>
  API.post<UserDto>('/auth/link-token', { provider, token });

export const loginWithEmail = (email: string, password: string) =>
  API.post<LocalLoginResponse>('/auth/login', { email, password });

export const getUsers = () =>
  API.get<UserDto[]>('/users');

export const createUser = (data: { login: string; name: string; email: string; password: string; accessRoleId: number | null; role?: string }) =>
  API.post<UserDto>('/users', data);

export const updateUser = (id: number, data: { login: string; name: string; email: string; password?: string; accessRoleId: number | null; role?: string }) =>
  API.put<UserDto>(`/users/${id}`, data);

export const updateUserRole = (id: number, accessRoleId: number, role?: string) =>
  API.put<UserDto>(`/users/${id}/role`, { accessRoleId, role });

export const updateUserSuspension = (id: number, suspended: boolean) =>
  API.put<UserDto>(`/users/${id}/suspension`, { suspended });

export const deleteUser = (id: number) =>
  API.delete(`/users/${id}`);

export const getAccessRoles = () =>
  API.get<AccessRoleDto[]>('/access-roles');

export const createAccessRole = (data: { name: string; description: string; baseRole: string; permissions: string[] }) =>
  API.post<AccessRoleDto>('/access-roles', data);

export const updateAccessRole = (id: number, data: { name: string; description: string; baseRole: string; permissions: string[] }) =>
  API.put<AccessRoleDto>(`/access-roles/${id}`, data);

export const deleteAccessRole = (id: number) =>
  API.delete(`/access-roles/${id}`);

export const getClients = () =>
  API.get<ClientDto[]>('/clients');

export const getServerNodes = () =>
  API.get<ServerNodeDto[]>('/servers');

export const createServerNode = (data: ServerNodeRequest) =>
  API.post<ServerNodeDto>('/servers', data);

export const updateServerNode = (id: number, data: ServerNodeRequest) =>
  API.put<ServerNodeDto>(`/servers/${id}`, data);

export const deleteServerNode = (id: number) =>
  API.delete(`/servers/${id}`);

export const getServerNode = (id: number) =>
  API.get<ServerNodeDetailDto>(`/servers/${id}`);

export const getLiveServerNode = (id: number) =>
  API.post<ServerNodeDetailDto>(`/servers/${id}/live`);

export const scanServerNode = (id: number) =>
  API.post<ServerNodeDetailDto>(`/servers/${id}/scan`);

export const getServerFindings = (id: number) =>
  API.get<HardeningFindingDto[]>(`/servers/${id}/findings`);

export const getPipelines = () =>
  API.get<PipelineDefinitionDto[]>('/pipelines');

export const getPipeline = (id: number) =>
  API.get<PipelineDefinitionDto>(`/pipelines/${id}`);

export const getPipelinePreset = (repositoryId: number) =>
  API.get<PipelinePresetDto>(`/pipelines/presets/monolith-ecommerce?repositoryId=${repositoryId}`);

export const getDockerHubCredential = () =>
  API.get<DockerHubCredentialDto>('/pipelines/docker-hub-credential');

export const saveDockerHubCredential = (data: DockerHubCredentialRequest) =>
  API.put<DockerHubCredentialDto>('/pipelines/docker-hub-credential', data);

export const createPipeline = (data: PipelineDefinitionRequest) =>
  API.post<PipelineDefinitionDto>('/pipelines', data);

export const updatePipeline = (id: number, data: PipelineDefinitionRequest) =>
  API.put<PipelineDefinitionDto>(`/pipelines/${id}`, data);

export const deletePipeline = (id: number) =>
  API.delete(`/pipelines/${id}`);

export const runPipeline = (id: number) =>
  API.post<PipelineRunDto>(`/pipelines/${id}/run`);

export const getPipelineRuns = (id: number) =>
  API.get<PipelineRunDto[]>(`/pipelines/${id}/runs`);

export const getPipelineRun = (runId: number) =>
  API.get<PipelineRunDto>(`/pipelines/runs/${runId}`);

export const approvePipelineRun = (runId: number) =>
  API.post<PipelineRunDto>(`/pipelines/runs/${runId}/approve`);

export const getPipelineRunLogsStreamUrl = (runId: number, token?: string | null) => {
  const query = token ? `?token=${encodeURIComponent(token)}` : '';
  return `/api/pipelines/runs/${runId}/logs${query}`;
};

export const getClient = (id: number) =>
  API.get<ClientDto>(`/clients/${id}`);

export const createClient = (data: { name: string; company: string; email: string }) =>
  API.post<ClientDto>('/clients', data);

export const updateClient = (id: number, data: { name: string; company: string; email: string }) =>
  API.put<ClientDto>(`/clients/${id}`, data);

export const assignEmployeeToClient = (id: number, employeeId: number) =>
  API.post<ClientDto>(`/clients/${id}/assign-employee`, { employeeId });

export const assignRepositoryToClient = (id: number, repositoryId: number) =>
  API.post<ClientDto>(`/clients/${id}/assign-repo`, { repositoryId });

export const removeRepositoryFromClient = (id: number, repoId: number) =>
  API.delete(`/clients/${id}/repos/${repoId}`);

// ── SSL Analysis ─────────────────────────────────────────────────────────────

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
  // Vulnerabilities
  heartbleed: boolean;
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
  referrerPolicy: boolean;
  permissionsPolicy: boolean;
  // SSL Labs external scan
  ssllabsGrade: string;
  ssllabsStatus: string;          // 'PENDING' | 'READY' | 'ERROR' | 'TIMEOUT' | 'DISABLED'
  ssllabsIpAddress: string;
  ssllabsHasWarnings: boolean;
  ssllabsForwardSecrecy: boolean;
  ssllabsDrown: boolean;
  // Censys Platform API
  censysGrade: string;
  censysStatus: string;           // 'PENDING' | 'READY' | 'ERROR' | 'DISABLED'
  censysIpAddress: string;
  censysDaysLeft: number;
  censysExpired: boolean;
  censysCertValid: boolean;
  censysIssuer: string;
  censysKeySize: string;
  censysValidationLevel: string;  // 'DV' | 'OV' | 'EV'
  censysCtPresent: boolean;
  censysSansCount: number;
  censysOpenPorts: string;
  // SSLyze (local parse of sslyze.json from Kali scan)
  sslyzeGrade: string;
  sslyzeStatus: string;           // 'PENDING' | 'READY' | 'ERROR'
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
  // Combined (weighted fusion of all sources)
  combinedGrade: string;
  sourcesReady: number;
  sourcesTotal: number;
}

export const startSslScan = (domain: string) =>
  API.post<ScanResponse>('/ssl/scan', { domain });

export const getSslResult = (scanId: number) =>
  API.get<SslResultDto>(`/ssl/scan/${scanId}/result`);

// ── AI Summary ────────────────────────────────────────────────────────────────

export const getAiSummary = (scanId: number) =>
  API.get<{ summary: string }>(`/scans/${scanId}/ai-summary`);

export const getSslAiAnalysis = (context: Record<string, unknown>) =>
  API.post<{ summary: string; keyRisks: string[]; recommendations: string[] }>('/ssl/ai-analysis', context);
