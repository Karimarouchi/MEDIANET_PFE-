package com.medianet.service;

import com.medianet.dto.*;
import com.medianet.entity.*;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.repository.*;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;
import org.springframework.web.server.ResponseStatusException;

import java.io.*;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final RepositoryRepo repositoryRepo;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final SecretFindingRepo secretFindingRepo;
    private final ResultParserService parserService;
    private final NvdEnrichmentService nvdEnrichmentService;
    private final ExploitDbService exploitDbService;
    private final CisaKevService cisaKevService;
    private final EpssService epssService;
    private final UserService userService;

    @Value("${vulnix.results.base-dir}")
    private String baseDir;

    @Value("${vulnix.docker.image}")
    private String dockerImage;

    /** Persistent host directory for OWASP Dependency-Check NVD database cache. */
    @Value("${vulnix.dc.cache.dir:#{systemProperties['user.home']}/.vulnix-dc-cache}")
    private String dcCacheDir;

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<Long, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final Map<Long, List<String>> logBuffers = new ConcurrentHashMap<>();
    private final Map<Long, Process> runningProcesses = new ConcurrentHashMap<>();

    public ScanService(RepositoryRepo repositoryRepo, ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo, SecretFindingRepo secretFindingRepo,
            ResultParserService parserService, NvdEnrichmentService nvdEnrichmentService,
            ExploitDbService exploitDbService,
            CisaKevService cisaKevService,
            EpssService epssService,
            UserService userService) {
        this.repositoryRepo = repositoryRepo;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.secretFindingRepo = secretFindingRepo;
        this.parserService = parserService;
        this.nvdEnrichmentService = nvdEnrichmentService;
        this.exploitDbService = exploitDbService;
        this.cisaKevService = cisaKevService;
        this.epssService = epssService;
        this.userService = userService;
    }

    /**
     * Start a scan: create repo + scanResult, launch Docker, return IDs
     * immediately.
     */
    public ScanResponse startScan(ScanRequest request, User currentUser) {
        // Determine a stable identifier for repo lookup
        String scanMode = request.getScanMode() != null ? request.getScanMode() : "auto";
        boolean isDockerImage = "docker-image".equals(scanMode);
        String ownerLogin = currentUser != null ? currentUser.getLogin() : null;
        AuthProvider gitProvider = detectProvider(isDockerImage ? request.getDockerImage() : request.getRepoUrl(),
                scanMode, currentUser);

        String repoIdentifier = isDockerImage
                ? "docker://" + (request.getDockerImage() != null ? request.getDockerImage() : "unknown")
                : (request.getRepoUrl() != null ? request.getRepoUrl() : "");

        // Find or create repository scoped to this user
        Repository repo = (ownerLogin != null
                ? repositoryRepo.findByRepoUrlAndOwnerLogin(repoIdentifier, ownerLogin)
                : repositoryRepo.findByRepoUrl(repoIdentifier))
                .orElseGet(() -> {
                    Repository r = Repository.builder()
                            .repoUrl(repoIdentifier)
                            .branch(request.getBranch())
                            .scanMode(scanMode)
                            .targetDomain(request.getTargetDomain())
                            .ownerLogin(ownerLogin)
                            .ownerUser(currentUser)
                            .gitProvider(gitProvider)
                            .build();
                    return repositoryRepo.save(r);
                });

        // Update repo fields
        repo.setBranch(request.getBranch() != null ? request.getBranch() : repo.getBranch());
        repo.setScanMode(scanMode);
        repo.setTargetDomain(request.getTargetDomain() != null ? request.getTargetDomain() : repo.getTargetDomain());
        repo.setOwnerUser(currentUser != null ? currentUser : repo.getOwnerUser());
        repo.setOwnerLogin(ownerLogin != null ? ownerLogin : repo.getOwnerLogin());
        repo.setGitProvider(gitProvider);
        repo.setLastScannedAt(LocalDateTime.now());
        repositoryRepo.save(repo);

        // Create results directory
        String scanUuid = UUID.randomUUID().toString();
        String resultsDir = Path.of(baseDir, scanUuid).toString();
        try {
            Files.createDirectories(Path.of(resultsDir));
        } catch (IOException e) {
            throw new RuntimeException("Failed to create results directory: " + resultsDir, e);
        }

        // Create ScanResult
        ScanResult scan = ScanResult.builder()
                .status(ScanStatus.RUNNING)
                .startedAt(LocalDateTime.now())
                .resultsDir(resultsDir)
                .repository(repo)
                .build();
        scan = scanResultRepo.save(scan);

        // Launch Docker in background
        final Long scanId = scan.getId();
        final Long repoId = repo.getId();
        final String targetDomain = request.getTargetDomain() != null ? request.getTargetDomain() : "";
        final String branch = request.getBranch() != null && !request.getBranch().isBlank() ? request.getBranch() : "";

        if ("docker-image".equals(scanMode)) {
            // Docker image mode: start target container on host, then scan it
            final String dockerImageToScan = request.getDockerImage() != null ? request.getDockerImage() : "";
            final int containerPort = request.getContainerPort() != null ? request.getContainerPort() : 80;
            executor.submit(() -> runDockerImageScan(scanId, dockerImageToScan, containerPort, resultsDir));
        } else {
            final String repoUrl = request.getRepoUrl() != null ? request.getRepoUrl() : "";
            final String cloneRepoUrl = resolveCloneRepoUrl(repoUrl, gitProvider, currentUser);
            final String dastTargetUrl = request.getDastTargetUrl() != null ? request.getDastTargetUrl() : "";
            final String targetOs = request.getTargetOs() != null ? request.getTargetOs() : "";
            final String complianceProfile = request.getComplianceProfile() != null ? request.getComplianceProfile()
                    : "";
            executor.submit(
                    () -> runDockerScan(scanId, repoUrl, cloneRepoUrl, scanMode, targetDomain, dastTargetUrl, branch,
                            targetOs, complianceProfile, resultsDir));
        }

        return ScanResponse.builder()
                .scanId(scanId)
                .repoId(repoId)
                .build();
    }

    /**
     * Run docker scan, stream logs, parse results when done.
     */
    private void runDockerScan(Long scanId, String repoUrl, String cloneRepoUrl, String scanMode,
            String targetDomain, String dastTargetUrl, String branch,
            String targetOs, String complianceProfile, String resultsDir) {
        try {
            // Convert Windows path to Docker-compatible mount
            String dockerMount = resultsDir.replace("\\", "/");

            // For ssl-only/dast modes, REPO_URL is a synthetic key (ssl://, dast://)
            // and should NOT be passed to Docker (it would attempt a git clone and fail).
            String dockerRepoUrl = ("ssl-only".equals(scanMode) || "dast".equals(scanMode)) ? "" : repoUrl;
            String dockerCloneUrl = ("ssl-only".equals(scanMode) || "dast".equals(scanMode)) ? "" : cloneRepoUrl;

            List<String> cmd = new ArrayList<>(List.of(
                    "docker", "run", "--rm",
                    "-e", "REPO_URL=" + dockerRepoUrl,
                    "-e", "REPO_CLONE_URL=" + dockerCloneUrl,
                    "-e", "SCAN_MODE=" + scanMode));

            if (branch != null && !branch.isBlank()) {
                cmd.addAll(List.of("-e", "BRANCH=" + branch));
            }

            if (targetDomain != null && !targetDomain.isBlank()) {
                cmd.addAll(List.of("-e", "TARGET_DOMAIN=" + targetDomain));
            }

            if (dastTargetUrl != null && !dastTargetUrl.isBlank()) {
                cmd.addAll(List.of("-e", "DAST_TARGET_URL=" + dastTargetUrl));
            }

            // Idée 3 — OS cible : pass to Grype as --distro
            if (targetOs != null && !targetOs.isBlank()) {
                cmd.addAll(List.of("-e", "TARGET_OS=" + targetOs));
            }

            // Idée 2 — OpenSCAP compliance profile
            if (complianceProfile != null && !complianceProfile.isBlank()) {
                cmd.addAll(List.of("-e", "COMPLIANCE_PROFILE=" + complianceProfile));
            }

            // Mount DC cache dir (host → container) so NVD DB persists across scans
            String dcCacheMount = dcCacheDir.replace("\\", "/");
            // Ensure the host directory exists
            new java.io.File(dcCacheDir).mkdirs();

            cmd.addAll(List.of(
                    "-v", dcCacheMount + ":/root/.dependency-check",
                    "-v", dockerMount + ":/workspace/results",
                    dockerImage));

            log.info("Running docker scan {} with repoUrl={} cloneUrl={} scanMode={}",
                    scanId,
                    dockerRepoUrl,
                    dockerCloneUrl.equals(dockerRepoUrl) ? dockerCloneUrl : "[secure]",
                    scanMode);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            runningProcesses.put(scanId, process);

            // Stream logs
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sendLog(scanId, line);
                }
            }

            int exitCode = process.waitFor();
            runningProcesses.remove(scanId);
            log.info("Docker process exited with code: {}", exitCode);

            // Parse results
            ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
            if (scan == null)
                return;

            if (exitCode == 0) {
                // Parse result.json for metadata
                JsonNode resultJson = parserService.parseResultJson(resultsDir);
                if (resultJson != null) {
                    JsonNode eco = resultJson.get("ecosystemsDetected");
                    if (eco != null)
                        scan.setEcosystemsDetected(eco.toString());
                    JsonNode tools = resultJson.get("toolsExecuted");
                    if (tools != null)
                        scan.setToolsExecuted(tools.toString());
                }

                // Parse CVEs
                List<CveEntry> cves = parserService.parseCves(resultsDir);

                // Enrich CVEs with NVD data (descriptions, CVSS, severity)
                sendLog(scanId, "[NVD] Starting CVE enrichment via NVD API...");
                nvdEnrichmentService.enrich(cves, msg -> sendLog(scanId, msg));

                // Enrich CVEs with Exploit-DB data (public exploits)
                int exploitCount = 0;
                for (CveEntry cve : cves) {
                    if (exploitDbService.hasExploit(cve.getCveId())) {
                        cve.setExploitAvailable(true);
                        cve.setExploitUrl(exploitDbService.getFirstExploitUrl(cve.getCveId()));
                        exploitCount++;
                    }
                    cve.setScanResult(scan);
                }
                if (exploitCount > 0) {
                    sendLog(scanId, "[EXPLOITDB] " + exploitCount + " CVE(s) avec exploit public détecté(s).");
                }

                // Enrich CVEs with CISA KEV data (actively exploited in the wild)
                int kevCount = 0;
                for (CveEntry cve : cves) {
                    if (cisaKevService.isKev(cve.getCveId())) {
                        CisaKevService.KevEntry kev = cisaKevService.getKevEntry(cve.getCveId());
                        cve.setKevListed(true);
                        cve.setKevDateAdded(kev != null ? kev.dateAdded() : null);
                        cve.setKevRansomware(kev != null && kev.ransomware());
                        kevCount++;
                    }
                }
                if (kevCount > 0) {
                    sendLog(scanId, "[KEV] " + kevCount + " CVE(s) répertoriées dans le catalogue CISA KEV.");
                }

                // Enrich CVEs with EPSS scores (exploitation probability)
                epssService.enrichCves(cves);
                long epssCount = cves.stream().filter(c -> c.getEpssScore() != null).count();
                if (epssCount > 0) {
                    sendLog(scanId, "[EPSS] " + epssCount + " CVE(s) enrichies avec un score EPSS.");
                }
                cveEntryRepo.saveAll(cves);

                // Parse secrets
                List<SecretFinding> secrets = parserService.parseSecrets(resultsDir);
                for (SecretFinding secret : secrets) {
                    secret.setScanResult(scan);
                }
                secretFindingRepo.saveAll(secrets);

                scan.setStatus(ScanStatus.COMPLETED);
                sendLog(scanId,
                        "[SYSTEM] Scan completed. " + cves.size() + " CVEs, " + secrets.size() + " secrets found.");
            } else {
                scan.setStatus(ScanStatus.FAILED);
                sendLog(scanId, "[ERROR] Scan failed with exit code: " + exitCode);
            }

            scan.setFinishedAt(LocalDateTime.now());
            scanResultRepo.save(scan);
            sendLog(scanId, "%%SCAN_COMPLETE%%");

        } catch (Exception e) {
            log.error("Docker scan failed", e);
            ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
            if (scan != null) {
                scan.setStatus(ScanStatus.FAILED);
                scan.setFinishedAt(LocalDateTime.now());
                scanResultRepo.save(scan);
            }
            sendLog(scanId, "[ERROR] " + e.getMessage());
            sendLog(scanId, "%%SCAN_COMPLETE%%");
        }
    }

    private String resolveCloneRepoUrl(String repoUrl, AuthProvider gitProvider, User currentUser) {
        if (repoUrl == null || repoUrl.isBlank() || currentUser == null || gitProvider != AuthProvider.GITLAB) {
            return repoUrl;
        }

        String accessToken = userService.getAccessToken(currentUser, AuthProvider.GITLAB);
        if (accessToken == null || accessToken.isBlank()) {
            return repoUrl;
        }

        if (repoUrl.startsWith("https://")) {
            return repoUrl.replaceFirst("^https://",
                    "https://oauth2:" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8) + "@");
        }

        if (repoUrl.startsWith("http://")) {
            return repoUrl.replaceFirst("^http://",
                    "http://oauth2:" + URLEncoder.encode(accessToken, StandardCharsets.UTF_8) + "@");
        }

        return repoUrl;
    }

    /**
     * Docker image scan mode:
     * 1. docker pull imageRef
     * 2. docker run -d -p hostPort:containerPort imageRef → get containerId
     * 3. Wait for the app to respond
     * 4. Run scanner with SCAN_MODE=docker-image, DOCKER_IMAGE=imageRef,
     * DAST_TARGET_URL=http://host.docker.internal:hostPort
     * 5. docker stop + rm the target container
     */
    private void runDockerImageScan(Long scanId, String imageRef, int containerPort, String resultsDir) {
        String targetContainerId = null;
        int hostPort = 0;
        try {
            // --- Step 1: docker pull ---
            sendLog(scanId, "[SCAN] Pulling Docker image: " + imageRef);
            runAndLog(scanId, List.of("docker", "pull", imageRef));

            // --- Step 2: find a free host port ---
            try (java.net.ServerSocket s = new java.net.ServerSocket(0)) {
                hostPort = s.getLocalPort();
            }
            sendLog(scanId,
                    "[INFO] Starting target container on host port " + hostPort + " → container port " + containerPort);

            String containerName = "vulnix-target-" + scanId;
            Process startProc = new ProcessBuilder(
                    "docker", "run", "-d", "--rm",
                    "--name", containerName,
                    "-p", hostPort + ":" + containerPort,
                    imageRef)
                    .redirectErrorStream(true).start();
            targetContainerId = new String(startProc.getInputStream().readAllBytes()).trim();
            startProc.waitFor();
            sendLog(scanId, "[INFO] Container started: "
                    + targetContainerId.substring(0, Math.min(12, targetContainerId.length())));

            // --- Step 3: wait for app to respond (max 60s) ---
            String appUrl = "http://host.docker.internal:" + hostPort;
            sendLog(scanId, "[INFO] Waiting for app at " + appUrl + " ...");
            boolean ready = waitForApp("localhost", hostPort, 60);
            if (!ready) {
                sendLog(scanId,
                        "[WARN] App did not respond in 60s — proceeding with image CVE scan only (ZAP may fail)");
            } else {
                sendLog(scanId, "[SUCCESS] App is ready at " + appUrl);
            }

            // --- Step 4: run scanner ---
            String dockerMount = resultsDir.replace("\\", "/");
            List<String> cmd = new ArrayList<>(List.of(
                    "docker", "run", "--rm",
                    "-e", "SCAN_MODE=docker-image",
                    "-e", "DOCKER_IMAGE=" + imageRef,
                    "-e", "DAST_TARGET_URL=" + appUrl,
                    "-e", "REPO_URL=",
                    "-v", dockerMount + ":/workspace/results",
                    "--add-host=host.docker.internal:host-gateway",
                    dockerImage));

            log.info("Running docker command: {}", String.join(" ", cmd));
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            runningProcesses.put(scanId, process);

            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    sendLog(scanId, line);
                }
            }
            int exitCode = process.waitFor();
            runningProcesses.remove(scanId);

            // --- Step 5: parse results same as normal scan ---
            ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
            if (scan == null)
                return;

            if (exitCode == 0) {
                JsonNode resultJson = parserService.parseResultJson(resultsDir);
                if (resultJson != null) {
                    JsonNode eco = resultJson.get("ecosystemsDetected");
                    if (eco != null)
                        scan.setEcosystemsDetected(eco.toString());
                    JsonNode tools = resultJson.get("toolsExecuted");
                    if (tools != null)
                        scan.setToolsExecuted(tools.toString());
                }
                List<CveEntry> cves = parserService.parseCves(resultsDir);
                sendLog(scanId, "[NVD] Starting CVE enrichment...");
                nvdEnrichmentService.enrich(cves, msg -> sendLog(scanId, msg));
                for (CveEntry cve : cves) {
                    if (exploitDbService.hasExploit(cve.getCveId())) {
                        cve.setExploitAvailable(true);
                        cve.setExploitUrl(exploitDbService.getFirstExploitUrl(cve.getCveId()));
                    }
                    if (cisaKevService.isKev(cve.getCveId())) {
                        cve.setKevListed(true);
                        CisaKevService.KevEntry kev = cisaKevService.getKevEntry(cve.getCveId());
                        if (kev != null) {
                            cve.setKevDateAdded(kev.dateAdded());
                            cve.setKevRansomware(kev.ransomware());
                        }
                    }
                    cve.setScanResult(scan);
                }
                if (!cves.isEmpty())
                    cveEntryRepo.saveAll(cves);
                List<com.medianet.entity.SecretFinding> secrets = parserService.parseSecrets(resultsDir);
                for (com.medianet.entity.SecretFinding s : secrets)
                    s.setScanResult(scan);
                if (!secrets.isEmpty())
                    secretFindingRepo.saveAll(secrets);
                scan.setStatus(ScanStatus.COMPLETED);
            } else {
                scan.setStatus(ScanStatus.FAILED);
            }
            scan.setFinishedAt(LocalDateTime.now());
            scanResultRepo.save(scan);
            sendLog(scanId, "%%SCAN_COMPLETE%%");

        } catch (Exception e) {
            log.error("Docker image scan failed", e);
            ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
            if (scan != null) {
                scan.setStatus(ScanStatus.FAILED);
                scan.setFinishedAt(LocalDateTime.now());
                scanResultRepo.save(scan);
            }
            sendLog(scanId, "[ERROR] " + e.getMessage());
            sendLog(scanId, "%%SCAN_COMPLETE%%");
        } finally {
            // Always stop and remove the target container
            if (targetContainerId != null && !targetContainerId.isEmpty()) {
                try {
                    sendLog(scanId, "[INFO] Stopping target container...");
                    new ProcessBuilder("docker", "stop", targetContainerId)
                            .redirectErrorStream(true).start().waitFor();
                } catch (Exception ignored) {
                }
            }
        }
    }

    /**
     * Wait until a TCP port is open on localhost, max waitSeconds. Returns true if
     * ready.
     */
    private boolean waitForApp(String host, int port, int waitSeconds) {
        long deadline = System.currentTimeMillis() + waitSeconds * 1000L;
        while (System.currentTimeMillis() < deadline) {
            try (java.net.Socket s = new java.net.Socket()) {
                s.connect(new java.net.InetSocketAddress(host, port), 1000);
                return true;
            } catch (Exception ignored) {
            }
            try {
                Thread.sleep(2000);
            } catch (InterruptedException ignored) {
                break;
            }
        }
        return false;
    }

    /** Run a command, stream its output to the scan log. */
    private void runAndLog(Long scanId, List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
            String line;
            while ((line = r.readLine()) != null)
                sendLog(scanId, line);
        }
        p.waitFor();
    }

    /**
     * Register SSE emitter for log streaming. Replays buffered logs first.
     */
    public SseEmitter createLogEmitter(Long scanId) {
        SseEmitter emitter = new SseEmitter(600_000L); // 10 min timeout

        // Add to list of emitters for this scan
        emitters.computeIfAbsent(scanId, k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> {
            List<SseEmitter> list = emitters.get(scanId);
            if (list != null)
                list.remove(emitter);
        });
        emitter.onTimeout(() -> {
            List<SseEmitter> list = emitters.get(scanId);
            if (list != null)
                list.remove(emitter);
        });
        emitter.onError(e -> {
            List<SseEmitter> list = emitters.get(scanId);
            if (list != null)
                list.remove(emitter);
        });

        // Send initial heartbeat so client knows connection is alive
        try {
            emitter.send(SseEmitter.event().data("[SYSTEM] Connected to scan #" + scanId + " log stream"));
        } catch (Exception e) {
            log.warn("Failed to send initial SSE heartbeat for scan {}", scanId);
        }

        // Replay buffered logs
        List<String> buffer = logBuffers.get(scanId);
        if (buffer != null) {
            try {
                for (String msg : buffer) {
                    emitter.send(SseEmitter.event().data(msg));
                }
                // If scan already finished, complete the emitter
                if (buffer.contains("%%SCAN_COMPLETE%%")) {
                    emitter.complete();
                    List<SseEmitter> list = emitters.get(scanId);
                    if (list != null)
                        list.remove(emitter);
                }
            } catch (Exception e) {
                List<SseEmitter> list = emitters.get(scanId);
                if (list != null)
                    list.remove(emitter);
            }
        }

        return emitter;
    }

    private void sendLog(Long scanId, String message) {
        // Always buffer the message
        logBuffers.computeIfAbsent(scanId, k -> new java.util.concurrent.CopyOnWriteArrayList<>()).add(message);

        // Send to all connected emitters
        List<SseEmitter> list = emitters.get(scanId);
        if (list != null) {
            for (SseEmitter emitter : list) {
                try {
                    emitter.send(SseEmitter.event().data(message));
                    if ("%%SCAN_COMPLETE%%".equals(message)) {
                        emitter.complete();
                    }
                } catch (Exception e) {
                    list.remove(emitter);
                }
            }
            if ("%%SCAN_COMPLETE%%".equals(message)) {
                emitters.remove(scanId);
            }
        }
    }

    // ==================== STOP & DELETE ====================

    public void stopScan(Long scanId) {
        Process process = runningProcesses.get(scanId);
        if (process != null && process.isAlive()) {
            process.destroyForcibly();
            runningProcesses.remove(scanId);
        }
        ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
        if (scan != null && scan.getStatus() == ScanStatus.RUNNING) {
            scan.setStatus(ScanStatus.FAILED);
            scan.setFinishedAt(LocalDateTime.now());
            scanResultRepo.save(scan);
            sendLog(scanId, "[SYSTEM] Scan stopped by user.");
            sendLog(scanId, "%%SCAN_COMPLETE%%");
        }
        logBuffers.remove(scanId);
    }

    @jakarta.transaction.Transactional
    public void deleteScan(Long scanId) {
        // Stop if running
        Process process = runningProcesses.get(scanId);
        if (process != null && process.isAlive()) {
            process.destroyForcibly();
            runningProcesses.remove(scanId);
        }
        emitters.remove(scanId);
        logBuffers.remove(scanId);

        ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
        if (scan == null)
            return;

        // Delete results directory
        String resultsDir = scan.getResultsDir();
        if (resultsDir != null) {
            try {
                Path dir = Path.of(resultsDir);
                if (Files.exists(dir)) {
                    Files.walk(dir).sorted(java.util.Comparator.reverseOrder())
                            .map(Path::toFile).forEach(java.io.File::delete);
                }
            } catch (IOException e) {
                log.warn("Failed to delete results dir: {}", resultsDir, e);
            }
        }

        // Delete DB records (CVEs, secrets, then scan)
        cveEntryRepo.deleteAll(cveEntryRepo.findByScanResultId(scanId));
        secretFindingRepo.deleteAll(secretFindingRepo.findByScanResultId(scanId));
        scanResultRepo.delete(scan);
    }

    // ==================== QUERY METHODS ====================

    public List<RepositoryDto> getAllRepositories(User currentUser) {
        return findVisibleRepositories(currentUser).stream().map(this::toRepoDto).toList();
    }

    public List<ScanResultDto> getAllScans(User currentUser) {
        if (currentUser == null) {
            return List.of();
        }
        if (currentUser.getRole() == UserRole.ADMIN) {
            return scanResultRepo.findAllByOrderByStartedAtDesc()
                    .stream().map(this::toScanDto).toList();
        }
        List<Long> repoIds = findVisibleRepositories(currentUser).stream().map(Repository::getId).toList();
        if (repoIds.isEmpty()) {
            return List.of();
        }
        return scanResultRepo.findByRepositoryIdInOrderByStartedAtDesc(repoIds)
                .stream().map(this::toScanDto).toList();
    }

    public List<ScanResultDto> getScansByRepo(User currentUser, Long repoId) {
        ensureRepositoryAccess(currentUser, repoId);
        return scanResultRepo.findByRepositoryIdOrderByStartedAtDesc(repoId)
                .stream().map(this::toScanDto).toList();
    }

    public List<CveDto> getCvesByScan(User currentUser, Long scanId) {
        ensureScanAccess(currentUser, scanId);
        return cveEntryRepo.findByScanResultId(scanId)
                .stream().map(this::toCveDto).toList();
    }

    public List<CveDto> getCvesByRepo(User currentUser, Long repoId) {
        ensureRepositoryAccess(currentUser, repoId);
        ScanResult latest = scanResultRepo.findFirstByRepositoryIdOrderByStartedAtDesc(repoId);
        if (latest == null)
            return Collections.emptyList();
        return cveEntryRepo.findByScanResultId(latest.getId())
                .stream().map(this::toCveDto).toList();
    }

    public List<SecretDto> getSecretsByScan(User currentUser, Long scanId) {
        ensureScanAccess(currentUser, scanId);
        return secretFindingRepo.findByScanResultId(scanId)
                .stream().map(this::toSecretDto).toList();
    }

    public List<com.medianet.dto.SastFindingDto> getSastByScan(User currentUser, Long scanId) {
        ensureScanAccess(currentUser, scanId);
        ScanResult scan = scanResultRepo.findById(scanId).orElse(null);
        if (scan == null)
            return Collections.emptyList();
        return parserService.parseSastDirect(scan.getResultsDir());
    }

    public ScanResult getAuthorizedScan(User currentUser, Long scanId) {
        ScanResult scan = scanResultRepo.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        if (repoId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found for scan");
        }
        ensureRepositoryAccess(currentUser, repoId);
        return scan;
    }

    // ==================== MAPPERS ====================

    private RepositoryDto toRepoDto(Repository r) {
        return RepositoryDto.builder()
                .id(r.getId())
                .repoUrl(r.getRepoUrl())
                .gitProvider(r.getGitProvider() != null ? r.getGitProvider().name() : null)
                .branch(r.getBranch())
                .scanMode(r.getScanMode())
                .targetDomain(r.getTargetDomain())
                .clientIds(extractClientIds(r))
                .clientNames(extractClientNames(r))
                .createdAt(r.getCreatedAt())
                .lastScannedAt(r.getLastScannedAt())
                .build();
    }

    private ScanResultDto toScanDto(ScanResult s) {
        Repository repo = s.getRepository();
        return ScanResultDto.builder()
                .id(s.getId())
                .repoId(repo != null ? repo.getId() : null)
                .repoUrl(repo != null ? repo.getRepoUrl() : null)
                .gitProvider(repo != null && repo.getGitProvider() != null ? repo.getGitProvider().name() : null)
                .branch(repo != null ? repo.getBranch() : null)
                .scanMode(repo != null ? repo.getScanMode() : null)
                .targetDomain(repo != null ? repo.getTargetDomain() : null)
                .clientIds(repo != null ? extractClientIds(repo) : List.of())
                .clientNames(repo != null ? extractClientNames(repo) : List.of())
                .status(s.getStatus().name())
                .startedAt(s.getStartedAt())
                .finishedAt(s.getFinishedAt())
                .ecosystemsDetected(s.getEcosystemsDetected())
                .toolsExecuted(s.getToolsExecuted())
                .cveCount(s.getCveEntries() != null ? s.getCveEntries().size() : 0)
                .secretCount(s.getSecretFindings() != null ? s.getSecretFindings().size() : 0)
                .build();
    }

    private List<Long> extractClientIds(Repository repository) {
        if (repository.getClientLinks() == null || repository.getClientLinks().isEmpty()) {
            return List.of();
        }
        return repository.getClientLinks().stream()
                .map(ClientRepository::getClient)
                .filter(Objects::nonNull)
                .map(Client::getId)
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .toList();
    }

    private List<String> extractClientNames(Repository repository) {
        if (repository.getClientLinks() == null || repository.getClientLinks().isEmpty()) {
            return List.of();
        }
        return repository.getClientLinks().stream()
                .map(ClientRepository::getClient)
                .filter(Objects::nonNull)
                .map(Client::getName)
                .filter(Objects::nonNull)
                .distinct()
                .sorted()
                .toList();
    }

    private CveDto toCveDto(CveEntry c) {
        return CveDto.builder()
                .id(c.getId())
                .cveId(c.getCveId())
                .packageName(c.getPackageName())
                .packageVersion(c.getPackageVersion())
                .severity(c.getSeverity())
                .cvssScore(c.getCvssScore())
                .fixedVersion(c.getFixedVersion())
                .description(c.getDescription())
                .dataSource(c.getDataSource())
                .source(c.getSource())
                .filePath(c.getFilePath())
                .lineNumber(c.getLineNumber())
                .exploitAvailable(c.isExploitAvailable())
                .exploitUrl(c.getExploitUrl())
                .kevListed(c.isKevListed())
                .kevDateAdded(c.getKevDateAdded())
                .kevRansomware(c.isKevRansomware())
                .epssScore(c.getEpssScore())
                .epssPercentile(c.getEpssPercentile())
                .confirmedBy(c.getConfirmedBy())
                .sources(c.getSources())
                .build();
    }

    private SecretDto toSecretDto(SecretFinding s) {
        String match = s.getMatch();
        String maskedMatch = null;
        if (match != null && match.length() > 8) {
            maskedMatch = match.substring(0, 4) + "..." + match.substring(match.length() - 4);
        } else if (match != null && !match.isEmpty()) {
            maskedMatch = "****";
        }
        return SecretDto.builder()
                .id(s.getId())
                .ruleId(s.getRuleId())
                .description(s.getDescription())
                .file(s.getFile())
                .startLine(s.getStartLine())
                .endLine(s.getEndLine())
                .author(s.getAuthor())
                .date(s.getDate())
                .commit(s.getCommit())
                .maskedMatch(maskedMatch)
                .build();
    }

    private AuthProvider detectProvider(String target, String scanMode, User currentUser) {
        if ("ssl-only".equals(scanMode) || "dast".equals(scanMode) || "docker-image".equals(scanMode)) {
            return currentUser != null && currentUser.getPrimaryProvider() != null
                    ? currentUser.getPrimaryProvider()
                    : AuthProvider.GITHUB;
        }
        if (target != null && target.contains("gitlab.com")) {
            return AuthProvider.GITLAB;
        }
        return AuthProvider.GITHUB;
    }

    private List<Repository> findVisibleRepositories(User currentUser) {
        if (currentUser == null) {
            return List.of();
        }
        return switch (currentUser.getRole()) {
            case ADMIN -> repositoryRepo.findAll().stream()
                    .sorted(java.util.Comparator.comparing(Repository::getCreatedAt).reversed())
                    .toList();
            case EMPLOYEE -> repositoryRepo.findVisibleToEmployee(currentUser.getId());
        };
    }

    private void ensureRepositoryAccess(User currentUser, Long repoId) {
        if (currentUser == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication required");
        }
        boolean allowed = switch (currentUser.getRole()) {
            case ADMIN -> repositoryRepo.existsById(repoId);
            case EMPLOYEE -> repositoryRepo.canEmployeeAccess(repoId, currentUser.getId());
        };
        if (!allowed) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Repository not accessible");
        }
    }

    private void ensureScanAccess(User currentUser, Long scanId) {
        ScanResult scan = scanResultRepo.findById(scanId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        Long repoId = scan.getRepository() != null ? scan.getRepository().getId() : null;
        if (repoId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Repository not found for scan");
        }
        ensureRepositoryAccess(currentUser, repoId);
    }
}
