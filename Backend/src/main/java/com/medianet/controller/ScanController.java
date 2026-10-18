package com.medianet.controller;

import com.medianet.dto.*;
import com.medianet.entity.User;
import com.medianet.entity.ScanResult;
import com.medianet.repository.ScanResultRepo;
import com.medianet.service.UserService;
import com.medianet.service.CisaKevService;
import com.medianet.service.EpssService;
import com.medianet.service.ExploitDbService;
import com.medianet.service.GeminiSummaryService;
import com.medianet.service.NvdEnrichmentService;
import com.medianet.service.ScanService;
import com.medianet.service.ScanWorkerPool;
import com.medianet.service.ComplianceService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api")
public class ScanController {

    private final ScanService scanService;
    private final NvdEnrichmentService nvdEnrichmentService;
    private final ExploitDbService exploitDbService;
    private final CisaKevService cisaKevService;
    private final EpssService epssService;
    private final UserService userService;
    private final GeminiSummaryService geminiSummaryService;
    private final ScanResultRepo scanResultRepo;
    private final ComplianceService complianceService;
    private final ScanWorkerPool scanWorkerPool;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ScanController(ScanService scanService, NvdEnrichmentService nvdEnrichmentService,
            ExploitDbService exploitDbService, CisaKevService cisaKevService, EpssService epssService,
            UserService userService, GeminiSummaryService geminiSummaryService, ScanResultRepo scanResultRepo,
            ComplianceService complianceService, ScanWorkerPool scanWorkerPool) {
        this.scanService = scanService;
        this.nvdEnrichmentService = nvdEnrichmentService;
        this.exploitDbService = exploitDbService;
        this.cisaKevService = cisaKevService;
        this.epssService = epssService;
        this.userService = userService;
        this.geminiSummaryService = geminiSummaryService;
        this.scanResultRepo = scanResultRepo;
        this.complianceService = complianceService;
        this.scanWorkerPool = scanWorkerPool;
    }

    // POST /api/scans → Start a scan
    @PostMapping("/scans")
    public ResponseEntity<ScanResponse> startScan(
            @Valid @RequestBody ScanRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        ScanResponse response = scanService.startScan(request, currentUser);
        return ResponseEntity.ok(response);
    }

    // GET /api/scans/{scanId}/logs → SSE log stream
    @GetMapping(value = "/scans/{scanId}/logs", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamLogs(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(value = "token", required = false) String token,
            jakarta.servlet.http.HttpServletResponse response) {
        String effectiveAuth = authHeader != null && !authHeader.isBlank()
                ? authHeader
                : (token != null && !token.isBlank() ? "Bearer " + token : null);
        User currentUser = userService.getRequiredUser(effectiveAuth);
        scanService.getAuthorizedScan(currentUser, scanId);
        response.setHeader("X-Accel-Buffering", "no");
        response.setHeader("Cache-Control", "no-cache");
        return scanService.createLogEmitter(scanId);
    }

    // POST /api/scans/{scanId}/stop → Stop a running scan
    @PostMapping("/scans/{scanId}/stop")
    public ResponseEntity<Void> stopScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        scanService.getAuthorizedScan(currentUser, scanId);
        scanService.stopScan(scanId);
        return ResponseEntity.ok().build();
    }

    // DELETE /api/scans/{scanId} → Delete a scan
    @DeleteMapping("/scans/{scanId}")
    public ResponseEntity<Void> deleteScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        scanService.getAuthorizedScan(currentUser, scanId);
        scanService.deleteScan(scanId);
        return ResponseEntity.ok().build();
    }

    // GET /api/scans/workers → Live status of each scan worker (idle / busy + which scan)
    @GetMapping("/scans/workers")
    public ResponseEntity<List<ScanWorkerPool.WorkerStatus>> getWorkers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanWorkerPool.currentStatuses());
    }

    // GET /api/scans → List all scans
    @GetMapping("/scans")
    public ResponseEntity<List<ScanResultDto>> getAllScans(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getAllScans(currentUser));
    }

    /** GET /api/scans/severity-summary?ids=1,2 — critical, high and KEV of those scans. */
    @GetMapping("/scans/severity-summary")
    public ResponseEntity<List<ScanSeveritySummaryDto>> severitySummary(
            @RequestParam(name = "ids", required = false) String ids,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.severitySummary(currentUser, parseScanIds(ids)));
    }

    private static List<Long> parseScanIds(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        List<Long> ids = new ArrayList<>();
        for (String part : raw.split(",")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            try {
                ids.add(Long.valueOf(trimmed));
            } catch (NumberFormatException ignored) {
                // Skip a token that is not a scan id.
            }
        }
        return ids;
    }

    // GET /api/scans/{scanId}/cves → CVEs for a specific scan
    @GetMapping("/scans/{scanId}/cves")
    public ResponseEntity<List<CveDto>> getCvesByScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getCvesByScan(currentUser, scanId));
    }

    // GET /api/scans/{scanId}/secrets → Secrets for a specific scan
    @GetMapping("/scans/{scanId}/secrets")
    public ResponseEntity<List<SecretDto>> getSecretsByScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getSecretsByScan(currentUser, scanId));
    }

    // POST /api/scans/{scanId}/secrets/triage → (re)run the ML triage on the stored secrets of a scan
    @PostMapping("/scans/{scanId}/secrets/triage")
    public ResponseEntity<List<SecretDto>> triageSecrets(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.triageSecrets(currentUser, scanId));
    }

    // PUT /api/secrets/{secretId}/verdict {verdict: REAL | FALSE_POSITIVE | null} → the analyst's decision
    @PutMapping("/secrets/{secretId}/verdict")
    public ResponseEntity<SecretDto> setSecretVerdict(@PathVariable Long secretId,
            @RequestBody java.util.Map<String, String> body,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.setAnalystVerdict(currentUser, secretId, body.get("verdict")));
    }

    // GET /api/scans/{scanId}/sast → SAST findings for a specific scan
    @GetMapping("/scans/{scanId}/sast")
    public ResponseEntity<List<com.medianet.dto.SastFindingDto>> getSastByScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getSastByScan(currentUser, scanId));
    }

    // GET /api/scans/{scanId}/ai-summary → Gemini AI executive summary
    @GetMapping("/scans/{scanId}/ai-summary")
    public ResponseEntity<java.util.Map<String, String>> getAiSummary(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        List<CveDto> cves = scanService.getCvesByScan(currentUser, scanId);
        String summary = geminiSummaryService.generateScanSummary(cves, currentUser);
        return ResponseEntity.ok(java.util.Map.of("summary", summary != null ? summary : ""));
    }

    @PostMapping("/repositories")
    public ResponseEntity<RepositoryDto> registerRepository(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody RegisterRepositoryRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.registerRepository(body != null ? body.repoUrl() : null, currentUser));
    }

    public record RegisterRepositoryRequest(String repoUrl) {
    }

    // GET /api/repositories → All scanned repos
    @GetMapping("/repositories")
    public ResponseEntity<List<RepositoryDto>> getAllRepositories(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getAllRepositories(currentUser));
    }

    // GET /api/repositories/{repoId}/scans → Scan history
    @GetMapping("/repositories/{repoId}/scans")
    public ResponseEntity<List<ScanResultDto>> getScansByRepo(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getScansByRepo(currentUser, repoId));
    }

    // GET /api/repositories/{repoId}/cves → CVEs from latest scan
    @GetMapping("/repositories/{repoId}/cves")
    public ResponseEntity<List<CveDto>> getCvesByRepo(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(scanService.getCvesByRepo(currentUser, repoId));
    }

    @org.springframework.beans.factory.annotation.Autowired
    private com.medianet.service.RepositoryHistoryService repositoryHistoryService;

    // GET /api/repositories/{repoId}/history → per finished scan: unique CVEs by severity, code alerts, secrets
    @GetMapping("/repositories/{repoId}/history")
    public ResponseEntity<List<java.util.Map<String, Object>>> getRepositoryHistory(@PathVariable Long repoId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        scanService.getScansByRepo(currentUser, repoId); // same access rule as the repository's scan list
        return ResponseEntity.ok(repositoryHistoryService.history(repoId));
    }

    // GET /api/scans/compare?fromScanId=X&toScanId=Y → Diff between two scans
    // (new / fixed / persisting CVEs and secrets)
    @GetMapping("/scans/compare")
    public ResponseEntity<java.util.Map<String, Object>> compareScans(
            @RequestParam Long fromScanId,
            @RequestParam Long toScanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        // Also enforces access control on both scans.
        scanService.getAuthorizedScan(currentUser, fromScanId);
        scanService.getAuthorizedScan(currentUser, toScanId);

        List<CveDto> fromCves = scanService.getCvesByScan(currentUser, fromScanId);
        List<CveDto> toCves = scanService.getCvesByScan(currentUser, toScanId);
        List<SecretDto> fromSecrets = scanService.getSecretsByScan(currentUser, fromScanId);
        List<SecretDto> toSecrets = scanService.getSecretsByScan(currentUser, toScanId);

        java.util.function.Function<CveDto, String> cveKey = c -> {
            String id = (c.getCanonicalId() != null && !c.getCanonicalId().isBlank())
                    ? c.getCanonicalId()
                    : c.getCveId();
            return id + "|" + c.getPackageName();
        };
        java.util.Map<String, CveDto> fromCveMap = fromCves.stream()
                .collect(java.util.stream.Collectors.toMap(cveKey, c -> c, (a, b) -> a));
        java.util.Map<String, CveDto> toCveMap = toCves.stream()
                .collect(java.util.stream.Collectors.toMap(cveKey, c -> c, (a, b) -> a));

        List<CveDto> newCves = toCveMap.entrySet().stream()
                .filter(e -> !fromCveMap.containsKey(e.getKey()))
                .map(java.util.Map.Entry::getValue).toList();
        List<CveDto> fixedCves = fromCveMap.entrySet().stream()
                .filter(e -> !toCveMap.containsKey(e.getKey()))
                .map(java.util.Map.Entry::getValue).toList();
        List<CveDto> persistingCves = toCveMap.entrySet().stream()
                .filter(e -> fromCveMap.containsKey(e.getKey()))
                .map(java.util.Map.Entry::getValue).toList();

        java.util.function.Function<SecretDto, String> secretKey = s ->
                s.getFile() + "|" + s.getStartLine() + "|" + s.getRuleId();
        java.util.Map<String, SecretDto> fromSecretMap = fromSecrets.stream()
                .collect(java.util.stream.Collectors.toMap(secretKey, s -> s, (a, b) -> a));
        java.util.Map<String, SecretDto> toSecretMap = toSecrets.stream()
                .collect(java.util.stream.Collectors.toMap(secretKey, s -> s, (a, b) -> a));

        List<SecretDto> newSecrets = toSecretMap.entrySet().stream()
                .filter(e -> !fromSecretMap.containsKey(e.getKey()))
                .map(java.util.Map.Entry::getValue).toList();
        List<SecretDto> fixedSecrets = fromSecretMap.entrySet().stream()
                .filter(e -> !toSecretMap.containsKey(e.getKey()))
                .map(java.util.Map.Entry::getValue).toList();

        java.util.Map<String, Object> result = new java.util.LinkedHashMap<>();
        result.put("fromScanId", fromScanId);
        result.put("toScanId", toScanId);
        result.put("newCves", newCves);
        result.put("fixedCves", fixedCves);
        result.put("persistingCves", persistingCves);
        result.put("newSecrets", newSecrets);
        result.put("fixedSecrets", fixedSecrets);
        return ResponseEntity.ok(result);
    }

    // POST /api/admin/enrich-missing-cves → Enrichir tous les CVEs manquants en
    // arrière-plan
    @PostMapping("/admin/enrich-missing-cves")
    public ResponseEntity<java.util.Map<String, String>> enrichMissingCves(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Global jobs over every project's CVEs: administrators only (was open to any logged-in user).
        userService.requireRole(authHeader, com.medianet.entity.UserRole.ADMIN);
        nvdEnrichmentService.enrichAllMissingCves();
        return ResponseEntity.ok(java.util.Map.of("message", "Enrichissement NVD démarré en arrière-plan"));
    }

    // POST /api/admin/enrich-exploits → Marquer les CVEs avec exploit public
    @PostMapping("/admin/enrich-exploits")
    public ResponseEntity<java.util.Map<String, String>> enrichExploits(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Global jobs over every project's CVEs: administrators only (was open to any logged-in user).
        userService.requireRole(authHeader, com.medianet.entity.UserRole.ADMIN);
        exploitDbService.enrichAllExistingCves();
        return ResponseEntity.ok(java.util.Map.of("message",
                "Enrichissement Exploit-DB démarré. Index contient " + exploitDbService.indexSize() + " CVEs."));
    }

    // POST /api/admin/enrich-kev → Marquer les CVEs du catalogue CISA KEV
    @PostMapping("/admin/enrich-kev")
    public ResponseEntity<java.util.Map<String, String>> enrichKev(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Global jobs over every project's CVEs: administrators only (was open to any logged-in user).
        userService.requireRole(authHeader, com.medianet.entity.UserRole.ADMIN);
        cisaKevService.enrichAllExistingCves();
        return ResponseEntity.ok(java.util.Map.of("message",
                "Enrichissement CISA KEV démarré. Catalogue contient " + cisaKevService.indexSize() + " CVEs."));
    }

    @GetMapping("/kev/status")
    public ResponseEntity<java.util.Map<String, Object>> kevStatus(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        int size = cisaKevService.indexSize();
        return ResponseEntity.ok(java.util.Map.of(
                "catalogSize", size,
                "loaded", size > 0));
    }

    // POST /api/admin/enrich-epss → Enrichir toutes les CVEs avec leur score EPSS
    @PostMapping("/admin/enrich-epss")
    public ResponseEntity<java.util.Map<String, String>> enrichEpss(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        // Global jobs over every project's CVEs: administrators only (was open to any logged-in user).
        userService.requireRole(authHeader, com.medianet.entity.UserRole.ADMIN);
        epssService.enrichAllExistingCves();
        return ResponseEntity.ok(java.util.Map.of("message",
                "Enrichissement EPSS démarré. Cache contient " + epssService.cacheSize() + " CVEs."));
    }

    // GET /api/scans/{scanId}/sbom → SBOM components for a scan
    @GetMapping("/scans/{scanId}/sbom")
    public ResponseEntity<List<java.util.Map<String, Object>>> getSbomByScan(@PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        ScanResult scan = scanService.getAuthorizedScan(currentUser, scanId);

        File sbomFile = Path.of(scan.getResultsDir(), "sbom.json").toFile();
        if (!sbomFile.exists())
            return ResponseEntity.ok(List.of());

        try {
            JsonNode root = objectMapper.readTree(sbomFile);
            JsonNode artifacts = root.path("artifacts");
            List<java.util.Map<String, Object>> result = new ArrayList<>();
            if (artifacts.isArray()) {
                for (JsonNode art : artifacts) {
                    java.util.Map<String, Object> comp = new java.util.LinkedHashMap<>();
                    comp.put("id", art.path("id").asText(""));
                    comp.put("name", art.path("name").asText(""));
                    comp.put("version", art.path("version").asText(""));
                    comp.put("type", art.path("type").asText(""));
                    comp.put("language", art.path("language").asText(""));
                    comp.put("purl", art.path("purl").asText(""));
                    // Extract first license value
                    JsonNode licenses = art.path("licenses");
                    String license = "";
                    if (licenses.isArray() && licenses.size() > 0) {
                        license = licenses.get(0).path("value").asText("");
                    }
                    comp.put("license", license);
                    // Extract location path
                    JsonNode locations = art.path("locations");
                    String location = "";
                    if (locations.isArray() && locations.size() > 0) {
                        location = locations.get(0).path("path").asText("");
                    }
                    comp.put("location", location);
                    result.add(comp);
                }
            }
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.ok(List.of());
        }
    }

    // ——————————————————————————————————————————————————
    // Idée 2 — OpenSCAP Compliance endpoints
    // ——————————————————————————————————————————————————

    /**
     * GET /api/scans/{scanId}/compliance
     * Returns the list of OpenSCAP rule results for a given scan.
     * Only available if the scan was launched with a complianceProfile.
     */
    @GetMapping("/scans/{scanId}/compliance")
    public ResponseEntity<java.util.Map<String, Object>> getComplianceResults(
            @PathVariable Long scanId,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        ScanResult scan = scanService.getAuthorizedScan(currentUser, scanId);

        File xmlFile = new File(scan.getResultsDir(), "openscap-results.xml");
        if (!xmlFile.exists()) {
            java.util.Map<String, Object> empty = new java.util.LinkedHashMap<>();
            empty.put("available", false);
            empty.put("findings", List.of());
            empty.put("summary", java.util.Map.of());
            return ResponseEntity.ok(empty);
        }

        // Read profile from scan metadata file if present, otherwise default label
        String profile = readProfileFromMetadata(scan.getResultsDir());
        List<ComplianceFindingDto> findings = complianceService.parseComplianceResults(scan.getResultsDir(), profile);
        java.util.Map<String, Object> summary = complianceService.buildSummary(findings);

        java.util.Map<String, Object> response = new java.util.LinkedHashMap<>();
        response.put("available", true);
        response.put("profile", profile);
        response.put("findings", findings);
        response.put("summary", summary);
        return ResponseEntity.ok(response);
    }

    /**
     * Reads the compliance_profile.txt written by the scanner into the results dir.
     */
    private String readProfileFromMetadata(String resultsDir) {
        // The results dir is writable by the scanned repo's code: refuse links and keep only a profile identifier.
        return com.medianet.util.ScanResultFiles.readText(resultsDir, "compliance_profile.txt", 256)
                .map(String::trim)
                .filter(p -> p.matches("[A-Za-z0-9_.:-]{1,200}"))
                .orElse("unknown");
    }
}
