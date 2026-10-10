package com.medianet.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.ScanResult;
import com.medianet.entity.SupplyChainScore;
import com.medianet.repository.SupplyChainScoreRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

/**
 * Supply-chain screening of the npm dependencies listed in a scan's SBOM.
 *
 * <p>
 * Each package is downloaded by the Python sidecar {@code ml/supplychain/score.py} (in memory, never
 * installed or executed) and scored by the trained detector. The result is an INDICATOR for human review
 * (tiers REVIEW / HIGH_CONFIDENCE), plus a deterministic KNOWN_MALICIOUS tier from OSSF reports. It never
 * blocks a release: the CI gate stays in {@code CiScanService}.
 */
@Service
public class SupplyChainService {

    private static final Logger log = LoggerFactory.getLogger(SupplyChainService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static final String ECOSYSTEM_NPM = "npm";
    static final String ECOSYSTEM_PYPI = "pypi";
    static final List<String> MODEL_ECOSYSTEMS = List.of(ECOSYSTEM_NPM, ECOSYSTEM_PYPI);
    static final int BATCH_SIZE = 40;
    static final Set<String> CACHEABLE_STATUSES = Set.of("SCORED", "NOT_FOUND", "TOO_LARGE", "NO_SDIST",
            "UNSUPPORTED_ECOSYSTEM");
    static final Set<String> FLAGGED_TIERS = Set.of("KNOWN_MALICIOUS", "HIGH_CONFIDENCE", "REVIEW");

    static final String DISCLAIMER = "Indicateur statistique issu d'un modèle entraîné sur des paquets npm malveillants "
            + "publics (DataDog, OSSF) : il signale un paquet à vérifier, pas une décision de blocage. "
            + "« Confiance élevée » = seuil strict (≈0,1 % de fausses alertes mesurées), « À vérifier » = seuil large "
            + "(≈1 %). « Connu malveillant » vient de la liste OSSF, sans modèle. La CI reste seule juge de la release.";

    public record Component(String ecosystem, String name, String version) {
        String key() {
            return ecosystem + ":" + name + "@" + version;
        }
    }

    /** PEP 503: PyPI names are case-insensitive and treat runs of - _ . as one dash. */
    static String normalizePypiName(String name) {
        return name.trim().toLowerCase().replaceAll("[-_.]+", "-");
    }

    private final SupplyChainScoreRepo repo;
    private final Path mlDir;
    private final Path pythonExe;
    private final String modelVersion;
    private final int cacheDays;
    private final int maxComponents;
    private final boolean enabled;
    private final boolean autoAnalyze;
    private final int batchTimeoutSeconds;

    private final Set<Long> running = ConcurrentHashMap.newKeySet();
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "supply-chain");
        t.setDaemon(true);
        return t;
    });

    public SupplyChainService(
            SupplyChainScoreRepo repo,
            @Value("${ml.dir:}") String mlDirConfig,
            @Value("${ml.python:}") String pythonConfig,
            @Value("${supplychain.model-version:v5.1}") String modelVersion,
            @Value("${supplychain.cache-days:30}") int cacheDays,
            @Value("${supplychain.max-components:400}") int maxComponents,
            @Value("${supplychain.enabled:true}") boolean enabled,
            @Value("${supplychain.auto-analyze:true}") boolean autoAnalyze,
            @Value("${supplychain.batch-timeout-seconds:300}") int batchTimeoutSeconds) {
        this.repo = repo;
        this.mlDir = MlPaths.resolveMlDir(mlDirConfig);
        this.pythonExe = MlPaths.resolvePython(pythonConfig, this.mlDir);
        this.modelVersion = modelVersion;
        this.cacheDays = cacheDays;
        this.maxComponents = maxComponents;
        this.enabled = enabled;
        this.autoAnalyze = autoAnalyze;
        this.batchTimeoutSeconds = batchTimeoutSeconds;
    }

    // ------------------------------------------------------------------ SBOM → npm components

    /** npm and PyPI components of a Syft SBOM ({@code artifacts[]}), de-duplicated per ecosystem. */
    static List<Component> extractComponents(JsonNode sbomRoot) {
        Map<String, Component> out = new LinkedHashMap<>();
        JsonNode artifacts = sbomRoot == null ? null : sbomRoot.path("artifacts");
        if (artifacts == null || !artifacts.isArray()) {
            return List.of();
        }
        for (JsonNode art : artifacts) {
            String purl = art.path("purl").asText("");
            String type = art.path("type").asText("");
            String ecosystem;
            if (purl.startsWith("pkg:npm/") || "npm".equalsIgnoreCase(type)) {
                ecosystem = ECOSYSTEM_NPM;
            } else if (purl.startsWith("pkg:pypi/") || "python".equalsIgnoreCase(type)) {
                ecosystem = ECOSYSTEM_PYPI;
            } else {
                continue;
            }
            String name = art.path("name").asText("").trim();
            String version = art.path("version").asText("").trim();
            if (name.isEmpty()) {
                continue;
            }
            if (ECOSYSTEM_PYPI.equals(ecosystem)) {
                name = normalizePypiName(name);
            }
            Component c = new Component(ecosystem, name, version);
            out.putIfAbsent(c.key(), c);
        }
        return new ArrayList<>(out.values());
    }

    /** Kept for existing callers/tests: only the npm part of {@link #extractComponents}. */
    static List<Component> extractNpmComponents(JsonNode sbomRoot) {
        return extractComponents(sbomRoot).stream().filter(c -> ECOSYSTEM_NPM.equals(c.ecosystem())).toList();
    }

    List<Component> componentsOf(ScanResult scan) {
        for (String file : List.of("sbom.json", "sbom.syft.json")) {
            Path p = Path.of(scan.getResultsDir(), file);
            if (Files.isRegularFile(p)) {
                try {
                    List<Component> c = extractComponents(MAPPER.readTree(p.toFile()));
                    if (!c.isEmpty()) {
                        return c;
                    }
                } catch (Exception e) {
                    log.warn("Cannot read SBOM {}: {}", p, e.getMessage());
                }
            }
        }
        return List.of();
    }

    // ------------------------------------------------------------------ report

    public boolean isModelAvailable() {
        return modelsAvailable().containsValue(true);
    }

    /** One model per ecosystem; an ecosystem without its bundle is reported, not an error. */
    public Map<String, Boolean> modelsAvailable() {
        Path dir = mlDir.resolve("supplychain");
        boolean script = Files.isRegularFile(dir.resolve("score.py"));
        Map<String, Boolean> out = new LinkedHashMap<>();
        for (String eco : MODEL_ECOSYSTEMS) {
            String folder = ECOSYSTEM_NPM.equals(eco) ? "artifacts" : "artifacts_" + eco;
            out.put(eco, script && Files.isRegularFile(dir.resolve(folder).resolve("runtime_bundle.joblib")));
        }
        return out;
    }

    public boolean isRunning(Long scanId) {
        return running.contains(scanId);
    }

    /** Cached results for the scan's npm dependencies; never triggers an analysis. */
    public Map<String, Object> report(ScanResult scan) {
        List<Component> components = componentsOf(scan);
        Map<String, SupplyChainScore> cached = cachedFor(components);
        return buildReport(scan.getId(), components, cached, running.contains(scan.getId()));
    }

    Map<String, Object> buildReport(Long scanId, List<Component> components, Map<String, SupplyChainScore> cached,
            boolean analysisRunning) {
        int known = 0, high = 0, review = 0, low = 0, notAnalysed = 0, pending = 0;
        List<Map<String, Object>> flagged = new ArrayList<>();
        List<Map<String, Object>> analyzed = new ArrayList<>();
        List<Map<String, Object>> skipped = new ArrayList<>();
        for (Component c : components) {
            SupplyChainScore s = cached.get(c.key());
            if (s == null) {
                pending++;
                continue;
            }
            String tier = s.getTier();
            if (!"SCORED".equals(s.getStatus()) && !"KNOWN_MALICIOUS".equals(tier)) {
                notAnalysed++;
                skipped.add(toBrief(s));
                continue;
            }
            analyzed.add(toBrief(s));
            switch (tier == null ? "" : tier) {
                case "KNOWN_MALICIOUS" -> known++;
                case "HIGH_CONFIDENCE" -> high++;
                case "REVIEW" -> review++;
                default -> low++;
            }
            if (tier != null && FLAGGED_TIERS.contains(tier)) {
                flagged.add(toItem(s));
            }
        }
        flagged.sort(Comparator.<Map<String, Object>>comparingInt(m -> tierRank((String) m.get("tier")))
                .thenComparing(m -> -((Number) m.getOrDefault("suspicionProba", 0.0)).doubleValue()));

        // every dependency the model actually scored, highest suspicion first: proof of work for the user
        analyzed.sort(Comparator.<Map<String, Object>>comparingInt(m -> tierRank((String) m.get("tier")))
                .thenComparing(m -> -((Number) m.getOrDefault("suspicionProba", 0.0)).doubleValue()));

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("knownMalicious", known);
        summary.put("highConfidence", high);
        summary.put("review", review);
        summary.put("low", low);
        summary.put("notAnalysed", notAnalysed);
        summary.put("pending", pending);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("scanId", scanId);
        body.put("enabled", enabled);
        body.put("modelAvailable", isModelAvailable());
        body.put("modelsAvailable", modelsAvailable());
        Map<String, Integer> byEcosystem = new LinkedHashMap<>();
        components.forEach(c -> byEcosystem.merge(c.ecosystem(), 1, Integer::sum));
        body.put("componentsByEcosystem", byEcosystem);
        body.put("modelVersion", modelVersion);
        body.put("analysisRunning", analysisRunning);
        body.put("totalComponents", components.size());
        body.put("summary", summary);
        body.put("flagged", flagged);
        body.put("analyzed", analyzed);
        body.put("skipped", skipped);
        body.put("disclaimer", DISCLAIMER);
        return body;
    }

    /** Compact row for the "all analysed dependencies" table (no reasons: those are only for flagged items). */
    private Map<String, Object> toBrief(SupplyChainScore s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ecosystem", s.getEcosystem());
        m.put("name", s.getName());
        m.put("version", s.getVersion());
        m.put("status", s.getStatus());
        m.put("tier", s.getTier());
        m.put("suspicionProba", s.getSuspicionProba());
        return m;
    }

    // ------------------------------------------------------------------ on-demand check of a few packages

    public static final int MAX_CHECK_PACKAGES = 20;

    /** Validates a "test these packages" request. Pure function so it is unit-testable. */
    static List<Component> validateCheckRequest(List<Component> requested) {
        if (requested == null || requested.isEmpty()) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST, "Indiquez au moins un paquet");
        }
        if (requested.size() > MAX_CHECK_PACKAGES) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "Maximum " + MAX_CHECK_PACKAGES + " paquets par vérification");
        }
        List<Component> clean = new ArrayList<>();
        for (Component c : requested) {
            String eco = c.ecosystem() == null ? ECOSYSTEM_NPM : c.ecosystem().trim().toLowerCase();
            String name = c.name() == null ? "" : c.name().trim();
            boolean scopedOk = !name.contains("/") || name.matches("@[A-Za-z0-9._~-]+/[A-Za-z0-9._~-]+");
            if (name.isEmpty() || name.length() > 214 || !name.matches("[A-Za-z0-9@/._~+-]+") || !scopedOk
                    || name.contains("..") || name.startsWith(".")) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.BAD_REQUEST, "Nom de paquet invalide : " + name);
            }
            String version = c.version() == null ? "" : c.version().trim();
            if (version.length() > 80 || !version.matches("[A-Za-z0-9._+~-]*")) {
                throw new org.springframework.web.server.ResponseStatusException(
                        org.springframework.http.HttpStatus.BAD_REQUEST, "Version invalide : " + version);
            }
            clean.add(new Component(eco, ECOSYSTEM_PYPI.equals(eco) ? normalizePypiName(name) : name, version));
        }
        return clean;
    }

    /**
     * Scores a handful of packages right now (nothing is stored). Lets a user test a package BEFORE adding it to
     * a project, and shows the detector at work on known-bad names.
     */
    public List<Map<String, Object>> checkPackages(List<Component> requested) {
        List<Component> packages = validateCheckRequest(requested);
        if (!enabled || !isModelAvailable()) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE, "Modèle supply chain indisponible");
        }
        try {
            JsonNode scored = runScorer(packages);
            List<Map<String, Object>> out = new ArrayList<>();
            for (JsonNode node : scored) {
                out.add(MAPPER.convertValue(node, new TypeReference<Map<String, Object>>() {
                }));
            }
            return out;
        } catch (org.springframework.web.server.ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Supply-chain check failed: {}", e.getMessage());
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_GATEWAY, "Analyse impossible pour le moment");
        }
    }

    static int tierRank(String tier) {
        return switch (tier == null ? "" : tier) {
            case "KNOWN_MALICIOUS" -> 0;
            case "HIGH_CONFIDENCE" -> 1;
            case "REVIEW" -> 2;
            default -> 3;
        };
    }

    private Map<String, Object> toItem(SupplyChainScore s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ecosystem", s.getEcosystem());
        m.put("name", s.getName());
        m.put("version", s.getVersion());
        m.put("tier", s.getTier());
        m.put("suspicionProba", s.getSuspicionProba());
        m.put("probableType", s.getProbableType());
        m.put("reasons", parseReasons(s.getReasonsJson()));
        m.put("knownMaliciousId", s.getKnownMaliciousId());
        m.put("scoredAt", s.getScoredAt() != null ? s.getScoredAt().toString() : null);
        return m;
    }

    static List<String> parseReasons(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        try {
            return MAPPER.readValue(json, new TypeReference<List<String>>() {
            });
        } catch (Exception e) {
            return List.of();
        }
    }

    private Map<String, SupplyChainScore> cachedFor(List<Component> components) {
        if (components.isEmpty()) {
            return Map.of();
        }
        Map<String, Set<String>> namesByEco = new HashMap<>();
        components.forEach(c -> namesByEco.computeIfAbsent(c.ecosystem(), k -> new HashSet<>()).add(c.name()));
        LocalDateTime oldest = LocalDateTime.now().minusDays(cacheDays);
        Map<String, SupplyChainScore> out = new HashMap<>();
        namesByEco.forEach((eco, names) -> {
            for (SupplyChainScore s : repo.findByEcosystemAndNameIn(eco, names)) {
                if (isFresh(s, oldest)) {
                    out.put(eco + ":" + s.getName() + "@" + s.getVersion(), s);
                }
            }
        });
        return out;
    }

    boolean isFresh(SupplyChainScore s, LocalDateTime oldest) {
        return s.getScoredAt() != null && s.getScoredAt().isAfter(oldest) && modelVersion.equals(s.getModelVersion());
    }

    // ------------------------------------------------------------------ analysis

    public void analyzeScanAsync(Long scanId, ScanResult scan) {
        if (!enabled || !autoAnalyze) {
            return;
        }
        executor.submit(() -> {
            try {
                analyze(scan);
            } catch (Exception e) {
                log.warn("Supply-chain analysis failed for scan {}: {}", scanId, e.getMessage());
            }
        });
    }

    /** Scores the dependencies that are not cached yet, stores the results and returns the report. */
    public Map<String, Object> analyze(ScanResult scan) {
        return analyze(scan, null);
    }

    /**
     * Runs the analysis as a STEP OF THE SCAN: progress lines go to the live scan log, and the caller only
     * announces the end of the scan once the supply-chain tab is fully loaded. Never throws.
     */
    public void analyzeDuringScan(ScanResult scan, java.util.function.Consumer<String> scanLog) {
        if (!enabled || !autoAnalyze) {
            return;
        }
        try {
            analyze(scan, scanLog);
        } catch (Exception e) {
            log.warn("Supply-chain analysis failed for scan {}: {}", scan.getId(), e.getMessage());
            scanLog.accept("[SUPPLY-CHAIN] Analyse interrompue (" + e.getClass().getSimpleName()
                    + ") : les résultats déjà calculés restent disponibles.");
        }
    }

    static String startLine(List<Component> components, int toAnalyse) {
        Map<String, Integer> byEco = new LinkedHashMap<>();
        components.forEach(c -> byEco.merge(c.ecosystem(), 1, Integer::sum));
        String detail = String.join(", ", byEco.entrySet().stream()
                .map(e -> ("pypi".equals(e.getKey()) ? "PyPI" : e.getKey()) + " : " + e.getValue()).toList());
        return "[SUPPLY-CHAIN] Recherche des paquets malveillants dans " + components.size() + " dépendances ("
                + detail + ")" + (toAnalyse < components.size()
                        ? " — " + (components.size() - toAnalyse) + " déjà connues en cache" : "") + "...";
    }

    @SuppressWarnings("unchecked")
    static String summaryLine(Map<String, Object> report) {
        Map<String, Object> s = (Map<String, Object>) report.get("summary");
        int analysed = ((Number) s.get("knownMalicious")).intValue() + ((Number) s.get("highConfidence")).intValue()
                + ((Number) s.get("review")).intValue() + ((Number) s.get("low")).intValue();
        return "[SUPPLY-CHAIN] Terminé : " + analysed + " analysées — " + s.get("knownMalicious")
                + " connu(s) malveillant(s), " + s.get("highConfidence") + " confiance élevée, " + s.get("review")
                + " à vérifier" + (((Number) s.get("notAnalysed")).intValue() > 0
                        ? ", " + s.get("notAnalysed") + " non analysable(s)" : "") + ".";
    }

    Map<String, Object> analyze(ScanResult scan, java.util.function.Consumer<String> scanLog) {
        java.util.function.Consumer<String> say = scanLog != null ? scanLog : m -> { };
        Long scanId = scan.getId();
        List<Component> components = componentsOf(scan);
        if (components.isEmpty()) {
            say.accept("[SUPPLY-CHAIN] Aucune dépendance npm ou PyPI dans le SBOM : rien à analyser.");
            return buildReport(scanId, components, cachedFor(components), false);
        }
        if (!enabled || !isModelAvailable()) {
            say.accept("[SUPPLY-CHAIN] Modèle indisponible sur ce serveur : recherche de paquets malveillants ignorée.");
            return buildReport(scanId, components, cachedFor(components), false);
        }
        if (!running.add(scanId)) {
            return buildReport(scanId, components, cachedFor(components), true);
        }
        try {
            Map<String, SupplyChainScore> cached = cachedFor(components);
            List<Component> todo = components.stream().filter(c -> !cached.containsKey(c.key()))
                    .limit(maxComponents).toList();
            log.info("Supply-chain scan {}: {} components, {} to analyse", scanId, components.size(), todo.size());
            say.accept(startLine(components, todo.size()));
            for (int i = 0; i < todo.size(); i += BATCH_SIZE) {
                List<Component> batch = todo.subList(i, Math.min(todo.size(), i + BATCH_SIZE));
                try {
                    JsonNode scored = runScorer(batch);
                    storeResults(batch, scored);
                } catch (Exception e) {
                    log.warn("Supply-chain batch failed ({} packages): {}", batch.size(), e.getMessage());
                    say.accept("[SUPPLY-CHAIN] Un lot de " + batch.size() + " paquets n'a pas pu être analysé (réseau ?).");
                }
                say.accept("[SUPPLY-CHAIN] " + Math.min(todo.size(), i + BATCH_SIZE) + "/" + todo.size()
                        + " dépendances examinées...");
            }
            Map<String, Object> report = buildReport(scanId, components, cachedFor(components), false);
            say.accept(summaryLine(report));
            return report;
        } finally {
            running.remove(scanId);
        }
    }

    private void storeResults(List<Component> batch, JsonNode scored) {
        if (!scored.isArray()) {
            return;
        }
        List<SupplyChainScore> rows = new ArrayList<>();
        for (int i = 0; i < scored.size() && i < batch.size(); i++) {
            SupplyChainScore s = toEntity(batch.get(i), scored.get(i));
            if (s != null) {
                rows.add(s);
            }
        }
        for (SupplyChainScore s : rows) {
            try {
                // replace a stale row for the same package version instead of violating the unique key
                repo.findByEcosystemAndNameIn(s.getEcosystem(), List.of(s.getName())).stream()
                        .filter(old -> old.getVersion().equals(s.getVersion())).findFirst()
                        .ifPresent(old -> s.setId(old.getId()));
                repo.save(s);
            } catch (Exception e) {
                log.warn("Cannot store supply-chain score {}@{}: {}", s.getName(), s.getVersion(), e.getMessage());
            }
        }
    }

    /** Maps one sidecar answer to a cache row; transient failures return null so they are retried later. */
    SupplyChainScore toEntity(Component component, JsonNode node) {
        String status = node.path("status").asText("");
        String tier = node.hasNonNull("tier") ? node.get("tier").asText() : null;
        boolean known = "KNOWN_MALICIOUS".equals(tier);
        if (!known && !CACHEABLE_STATUSES.contains(status)) {
            return null;
        }
        List<String> reasons = new ArrayList<>();
        node.path("reasons").forEach(r -> reasons.add(r.asText()));
        String reasonsJson;
        try {
            reasonsJson = MAPPER.writeValueAsString(reasons);
        } catch (Exception e) {
            reasonsJson = "[]";
        }
        return SupplyChainScore.builder()
                .ecosystem(component.ecosystem())
                .name(truncate(component.name(), 300))
                .version(truncate(component.version(), 120))
                .status(known ? "SCORED" : status)
                .tier(tier)
                .suspicionProba(node.hasNonNull("suspicionProba") ? node.get("suspicionProba").asDouble() : null)
                .probableType(node.hasNonNull("probableType") ? node.get("probableType").asText() : null)
                .reasonsJson(reasonsJson)
                .knownMaliciousId(node.hasNonNull("knownMaliciousId") ? node.get("knownMaliciousId").asText() : null)
                .modelVersion(modelVersion)
                .scoredAt(LocalDateTime.now())
                .build();
    }

    private static String truncate(String s, int max) {
        return s == null ? "" : (s.length() > max ? s.substring(0, max) : s);
    }

    // ------------------------------------------------------------------ Python sidecar

    private JsonNode runScorer(List<Component> batch) throws Exception {
        Path script = mlDir.resolve("supplychain").resolve("score.py");
        List<Map<String, String>> payload = new ArrayList<>();
        for (Component c : batch) {
            Map<String, String> m = new LinkedHashMap<>();
            m.put("name", c.name());
            m.put("version", c.version());
            m.put("ecosystem", c.ecosystem());
            payload.add(m);
        }
        ProcessBuilder pb = new ProcessBuilder(pythonExe.toString(), script.toString());
        pb.directory(mlDir.resolve("supplychain").toFile());
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        pb.redirectErrorStream(false);
        Process process = pb.start();
        // Drain both pipes concurrently so a large answer can never block the child process.
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> read(process.getInputStream()));
        CompletableFuture<String> err = CompletableFuture.supplyAsync(() -> read(process.getErrorStream()));
        process.getOutputStream().write(MAPPER.writeValueAsBytes(payload));
        process.getOutputStream().close();
        if (!process.waitFor(batchTimeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("score.py timed out after " + batchTimeoutSeconds + "s");
        }
        String stdout = out.get(5, TimeUnit.SECONDS);
        String stderr = err.get(5, TimeUnit.SECONDS);
        if (process.exitValue() != 0) {
            throw new IllegalStateException("score.py failed: " + (stderr.isBlank() ? stdout : stderr));
        }
        return MAPPER.readTree(stdout);
    }

    private static String read(InputStream stream) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            stream.transferTo(out);
            return out.toString(StandardCharsets.UTF_8).trim();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
