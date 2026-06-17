package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CveEntry;
import com.medianet.repository.CveEntryRepo;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * EPSS (Exploit Prediction Scoring System) integration — FIRST.org API.
 *
 * EPSS measures the probability (0–1) that a CVE will be exploited in the wild
 * within the next 30 days, based on threat intelligence and ML models.
 *
 * API endpoint (free, no key required):
 * https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...
 *
 * Supports up to 100 CVEs per request — we batch accordingly.
 * Data is refreshed daily by FIRST.org; we refresh every 48 h.
 */
@Service
public class EpssService {

    private static final Logger log = LoggerFactory.getLogger(EpssService.class);

    private static final String EPSS_API = "https://api.first.org/data/v1/epss";
    private static final int BATCH_SIZE = 100;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final CveEntryRepo cveEntryRepo;

    public EpssService(CveEntryRepo cveEntryRepo) {
        this.cveEntryRepo = cveEntryRepo;
    }

    /** In-memory cache: uppercase(CVE-ID) → EpssData (score + percentile). */
    public record EpssData(double score, double percentile) {
    }

    private volatile Map<String, EpssData> epssCache = Map.of();

    // -------------------------------------------------------------------------
    // Lifecycle — warm-up cache from already-known CVEs in DB at startup
    // -------------------------------------------------------------------------

    @PostConstruct
    public void init() {
        log.info("[EPSS] Initialisation — chargement depuis la DB...");
        List<String> cveIds = cveEntryRepo.findAll()
                .stream()
                .map(CveEntry::getCveId)
                .filter(id -> id != null && !id.isBlank())
                .distinct()
                .collect(Collectors.toList());
        if (!cveIds.isEmpty()) {
            Map<String, EpssData> loaded = fetchEpss(cveIds);
            this.epssCache = Collections.unmodifiableMap(loaded);
            log.info("[EPSS] Cache initialisé : {} CVEs avec score EPSS.", loaded.size());
        } else {
            log.info("[EPSS] Aucune CVE en DB pour l'initialisation du cache EPSS.");
        }
    }

    /** Refresh cache every 48 hours (172 800 000 ms). */
    @Scheduled(fixedDelay = 172_800_000)
    public void scheduledRefresh() {
        log.info("[EPSS] Rafraîchissement planifié (48 h)...");
        init();
    }

    // -------------------------------------------------------------------------
    // Retroactive DB enrichment
    // -------------------------------------------------------------------------

    /**
     * Iterates ALL CveEntries in the DB and updates their EPSS score/percentile.
     * Called at startup (async) and via admin endpoint.
     */
    @Async
    public void enrichAllExistingCves() {
        List<CveEntry> all = cveEntryRepo.findAll();
        if (all.isEmpty()) {
            log.info("[EPSS] Aucune CVE en base à enrichir.");
            return;
        }
        log.info("[EPSS] Enrichissement rétroactif EPSS de {} CVEs en base...", all.size());

        // Collect distinct CVE IDs that need enrichment
        List<String> cveIds = all.stream()
                .map(CveEntry::getCveId)
                .filter(id -> id != null && !id.isBlank())
                .distinct()
                .collect(Collectors.toList());

        Map<String, EpssData> fetched = fetchEpss(cveIds);

        // Merge into cache
        Map<String, EpssData> merged = new HashMap<>(epssCache);
        merged.putAll(fetched);
        this.epssCache = Collections.unmodifiableMap(merged);

        int updated = 0;
        for (CveEntry cve : all) {
            EpssData data = fetched.get(cve.getCveId() != null ? cve.getCveId().toUpperCase() : "");
            if (data != null) {
                cve.setEpssScore(data.score());
                cve.setEpssPercentile(data.percentile());
                updated++;
            }
        }
        if (updated > 0) {
            cveEntryRepo.saveAll(all);
            log.info("[EPSS] {} CVE(s) enrichies avec un score EPSS.", updated);
        } else {
            log.info("[EPSS] Aucun score EPSS trouvé pour les CVEs en base (API indisponible ou CVEs inconnues).");
        }
    }

    // -------------------------------------------------------------------------
    // Public API used during live scans
    // -------------------------------------------------------------------------

    /** Returns the EPSS data for a CVE from the in-memory cache, or null. */
    public EpssData getEpss(String cveId) {
        if (cveId == null || cveId.isBlank())
            return null;
        return epssCache.get(cveId.toUpperCase());
    }

    /**
     * Enriches a batch of fresh CVEs (from a live scan) with EPSS data.
     * Fetches only CVEs not already in the cache to avoid redundant requests.
     */
    public void enrichCves(List<CveEntry> cves) {
        List<String> missing = cves.stream()
                .map(CveEntry::getCveId)
                .filter(id -> id != null && !id.isBlank() && !epssCache.containsKey(id.toUpperCase()))
                .distinct()
                .collect(Collectors.toList());

        Map<String, EpssData> fetched = missing.isEmpty() ? Map.of() : fetchEpss(missing);

        // Merge into cache
        if (!fetched.isEmpty()) {
            Map<String, EpssData> merged = new HashMap<>(epssCache);
            merged.putAll(fetched);
            this.epssCache = Collections.unmodifiableMap(merged);
        }

        // Apply to CVE entities
        for (CveEntry cve : cves) {
            EpssData data = epssCache.get(cve.getCveId() != null ? cve.getCveId().toUpperCase() : "");
            if (data != null) {
                cve.setEpssScore(data.score());
                cve.setEpssPercentile(data.percentile());
            }
        }
    }

    /** How many CVEs are currently cached. */
    public int cacheSize() {
        return epssCache.size();
    }

    // -------------------------------------------------------------------------
    // Internal — batch HTTP requests to FIRST.org EPSS API
    // -------------------------------------------------------------------------

    /**
     * Fetches EPSS scores for the given list of CVE IDs in batches of BATCH_SIZE.
     * Returns a map: uppercase(CVE-ID) → EpssData.
     */
    private Map<String, EpssData> fetchEpss(List<String> cveIds) {
        Map<String, EpssData> result = new HashMap<>();
        if (cveIds == null || cveIds.isEmpty())
            return result;

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();

        // Split into batches
        for (int i = 0; i < cveIds.size(); i += BATCH_SIZE) {
            List<String> batch = cveIds.subList(i, Math.min(i + BATCH_SIZE, cveIds.size()));
            String cveParam = String.join(",", batch);
            String url = EPSS_API + "?cve=" + cveParam + "&limit=" + BATCH_SIZE;

            try {
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .timeout(Duration.ofSeconds(30))
                        .header("Accept", "application/json")
                        .GET()
                        .build();

                HttpResponse<String> response = client.send(request,
                        HttpResponse.BodyHandlers.ofString());

                if (response.statusCode() != 200) {
                    log.warn("[EPSS] HTTP {} pour le batch {}-{}", response.statusCode(), i, i + batch.size());
                    continue;
                }

                JsonNode root = MAPPER.readTree(response.body());
                JsonNode data = root.get("data");
                if (data == null || !data.isArray())
                    continue;

                for (JsonNode entry : data) {
                    String cveId = entry.path("cve").asText("").toUpperCase();
                    double score = entry.path("epss").asDouble(0.0);
                    double percentile = entry.path("percentile").asDouble(0.0);
                    if (!cveId.isBlank()) {
                        result.put(cveId, new EpssData(score, percentile));
                    }
                }

            } catch (Exception e) {
                log.warn("[EPSS] Erreur lors de la récupération du batch {}-{} : {}", i, i + batch.size(),
                        e.getMessage());
            }
        }

        log.debug("[EPSS] {} scores EPSS récupérés pour {} CVEs demandées.", result.size(), cveIds.size());
        return result;
    }
}
