package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CveEntry;
import com.medianet.repository.CveEntryRepo;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;

/**
 * CISA Known Exploited Vulnerabilities (KEV) integration service.
 *
 * Downloads the official CISA KEV JSON catalogue at startup and refreshes
 * every 24 h. Falls back to a local cached copy when offline.
 *
 * Source:
 * https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *
 * Relevant JSON fields per vulnerability:
 * "cveID" → CVE identifier (e.g. "CVE-2021-44228")
 * "dateAdded" → ISO date when added to the catalogue
 * "knownRansomwareCampaignUse" → "Known" | "Unknown"
 */
@Service
public class CisaKevService {

    private static final Logger log = LoggerFactory.getLogger(CisaKevService.class);

    private static final String KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Value("${cisa.kev.local-path:./cisa-kev-cache.json}")
    private String localCachePath;

    private final CveEntryRepo cveEntryRepo;

    public CisaKevService(CveEntryRepo cveEntryRepo) {
        this.cveEntryRepo = cveEntryRepo;
    }

    /** Immutable value carrier for a single KEV entry. */
    public record KevEntry(String dateAdded, boolean ransomware) {
    }

    /**
     * In-memory index: uppercase(CVE-ID) → KevEntry.
     * Volatile so reads from other threads always see the latest swap.
     */
    private volatile Map<String, KevEntry> kevIndex = Map.of();

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @PostConstruct
    public void init() {
        log.info("[KEV] Initialisation du service CISA KEV...");
        loadKev();
    }

    /** Refresh every 24 hours (86 400 000 ms). */
    @Scheduled(fixedDelay = 86_400_000)
    public void scheduledRefresh() {
        log.info("[KEV] Rafraîchissement planifié (24 h)...");
        loadKev();
    }

    /**
     * Retroactive enrichment: iterates ALL CveEntries in DB and marks those
     * found in the KEV catalogue. Called at startup (async) and via admin endpoint.
     */
    @Async
    public void enrichAllExistingCves() {
        List<CveEntry> all = cveEntryRepo.findAll();
        if (all.isEmpty()) {
            log.info("[KEV] Aucune CVE en base à enrichir.");
            return;
        }
        log.info("[KEV] Enrichissement rétroactif KEV de {} CVEs en base...", all.size());
        int updated = 0;
        for (CveEntry cve : all) {
            String key = cve.getCveId() != null ? cve.getCveId().toUpperCase() : "";
            KevEntry entry = kevIndex.get(key);
            if (entry != null && !cve.isKevListed()) {
                cve.setKevListed(true);
                cve.setKevDateAdded(entry.dateAdded());
                cve.setKevRansomware(entry.ransomware());
                updated++;
            }
        }
        if (updated > 0) {
            cveEntryRepo.saveAll(all);
            log.info("[KEV] {} CVE(s) marquées dans le catalogue CISA KEV.", updated);
        } else {
            log.info("[KEV] Aucune nouvelle CVE KEV trouvée parmi celles en base.");
        }
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /** Returns true if this CVE is in the CISA KEV catalogue. */
    public boolean isKev(String cveId) {
        if (cveId == null || cveId.isBlank())
            return false;
        return kevIndex.containsKey(cveId.toUpperCase());
    }

    /**
     * Returns the KEV entry (dateAdded, ransomware flag) for the given CVE,
     * or null if not in the catalogue.
     */
    public KevEntry getKevEntry(String cveId) {
        if (cveId == null || cveId.isBlank())
            return null;
        return kevIndex.get(cveId.toUpperCase());
    }

    /** Number of CVEs in the current in-memory KEV index. */
    public int indexSize() {
        return kevIndex.size();
    }

    // -------------------------------------------------------------------------
    // Internal loading logic
    // -------------------------------------------------------------------------

    private void loadKev() {
        Path localPath = Path.of(localCachePath);
        boolean downloaded = tryDownload(localPath);

        if (!downloaded) {
            if (Files.exists(localPath)) {
                log.warn("[KEV] Téléchargement échoué — utilisation du cache local : {}", localPath);
            } else {
                log.error("[KEV] Pas de connexion et pas de cache local. Index KEV vide.");
                return;
            }
        }

        buildIndex(localPath);
    }

    /** Attempts a download; returns true on success. */
    private boolean tryDownload(Path dest) {
        try {
            if (dest.getParent() != null) {
                Files.createDirectories(dest.getParent());
            }

            HttpClient client = HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(20))
                    .followRedirects(HttpClient.Redirect.NORMAL)
                    .build();

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(KEV_URL))
                    .timeout(Duration.ofSeconds(60))
                    .GET()
                    .build();

            log.info("[KEV] Téléchargement du catalogue KEV depuis : {}", KEV_URL);
            HttpResponse<InputStream> response = client.send(request,
                    HttpResponse.BodyHandlers.ofInputStream());

            if (response.statusCode() != 200) {
                log.warn("[KEV] Réponse HTTP {} — abandon du téléchargement.", response.statusCode());
                return false;
            }

            Path temp = dest.resolveSibling(dest.getFileName() + ".tmp");
            try (InputStream in = response.body()) {
                Files.copy(in, temp, StandardCopyOption.REPLACE_EXISTING);
            }
            Files.move(temp, dest, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            log.info("[KEV] Catalogue KEV sauvegardé dans : {}", dest.toAbsolutePath());
            return true;

        } catch (Exception e) {
            log.warn("[KEV] Impossible de télécharger le catalogue KEV : {}", e.getMessage());
            return false;
        }
    }

    /** Parses the KEV JSON and builds the in-memory index. */
    private void buildIndex(Path jsonFile) {
        Map<String, KevEntry> newIndex = new HashMap<>();
        try {
            JsonNode root = MAPPER.readTree(jsonFile.toFile());
            JsonNode vulns = root.get("vulnerabilities");
            if (vulns == null || !vulns.isArray()) {
                log.error("[KEV] Fichier KEV invalide — champ 'vulnerabilities' absent.");
                return;
            }
            for (JsonNode v : vulns) {
                String cveId = v.path("cveID").asText("").toUpperCase();
                String dateAdded = v.path("dateAdded").asText(null);
                String ransomwareStr = v.path("knownRansomwareCampaignUse").asText("Unknown");
                boolean ransomware = "Known".equalsIgnoreCase(ransomwareStr);
                if (!cveId.isBlank()) {
                    newIndex.put(cveId, new KevEntry(dateAdded, ransomware));
                }
            }
            this.kevIndex = Collections.unmodifiableMap(newIndex);
            log.info("[KEV] Index construit : {} CVEs dans le catalogue CISA KEV.", newIndex.size());

        } catch (IOException e) {
            log.error("[KEV] Erreur lors du parsing du JSON KEV : {}", e.getMessage());
        }
    }
}
