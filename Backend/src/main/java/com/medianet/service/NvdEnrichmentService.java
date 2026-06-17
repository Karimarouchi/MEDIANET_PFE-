package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CveEntry;
import com.medianet.entity.NvdCacheEntry;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.NvdCacheRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.*;
import java.util.function.Consumer;

/**
 * Enriches CVE entries with data from external APIs.
 * - CVE-* â†’ NVD API (with cache + FR translation)
 * - CWE-* â†’ static local map (no API call)
 * - GHSA-* â†’ GitHub Advisory API
 */
@Service
public class NvdEnrichmentService {

    private static final Logger log = LoggerFactory.getLogger(NvdEnrichmentService.class);
    private static final String NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";
    private static final String GHSA_API_URL = "https://api.github.com/advisories/";
    private static final long NVD_DELAY_MS = 650;
    private static final long GHSA_DELAY_MS = 300;
    private static final int CACHE_TTL_DAYS = 30;

    // -----------------------------------------------------------------------
    // CWE static local map (FR descriptions)
    // -----------------------------------------------------------------------
    private static final Map<String, CweInfo> CWE_MAP = new HashMap<>();
    static {
        CWE_MAP.put("CWE-89", new CweInfo("HIGH",
                "SQL Injection : requÃªte SQL construite avec des donnÃ©es utilisateur non filtrÃ©es permettant l'accÃ¨s ou la modification de la base de donnÃ©es."));
        CWE_MAP.put("CWE-79", new CweInfo("MEDIUM",
                "Cross-Site Scripting (XSS) : donnÃ©es utilisateur injectÃ©es dans le HTML sans Ã©chappement, permettant l'exÃ©cution de scripts malveillants."));
        CWE_MAP.put("CWE-798", new CweInfo("HIGH",
                "Identifiants codÃ©s en dur dans le code source. Ne jamais stocker de mots de passe, clÃ©s API ou tokens directement dans le code."));
        CWE_MAP.put("CWE-330", new CweInfo("MEDIUM",
                "Utilisation de valeurs alÃ©atoires cryptographiquement insuffisantes pour des opÃ©rations de sÃ©curitÃ© (tokens, clÃ©s, seeds)."));
        CWE_MAP.put("CWE-22", new CweInfo("HIGH",
                "Path Traversal : accÃ¨s non autorisÃ© Ã  des fichiers hors du rÃ©pertoire prÃ©vu via des sÃ©quences comme '../'."));
        CWE_MAP.put("CWE-78", new CweInfo("CRITICAL",
                "OS Command Injection : commande systÃ¨me construite avec des donnÃ©es utilisateur non validÃ©es, permettant l'exÃ©cution de commandes arbitraires."));
        CWE_MAP.put("CWE-502", new CweInfo("HIGH",
                "DÃ©sÃ©rialisation de donnÃ©es non fiables pouvant mener Ã  une exÃ©cution de code Ã  distance ou Ã  une corruption de l'Ã©tat de l'application."));
        CWE_MAP.put("CWE-918", new CweInfo("HIGH",
                "Server-Side Request Forgery (SSRF) : le serveur effectue des requÃªtes HTTP vers des URLs contrÃ´lÃ©es par l'attaquant."));
        CWE_MAP.put("CWE-94", new CweInfo("CRITICAL",
                "Injection de code : Ã©valuation de code fourni par l'utilisateur dans le contexte de l'application."));
        CWE_MAP.put("CWE-284", new CweInfo("HIGH",
                "ContrÃ´le d'accÃ¨s inadÃ©quat : manque de vÃ©rification des autorisations avant d'accÃ©der Ã  des ressources protÃ©gÃ©es."));
        CWE_MAP.put("CWE-311",
                new CweInfo("HIGH", "Absence de chiffrement de donnÃ©es sensibles stockÃ©es ou transmises en clair."));
        CWE_MAP.put("CWE-352", new CweInfo("MEDIUM",
                "Cross-Site Request Forgery (CSRF) : une requÃªte malveillante est exÃ©cutÃ©e Ã  l'insu de l'utilisateur authentifiÃ©."));
        CWE_MAP.put("CWE-476",
                new CweInfo("MEDIUM", "DÃ©fÃ©rencement de pointeur null pouvant provoquer un crash de l'application."));
        CWE_MAP.put("CWE-200", new CweInfo("MEDIUM",
                "Exposition d'informations sensibles Ã  un acteur non autorisÃ© (messages d'erreur, logs, rÃ©ponses API)."));
    }

    @Value("${nvd.api.key:}")
    private String apiKey;

    private final NvdCacheRepo cacheRepo;
    private final CveEntryRepo cveEntryRepo;
    private final TranslationService translationService;
    private final ObjectMapper mapper = new ObjectMapper();
    private final RestTemplate restTemplate = new RestTemplate();

    public NvdEnrichmentService(NvdCacheRepo cacheRepo,
            CveEntryRepo cveEntryRepo,
            TranslationService translationService) {
        this.cacheRepo = cacheRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.translationService = translationService;
    }

    // =========================================================================
    // PUBLIC API
    // =========================================================================

    /**
     * Enrich a freshly-parsed list of CVE entries in-place (called after each
     * scan).
     */
    public void enrich(List<CveEntry> entries, Consumer<String> logConsumer) {
        if (entries == null || entries.isEmpty())
            return;
        enrichList(entries, logConsumer, false);
    }

    /**
     * Async job: enrich ALL CveEntry rows in the DB where cvssScore IS NULL
     * or severity = 'UNKNOWN'. Called on startup and via the admin endpoint.
     */
    @Async
    public void enrichAllMissingCves() {
        List<CveEntry> missing = cveEntryRepo.findAllMissingEnrichment();
        if (missing.isEmpty()) {
            log.info("[ENRICH] Aucun CVE Ã  enrichir.");
            return;
        }
        log.info("[ENRICH] Enrichissement de {} CVEs manquants depuis la base...", missing.size());
        enrichList(missing, null, true);
        // Save all back to DB
        cveEntryRepo.saveAll(missing);
        log.info("[ENRICH] Enrichissement terminÃ©.");
    }

    // =========================================================================
    // INTERNAL DISPATCH
    // =========================================================================

    private void enrichList(List<CveEntry> entries, Consumer<String> logConsumer, boolean saveIndividually) {
        // --- CVE-* via NVD ---
        List<CveEntry> cveEntries = new ArrayList<>();
        List<CveEntry> cweEntries = new ArrayList<>();
        List<CveEntry> ghsaEntries = new ArrayList<>();
        List<CveEntry> otherEntries = new ArrayList<>();

        for (CveEntry e : entries) {
            String id = e.getCveId();
            if (id == null) {
                otherEntries.add(e);
                continue;
            }
            if (id.startsWith("CVE-"))
                cveEntries.add(e);
            else if (id.startsWith("CWE-"))
                cweEntries.add(e);
            else if (id.startsWith("GHSA-"))
                ghsaEntries.add(e);
            else
                otherEntries.add(e);
        }

        enrichViaNvd(cveEntries, logConsumer, saveIndividually);
        enrichViaCweMap(cweEntries, saveIndividually);
        enrichViaGhsa(ghsaEntries, saveIndividually);
    }

    // =========================================================================
    // CVE-* â†’ NVD API
    // =========================================================================

    private void enrichViaNvd(List<CveEntry> entries, Consumer<String> logConsumer, boolean saveIndividually) {
        if (entries.isEmpty())
            return;

        Set<String> toFetch = new LinkedHashSet<>();
        for (CveEntry e : entries)
            toFetch.add(e.getCveId());

        emit(logConsumer, "[NVD] Enrichissement de " + toFetch.size() + " CVE via NVD...");
        LocalDateTime staleThreshold = LocalDateTime.now().minusDays(CACHE_TTL_DAYS);
        Map<String, NvdCacheEntry> nvdData = new HashMap<>();
        boolean first = true;

        for (String cveId : toFetch) {
            Optional<NvdCacheEntry> cached = cacheRepo.findById(cveId);
            if (cached.isPresent() && cached.get().getCachedAt().isAfter(staleThreshold)) {
                nvdData.put(cveId, cached.get());
                continue;
            }
            if (!first)
                sleep(NVD_DELAY_MS);
            first = false;
            NvdCacheEntry fetched = fetchFromNvd(cveId);
            if (fetched != null) {
                cacheRepo.save(fetched);
                nvdData.put(cveId, fetched);
            }
        }

        int enriched = 0;
        for (CveEntry entry : entries) {
            NvdCacheEntry nvd = nvdData.get(entry.getCveId());
            if (nvd == null)
                continue;
            boolean changed = applyNvdData(entry, nvd);
            if (changed) {
                enriched++;
                if (saveIndividually)
                    cveEntryRepo.save(entry);
            }
        }
        emit(logConsumer, "[NVD] " + enriched + " entrÃ©es mises Ã  jour.");
    }

    // =========================================================================
    // CWE-* â†’ static local map
    // =========================================================================

    private void enrichViaCweMap(List<CveEntry> entries, boolean saveIndividually) {
        for (CveEntry entry : entries) {
            String id = entry.getCveId();
            CweInfo info = CWE_MAP.getOrDefault(id,
                    new CweInfo("MEDIUM",
                            "VulnÃ©rabilitÃ© de sÃ©curitÃ© dÃ©tectÃ©e par l'analyse statique du code source. Consultez la base CWE pour plus de dÃ©tails."));

            boolean changed = false;
            if ("UNKNOWN".equalsIgnoreCase(entry.getSeverity()) || isBlank(entry.getSeverity())) {
                entry.setSeverity(info.severity());
                changed = true;
            }
            if (isBlank(entry.getDescription())) {
                entry.setDescription(info.description());
                changed = true;
            }
            if (changed && saveIndividually)
                cveEntryRepo.save(entry);
        }
    }

    // =========================================================================
    // GHSA-* â†’ GitHub Advisory API
    // =========================================================================

    private void enrichViaGhsa(List<CveEntry> entries, boolean saveIndividually) {
        if (entries.isEmpty())
            return;
        log.info("[GHSA] Enrichissement de {} advisories via GitHub...", entries.size());
        boolean first = true;

        for (CveEntry entry : entries) {
            if (!first)
                sleep(GHSA_DELAY_MS);
            first = false;
            try {
                HttpHeaders headers = new HttpHeaders();
                headers.set("Accept", "application/vnd.github+json");
                headers.set("X-GitHub-Api-Version", "2022-11-28");
                HttpEntity<Void> req = new HttpEntity<>(headers);

                ResponseEntity<String> resp = restTemplate.exchange(
                        GHSA_API_URL + entry.getCveId(), HttpMethod.GET, req, String.class);

                if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null)
                    continue;

                JsonNode root = mapper.readTree(resp.getBody());

                boolean changed = false;
                // severity
                String ghSeverity = text(root, "severity");
                if (!isBlank(ghSeverity)
                        && ("UNKNOWN".equalsIgnoreCase(entry.getSeverity()) || isBlank(entry.getSeverity()))) {
                    entry.setSeverity(ghSeverity.toUpperCase());
                    changed = true;
                }
                // cvss score
                JsonNode cvssNode = root.get("cvss");
                if (cvssNode != null && entry.getCvssScore() == null) {
                    JsonNode scoreNode = cvssNode.get("score");
                    if (scoreNode != null && !scoreNode.isNull()) {
                        entry.setCvssScore(scoreNode.asDouble());
                        changed = true;
                    }
                }
                // description: try to translate summary
                String summary = text(root, "summary");
                if (!isBlank(summary) && isBlank(entry.getDescription())) {
                    String fr = translationService.translateToFrench(summary);
                    entry.setDescription(fr != null ? fr : summary);
                    changed = true;
                }

                if (changed && saveIndividually)
                    cveEntryRepo.save(entry);

            } catch (Exception e) {
                log.warn("[GHSA] Erreur pour {} : {}", entry.getCveId(), e.getMessage());
            }
        }
    }

    // =========================================================================
    // NVD helpers
    // =========================================================================

    private boolean applyNvdData(CveEntry entry, NvdCacheEntry nvd) {
        boolean changed = false;
        String bestDesc = !isBlank(nvd.getDescriptionFr()) ? nvd.getDescriptionFr() : nvd.getDescription();
        if (!isBlank(bestDesc)) {
            entry.setDescription(bestDesc);
            changed = true;
        }
        if (entry.getCvssScore() == null && nvd.getCvssScore() != null) {
            entry.setCvssScore(nvd.getCvssScore());
            changed = true;
        }
        if (("UNKNOWN".equalsIgnoreCase(entry.getSeverity()) || isBlank(entry.getSeverity()))
                && !isBlank(nvd.getSeverity())) {
            entry.setSeverity(nvd.getSeverity().toUpperCase());
            changed = true;
        }
        // Idée 3 — propagate affectedOs from NVD cache
        if (isBlank(entry.getAffectedOs()) && !isBlank(nvd.getAffectedOs())) {
            entry.setAffectedOs(nvd.getAffectedOs());
            changed = true;
        }
        return changed;
    }

    /**
     * Idée 3 — Extract affected OS from NVD CPE (Common Platform Enumeration) data.
     * Returns "WINDOWS", "LINUX", or "CROSS_PLATFORM".
     *
     * CPE format: cpe:2.3:part:vendor:product:version:...
     * part=o → operating system
     * part=a → application (OS-agnostic)
     * Windows CPE: microsoft:windows_*
     * Linux CPE: linux:linux_kernel, canonical:ubuntu_linux, redhat:*, debian:*,
     * alpine:*
     */
    private String extractAffectedOs(JsonNode cve) {
        JsonNode configurations = cve.get("configurations");
        if (configurations == null || !configurations.isArray())
            return "CROSS_PLATFORM";

        boolean hasWindows = false;
        boolean hasLinux = false;

        for (JsonNode config : configurations) {
            JsonNode nodes = config.get("nodes");
            if (nodes == null || !nodes.isArray())
                continue;
            for (JsonNode node : nodes) {
                JsonNode cpeMatch = node.get("cpeMatch");
                if (cpeMatch == null || !cpeMatch.isArray())
                    continue;
                for (JsonNode cpe : cpeMatch) {
                    String criteria = text(cpe, "criteria");
                    if (criteria == null)
                        continue;
                    String lower = criteria.toLowerCase();
                    // Windows detection
                    if (lower.contains(":o:microsoft:windows") || lower.contains(":o:microsoft:windows_server")) {
                        hasWindows = true;
                    }
                    // Linux detection (kernel, ubuntu, debian, rhel, alpine, fedora, suse, centos)
                    if (lower.contains(":o:linux:linux_kernel")
                            || lower.contains(":o:canonical:ubuntu")
                            || lower.contains(":o:debian:debian_linux")
                            || lower.contains(":o:redhat:")
                            || lower.contains(":o:fedoraproject:")
                            || lower.contains(":o:opensuse:")
                            || lower.contains(":o:suse:")
                            || lower.contains(":o:alpine_linux:")
                            || lower.contains(":o:centos:")) {
                        hasLinux = true;
                    }
                }
            }
        }

        if (hasWindows && !hasLinux)
            return "WINDOWS";
        if (hasLinux && !hasWindows)
            return "LINUX";
        return "CROSS_PLATFORM";
    }

    private NvdCacheEntry fetchFromNvd(String cveId) {
        try {
            HttpHeaders headers = new HttpHeaders();
            if (!isBlank(apiKey))
                headers.set("apiKey", apiKey);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<String> response = restTemplate.exchange(
                    NVD_API_URL + cveId, HttpMethod.GET, entity, String.class);

            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null)
                return null;

            JsonNode root = mapper.readTree(response.getBody());
            JsonNode vulns = root.get("vulnerabilities");
            if (vulns == null || !vulns.isArray() || vulns.isEmpty())
                return null;

            JsonNode cve = vulns.get(0).get("cve");
            if (cve == null)
                return null;

            String description = extractDescription(cve);
            String published = text(cve, "published");
            CvssInfo cvssInfo = extractCvss(cve);
            Double cvssScore = cvssInfo.score();
            String severity = !isBlank(cvssInfo.severity()) ? cvssInfo.severity().toUpperCase()
                    : deriveSeverity(cvssScore);
            String vector = extractCvssVector(cve);
            String descriptionFr = translationService.translateToFrench(description);
            String affectedOs = extractAffectedOs(cve);

            return NvdCacheEntry.builder()
                    .cveId(cveId).description(description).descriptionFr(descriptionFr)
                    .cvssScore(cvssScore).severity(severity).cvssVector(vector)
                    .publishedDate(published).cachedAt(LocalDateTime.now())
                    .affectedOs(affectedOs)
                    .build();

        } catch (HttpClientErrorException.TooManyRequests e) {
            log.warn("NVD rate-limit hit for {} â€” skipping", cveId);
            return null;
        } catch (Exception e) {
            log.warn("NVD lookup failed for {}: {}", cveId, e.getMessage());
            return null;
        }
    }

    private String extractDescription(JsonNode cve) {
        JsonNode descs = cve.get("descriptions");
        if (descs != null && descs.isArray())
            for (JsonNode d : descs)
                if ("en".equals(text(d, "lang")))
                    return text(d, "value");
        return null;
    }

    private CvssInfo extractCvss(JsonNode cve) {
        JsonNode metrics = cve.get("metrics");
        if (metrics == null)
            return new CvssInfo(null, null);
        for (String key : new String[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" }) {
            JsonNode arr = metrics.get(key);
            if (arr == null || !arr.isArray() || arr.isEmpty())
                continue;
            JsonNode best = null;
            for (JsonNode m : arr) {
                if ("Primary".equals(text(m, "type"))) {
                    best = m;
                    break;
                }
            }
            if (best == null)
                best = arr.get(0);
            JsonNode cvssData = best.get("cvssData");
            if (cvssData == null)
                continue;
            Double score = cvssData.has("baseScore") ? cvssData.get("baseScore").asDouble() : null;
            String sev = text(cvssData, "baseSeverity");
            if (sev == null)
                sev = text(best, "baseSeverity");
            return new CvssInfo(score, sev);
        }
        return new CvssInfo(null, null);
    }

    private String extractCvssVector(JsonNode cve) {
        JsonNode metrics = cve.get("metrics");
        if (metrics == null)
            return null;
        for (String key : new String[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" }) {
            JsonNode arr = metrics.get(key);
            if (arr != null && arr.isArray() && !arr.isEmpty()) {
                JsonNode best = null;
                for (JsonNode m : arr) {
                    if ("Primary".equals(text(m, "type"))) {
                        best = m;
                        break;
                    }
                }
                if (best == null)
                    best = arr.get(0);
                JsonNode cvssData = best.get("cvssData");
                if (cvssData != null)
                    return text(cvssData, "vectorString");
            }
        }
        return null;
    }

    // =========================================================================
    // Utilities
    // =========================================================================

    private String deriveSeverity(Double score) {
        if (score == null)
            return null;
        if (score >= 9.0)
            return "CRITICAL";
        if (score >= 7.0)
            return "HIGH";
        if (score >= 4.0)
            return "MEDIUM";
        return "LOW";
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String text(JsonNode node, String field) {
        JsonNode f = node.get(field);
        return (f != null && !f.isNull()) ? f.asText() : null;
    }

    private void emit(Consumer<String> logConsumer, String msg) {
        log.info(msg);
        if (logConsumer != null)
            logConsumer.accept(msg);
    }

    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
    }

    private record CvssInfo(Double score, String severity) {
    }

    private record CweInfo(String severity, String description) {
    }
}
