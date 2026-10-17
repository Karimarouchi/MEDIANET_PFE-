package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.File;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Calls the SSL Labs API v4 asynchronously for a given domain and writes
 * the parsed result to {@code ssl-labs-result.json} in the scan's results directory.
 *
 * Flow:
 *  1. Register once with SSL Labs (POST /register) — required by API v4.
 *  2. Ask for an assessment, reusing one SSL Labs already ran in the last {@code ssllabs.max-age-hours}
 *     (fromCache/maxAge): a new assessment per click burns the SSL Labs quota and hits its rate limits.
 *  3. Poll every 5 s (first 3 attempts) then every 10 s until status = READY/ERROR, waiting out 429/503/529.
 *  4. Parse every endpoint (one per server IP) and write a flat summary file. The grade is the worst endpoint.
 */
@Service
public class SslLabsService {

    private static final String BASE_URL = "https://api.ssllabs.com/api/v4";
    private static final Logger log = LoggerFactory.getLogger(SslLabsService.class);
    private static final List<String> GRADE_ORDER = List.of("A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M");

    @Value("${ssllabs.email:}")
    private String email;

    @Value("${ssllabs.firstName:PFE}")
    private String firstName;

    @Value("${ssllabs.lastName:Medianet}")
    private String lastName;

    @Value("${ssllabs.organization:Medianet}")
    private String organization;

    @Value("${ssllabs.enabled:true}")
    private boolean enabled;

    /** Reuse an SSL Labs assessment younger than this (hours). 0 = always start a new one. */
    @Value("${ssllabs.max-age-hours:4}")
    private int maxAgeHours;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();
    private final Set<String> cancelled = ConcurrentHashMap.newKeySet();

    /** Guard so registration is attempted only once per application lifetime. */
    private volatile boolean registered = false;

    // ── Registration ───────────────────────────────────────────────────────────

    private synchronized void ensureRegistered() {
        if (registered) return;
        if (!enabled || email == null || email.isBlank()) {
            registered = true;
            return;
        }
        try {
            Map<String, String> body = Map.of(
                    "firstName", firstName,
                    "lastName", lastName,
                    "email", email,
                    "organization", organization
            );
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            String response = restTemplate.postForObject(
                    BASE_URL + "/register",
                    new HttpEntity<>(body, headers),
                    String.class
            );
            log.info("[SSLLabs] Registration response: {}", response);
        } catch (Exception e) {
            // 400/409 usually means "already registered" — safe to continue
            log.warn("[SSLLabs] Registration call: {} (continuing anyway)", e.getMessage());
        }
        registered = true;
    }

    /** Stops the polling loop of a scan's assessment (called when the user cancels the scan). */
    public void cancel(String resultsDir) {
        if (resultsDir != null) {
            cancelled.add(resultsDir);
        }
    }

    // ── Async analysis entry point ─────────────────────────────────────────────

    /**
     * Starts an SSL Labs assessment for {@code target} ("host" or "host:port") in a background thread.
     * Writes {@code ssl-labs-result.json} into {@code resultsDir} as soon as
     * the assessment finishes (or on error/timeout).
     */
    @Async
    public void analyzeAsync(String target, String resultsDir) {
        if (!enabled || email == null || email.isBlank()) {
            log.info("[SSLLabs] Disabled or no email configured — skipping external scan.");
            return;
        }

        File outFile = Path.of(resultsDir, "ssl-labs-result.json").toFile();
        SslTargetGuard.Target t;
        try {
            t = SslTargetGuard.normalize(target);
        } catch (Exception e) {
            write(outFile, Map.of("status", "ERROR", "grade", "?", "domain", String.valueOf(target),
                    "error", "Domaine invalide pour SSL Labs."));
            return;
        }
        String domain = t.host();
        if (t.port() != 443) {
            write(outFile, Map.of("status", "DISABLED", "grade", "?", "domain", domain,
                    "error", "SSL Labs ne teste que le port 443 : pas de note SSL Labs pour le port " + t.port() + "."));
            return;
        }

        // Write PENDING immediately so the frontend can show a spinner
        write(outFile, Map.of("status", "PENDING", "grade", "?", "domain", domain));

        try {
            ensureRegistered();

            HttpHeaders h = new HttpHeaders();
            h.set("email", email);
            HttpEntity<Void> request = new HttpEntity<>(h);

            // ── 1. Ask for an assessment (cached one when recent enough) ─────
            UriComponentsBuilder start = UriComponentsBuilder.fromHttpUrl(BASE_URL + "/analyze")
                    .queryParam("host", domain)
                    .queryParam("publish", "off")
                    .queryParam("all", "done");
            if (maxAgeHours > 0) {
                start.queryParam("fromCache", "on").queryParam("maxAge", maxAgeHours);
            } else {
                start.queryParam("startNew", "on");
            }
            JsonNode first = call(start.build().toUriString(), request, resultsDir);
            if (first != null && isFinal(first)) {
                finish(outFile, first, domain, true);
                return;
            }
            log.info("[SSLLabs] Assessment started for {}", domain);

            // ── 2. Poll until READY or ERROR ───────────────────────────────
            String pollUrl = UriComponentsBuilder.fromHttpUrl(BASE_URL + "/analyze")
                    .queryParam("host", domain)
                    .queryParam("publish", "off")
                    .queryParam("all", "done")
                    .build().toUriString();

            // max 72 attempts ≈ 12 minutes (3×5s + 69×10s)
            for (int attempt = 0; attempt < 72; attempt++) {
                Thread.sleep(attempt < 3 ? 5_000L : 10_000L);
                if (cancelled.remove(resultsDir)) {
                    log.info("[SSLLabs] {} cancelled by user", domain);
                    return;
                }
                JsonNode root = call(pollUrl, request, resultsDir);
                if (root == null) {
                    continue;
                }
                log.info("[SSLLabs] {} → status={}", domain, root.path("status").asText("IN_PROGRESS"));
                if (isFinal(root)) {
                    finish(outFile, root, domain, false);
                    return;
                }
            }

            // Timed out
            write(outFile, Map.of(
                    "status", "TIMEOUT", "grade", "?", "domain", domain,
                    "error", "SSL Labs n'a pas terminé en 12 minutes."
            ));

        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            log.warn("[SSLLabs] Thread interrupted for {}", domain);
            write(outFile, Map.of("status", "ERROR", "grade", "?", "domain", domain,
                    "error", "Analyse SSL Labs interrompue (arrêt du serveur)."));
        } catch (Exception e) {
            log.error("[SSLLabs] Analysis failed for {}: {}", domain, e.getMessage());
            write(outFile, Map.of(
                    "status", "ERROR", "grade", "?", "domain", domain,
                    "error", e.getMessage() != null ? e.getMessage() : "unknown"
            ));
        } finally {
            cancelled.remove(resultsDir);
        }
    }

    /**
     * One API call. On 429 (too many requests) or 503/529 (SSL Labs overloaded) waits and returns null so the
     * caller tries again; gives up after a few waits.
     */
    private JsonNode call(String url, HttpEntity<Void> request, String resultsDir) throws Exception {
        for (int wait = 0; wait < 6; wait++) {
            try {
                ResponseEntity<String> resp = restTemplate.exchange(url, HttpMethod.GET, request, String.class);
                return mapper.readTree(resp.getBody());
            } catch (HttpStatusCodeException e) {
                int code = e.getStatusCode().value();
                if (code == 429 || code == 503 || code == 529) {
                    log.warn("[SSLLabs] HTTP {} (rate limit / overloaded), waiting before retry", code);
                    Thread.sleep(30_000L + wait * 15_000L);
                    if (cancelled.contains(resultsDir)) {
                        return null;
                    }
                    continue;
                }
                throw new IllegalStateException("SSL Labs HTTP " + code + " : " + e.getResponseBodyAsString());
            }
        }
        throw new IllegalStateException("SSL Labs reste saturé (HTTP 429/503) : réessayez plus tard.");
    }

    private static boolean isFinal(JsonNode root) {
        String status = root.path("status").asText("");
        return "READY".equals(status) || "ERROR".equals(status);
    }

    private void finish(File outFile, JsonNode root, String domain, boolean firstCall) {
        Map<String, Object> parsed = parseResult(root, domain);
        // Cached when READY came back on the very first request (no assessment was started).
        parsed.put("fromCache", firstCall && "READY".equals(parsed.get("status")));
        write(outFile, parsed);
        log.info("[SSLLabs] Result written for {} (grade={}, cached={})", domain, parsed.get("grade"), parsed.get("fromCache"));
    }

    private void write(File f, Map<String, ?> content) {
        try {
            mapper.writeValue(f, content);
        } catch (Exception e) {
            log.warn("[SSLLabs] Could not write {}: {}", f, e.getMessage());
        }
    }

    // ── JSON parsing ───────────────────────────────────────────────────────────

    /**
     * Flattens an SSL Labs answer. A host can have several IPs (one "endpoint" each): protocols and flaws are
     * the union over endpoints, and the grade is the worst one, as on the SSL Labs site.
     */
    static Map<String, Object> parseResult(JsonNode root, String domain) {
        Map<String, Object> r = new HashMap<>();
        r.put("status", root.path("status").asText("READY"));
        r.put("domain", domain);
        if ("ERROR".equals(root.path("status").asText(""))) {
            r.put("error", root.path("statusMessage").asText("Erreur SSL Labs"));
        }
        long testTime = root.path("testTime").asLong(0);
        if (testTime > 0) {
            r.put("testTime", Instant.ofEpochMilli(testTime).toString());
        }

        boolean tls10 = false, tls11 = false, tls12 = false, tls13 = false;
        boolean heartbleed = false, poodle = false, beast = false, freak = false, logjam = false, drown = false;
        boolean rc4 = false, crime = false, robot = false, has3des = false, fsAll = true, fsKnown = false;
        boolean ocsp = false, hsts = false, warnings = false;
        String worst = null;
        String firstIp = "";
        String statusMessage = "";
        List<Map<String, Object>> endpoints = new ArrayList<>();

        for (JsonNode ep : root.path("endpoints")) {
            String grade = ep.path("grade").asText("");
            Map<String, Object> e = new LinkedHashMap<>();
            e.put("ipAddress", ep.path("ipAddress").asText(""));
            e.put("grade", grade.isBlank() ? "?" : grade);
            e.put("statusMessage", ep.path("statusMessage").asText(""));
            endpoints.add(e);
            if (firstIp.isEmpty()) {
                firstIp = ep.path("ipAddress").asText("");
                statusMessage = ep.path("statusMessage").asText("");
            }
            if (!grade.isBlank() && (worst == null || gradeRank(grade) > gradeRank(worst))) {
                worst = grade;
            }
            warnings |= ep.path("hasWarnings").asBoolean(false);

            JsonNode details = ep.path("details");
            if (details.isMissingNode() || details.isNull()) {
                continue;
            }
            for (JsonNode proto : details.path("protocols")) {
                String ver = proto.path("version").asText("");
                if ("1.0".equals(ver)) tls10 = true;
                if ("1.1".equals(ver)) tls11 = true;
                if ("1.2".equals(ver)) tls12 = true;
                if ("1.3".equals(ver)) tls13 = true;
            }
            heartbleed |= details.path("heartbleed").asBoolean(false);
            poodle |= details.path("poodle").asBoolean(false);
            beast |= details.path("vulnBeast").asBoolean(false);
            freak |= details.path("freak").asBoolean(false);
            logjam |= details.path("logjam").asBoolean(false);
            drown |= details.path("drownVulnerable").asBoolean(false);
            rc4 |= details.path("supportsRc4").asBoolean(false);
            // CRIME = TLS compression enabled (bit 0 of compressionMethods)
            crime |= (details.path("compressionMethods").asInt(0) & 1) != 0;
            // ROBOT = Bleichenbacher oracle (2=weak, 3=strong)
            int bleich = details.path("bleichenbacher").asInt(0);
            robot |= bleich == 2 || bleich == 3;
            has3des |= offers3des(details.path("suites"));
            if (details.has("forwardSecrecy")) {
                fsKnown = true;
                // Forward Secrecy score ≥ 2 means modern clients can use FS
                fsAll &= details.path("forwardSecrecy").asInt(0) >= 2;
            }
            ocsp |= details.path("ocspStapling").asBoolean(false);
            hsts |= "present".equals(details.path("hstsPolicy").path("status").asText(""));
        }

        r.put("grade", worst != null ? worst : "?");
        r.put("ipAddress", firstIp);
        r.put("statusMessage", statusMessage);
        r.put("hasWarnings", warnings);
        r.put("endpoints", endpoints);
        if (worst == null && !"ERROR".equals(r.get("status")) && !statusMessage.isBlank()) {
            r.put("error", statusMessage);
        }
        if (!endpoints.isEmpty()) {
            r.put("tls10", tls10);
            r.put("tls11", tls11);
            r.put("tls12", tls12);
            r.put("tls13", tls13);
            r.put("heartbleed", heartbleed);
            r.put("poodle", poodle);
            r.put("beast", beast);
            r.put("freak", freak);
            r.put("logjam", logjam);
            r.put("drownVulnerable", drown);
            r.put("rc4", rc4);
            r.put("crime", crime);
            r.put("robot", robot);
            r.put("has3des", has3des);
            r.put("forwardSecrecy", fsKnown && fsAll);
            r.put("ocspStapling", ocsp);
            r.put("hsts", hsts);
        }

        // ── Certificate chain (first cert) ────────────────────────────────
        JsonNode certs = root.path("certs");
        if (!certs.isEmpty()) {
            JsonNode cert = certs.get(0);
            long notAfterMs = cert.path("notAfter").asLong(0);
            if (notAfterMs > 0) {
                long daysLeft = (notAfterMs - System.currentTimeMillis()) / 86_400_000L;
                r.put("certDaysLeft", (int) daysLeft);
                r.put("certExpired",  daysLeft < 0);
            }
            r.put("certIssuer",       cert.path("issuerSubject").asText("unknown"));
            r.put("certSubject",      cert.path("subject").asText("unknown"));
            r.put("certSignatureAlg", cert.path("sigAlg").asText("unknown"));
            r.put("certKeySize",      String.valueOf(cert.path("keySize").asInt(0)));
            r.put("certTransparency", cert.path("sct").asBoolean(false));
            r.put("certEv",           "E".equals(cert.path("validationType").asText("")));
            r.put("certSansCount",    cert.path("altNames").size());
            // Chain issues: bit 1 = incomplete chain
            int chainIssues = cert.path("issues").asInt(0);
            r.put("chainComplete", (chainIssues & 2) == 0);
        }

        return r;
    }

    /** True when a suite list names a 3DES suite. Accepts the v4 shape (array per protocol) and the v3 one. */
    static boolean offers3des(JsonNode suites) {
        if (suites == null || suites.isMissingNode() || suites.isNull()) {
            return false;
        }
        List<JsonNode> lists = new ArrayList<>();
        if (suites.isArray()) {
            suites.forEach(s -> lists.add(s.path("list")));
        } else {
            lists.add(suites.path("list"));
        }
        for (JsonNode list : lists) {
            for (JsonNode suite : list) {
                String name = suite.path("name").asText("").toUpperCase(Locale.ROOT);
                if (name.contains("3DES") || name.contains("DES_CBC3") || name.contains("DES-CBC3")) {
                    return true;
                }
            }
        }
        return false;
    }

    static int gradeRank(String grade) {
        int i = GRADE_ORDER.indexOf(grade == null ? "" : grade.trim().toUpperCase(Locale.ROOT));
        return i < 0 ? -1 : i;
    }
}
