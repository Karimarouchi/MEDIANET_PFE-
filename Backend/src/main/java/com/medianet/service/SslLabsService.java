package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.File;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

/**
 * Calls the SSL Labs API v4 asynchronously for a given domain and writes
 * the parsed result to {@code ssl-labs-result.json} in the scan's results directory.
 *
 * Flow:
 *  1. Register once with SSL Labs (POST /register) — required by API v4.
 *  2. Kick off an assessment (GET /analyze?startNew=on).
 *  3. Poll every 5 s (first 3 attempts) then every 10 s until status = READY/ERROR.
 *  4. Parse the JSON response and write a flat summary file.
 */
@Service
public class SslLabsService {

    private static final String BASE_URL = "https://api.ssllabs.com/api/v4";
    private static final Logger log = LoggerFactory.getLogger(SslLabsService.class);

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

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();

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

    // ── Async analysis entry point ─────────────────────────────────────────────

    /**
     * Starts an SSL Labs assessment for {@code domain} in a background thread.
     * Writes {@code ssl-labs-result.json} into {@code resultsDir} as soon as
     * the assessment finishes (or on error/timeout).
     */
    @Async
    public void analyzeAsync(String domain, String resultsDir) {
        if (!enabled || email == null || email.isBlank()) {
            log.info("[SSLLabs] Disabled or no email configured — skipping external scan.");
            return;
        }

        File outFile = Path.of(resultsDir, "ssl-labs-result.json").toFile();

        // Write PENDING immediately so the frontend can show a spinner
        try {
            mapper.writeValue(outFile, Map.of("status", "PENDING", "grade", "?", "domain", domain));
        } catch (Exception ignored) { /* non-fatal */ }

        try {
            ensureRegistered();

            HttpHeaders h = new HttpHeaders();
            h.set("email", email);
            HttpEntity<Void> request = new HttpEntity<>(h);

            // ── 1. Start a new assessment ──────────────────────────────────
            String startUrl = UriComponentsBuilder.fromHttpUrl(BASE_URL + "/analyze")
                    .queryParam("host", domain)
                    .queryParam("startNew", "on")
                    .queryParam("all", "done")
                    .build().toUriString();
            restTemplate.exchange(startUrl, HttpMethod.GET, request, String.class);
            log.info("[SSLLabs] Assessment started for {}", domain);

            // ── 2. Poll until READY or ERROR ───────────────────────────────
            String pollUrl = UriComponentsBuilder.fromHttpUrl(BASE_URL + "/analyze")
                    .queryParam("host", domain)
                    .queryParam("all", "done")
                    .build().toUriString();

            // max 72 attempts ≈ 12 minutes (3×5s + 69×10s)
            for (int attempt = 0; attempt < 72; attempt++) {
                Thread.sleep(attempt < 3 ? 5_000L : 10_000L);

                ResponseEntity<String> resp =
                        restTemplate.exchange(pollUrl, HttpMethod.GET, request, String.class);
                JsonNode root = mapper.readTree(resp.getBody());
                String status = root.path("status").asText("IN_PROGRESS");
                log.info("[SSLLabs] {} → status={}", domain, status);

                if ("READY".equals(status) || "ERROR".equals(status)) {
                    Map<String, Object> parsed = parseResult(root, domain);
                    mapper.writeValue(outFile, parsed);
                    log.info("[SSLLabs] Result written for {} (grade={})", domain, parsed.get("grade"));
                    return;
                }
            }

            // Timed out
            mapper.writeValue(outFile, Map.of(
                    "status", "TIMEOUT", "grade", "?", "domain", domain,
                    "error", "SSL Labs did not finish within 12 minutes"
            ));

        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            log.warn("[SSLLabs] Thread interrupted for {}", domain);
        } catch (Exception e) {
            log.error("[SSLLabs] Analysis failed for {}: {}", domain, e.getMessage());
            try {
                mapper.writeValue(outFile, Map.of(
                        "status", "ERROR", "grade", "?", "domain", domain,
                        "error", e.getMessage() != null ? e.getMessage() : "unknown"
                ));
            } catch (Exception ignored) { /* non-fatal */ }
        }
    }

    // ── JSON parsing ───────────────────────────────────────────────────────────

    private Map<String, Object> parseResult(JsonNode root, String domain) {
        Map<String, Object> r = new HashMap<>();
        r.put("status", root.path("status").asText("READY"));
        r.put("domain", domain);

        // ── Endpoint (first one) ───────────────────────────────────────────
        JsonNode endpoints = root.path("endpoints");
        if (!endpoints.isEmpty()) {
            JsonNode ep = endpoints.get(0);
            r.put("grade", ep.path("grade").asText("?"));
            r.put("ipAddress", ep.path("ipAddress").asText(""));
            r.put("hasWarnings", ep.path("hasWarnings").asBoolean(false));
            r.put("statusMessage", ep.path("statusMessage").asText(""));

            JsonNode details = ep.path("details");
            if (!details.isMissingNode() && !details.isNull()) {
                // Protocol support
                boolean tls10 = false, tls11 = false, tls12 = false, tls13 = false;
                for (JsonNode proto : details.path("protocols")) {
                    String ver = proto.path("version").asText("");
                    if ("1.0".equals(ver)) tls10 = true;
                    if ("1.1".equals(ver)) tls11 = true;
                    if ("1.2".equals(ver)) tls12 = true;
                    if ("1.3".equals(ver)) tls13 = true;
                }
                r.put("tls10", tls10);
                r.put("tls11", tls11);
                r.put("tls12", tls12);
                r.put("tls13", tls13);

                // Vulnerabilities
                r.put("heartbleed",     details.path("heartbleed").asBoolean(false));
                r.put("poodle",         details.path("poodle").asBoolean(false));
                r.put("beast",          details.path("vulnBeast").asBoolean(false));
                r.put("freak",          details.path("freak").asBoolean(false));
                r.put("logjam",         details.path("logjam").asBoolean(false));
                r.put("drownVulnerable",details.path("drownVulnerable").asBoolean(false));
                r.put("rc4",            details.path("supportsRc4").asBoolean(false));
                // CRIME = TLS compression enabled (bit 0 of compressionMethods)
                r.put("crime",          (details.path("compressionMethods").asInt(0) & 1) != 0);
                // ROBOT = Bleichenbacher oracle (2=weak, 3=strong)
                int bleich = details.path("bleichenbacher").asInt(0);
                r.put("robot",          bleich == 2 || bleich == 3);
                // 3DES — approximated: if BEAST is true, 3DES was often the cipher used
                r.put("has3des",        tls10 && details.path("supportsCBC").asBoolean(false));
                // Forward Secrecy score ≥ 2 means modern clients can use FS
                r.put("forwardSecrecy", details.path("forwardSecrecy").asInt(0) >= 2);
                // OCSP Stapling
                r.put("ocspStapling",   details.path("ocspStapling").asBoolean(false));
                // HSTS (present in hstsPolicy.status)
                String hstsStatus = details.path("hstsPolicy").path("status").asText("");
                r.put("hsts", "present".equals(hstsStatus));
            }
        } else {
            r.put("grade", "?");
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
}
