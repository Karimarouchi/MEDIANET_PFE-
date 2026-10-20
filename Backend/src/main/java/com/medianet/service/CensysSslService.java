package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.net.InetAddress;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Calls the Censys Platform API v3 to retrieve TLS/certificate data for a domain.
 * Endpoint: GET https://api.platform.censys.io/v3/global/asset/host/{ip}
 *
 * Extracts from port 443 service: cert validity, issuer, key size, CT, validation level.
 * Writes result to {resultsDir}/censys-result.json
 */
@Service
public class CensysSslService {

    private static final String API_BASE = "https://api.platform.censys.io/v3/global/asset/host/";

    // Censys v2 API: https://search.censys.io/api → My Account → API
    // App ID  = censys.api.id   (e.g. "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
    // Secret  = censys.api.secret
    // Authentication = Basic Auth (Base64 of "<id>:<secret>")
    @Value("${censys.api.id:}")
    private String apiId;

    @Value("${censys.api.secret:}")
    private String apiSecret;

    // Legacy single-key fallback (Platform API token — may be unsupported)
    @Value("${censys.api.key:}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();

    @Async
    public void analyzeAsync(String domain, String resultsDir) {
        File out = Path.of(resultsDir, "censys-result.json").toFile();

        // Write PENDING immediately
        try {
            ObjectNode pending = mapper.createObjectNode();
            pending.put("status", "PENDING");
            pending.put("grade", "?");
            mapper.writeValue(out, pending);
        } catch (Exception ignored) {}

        // Check credentials: prefer apiId+apiSecret (v2), fallback to apiKey (Platform)
        boolean hasV2Creds = apiId != null && !apiId.isBlank() && apiSecret != null && !apiSecret.isBlank();
        boolean hasV1Key   = apiKey != null && !apiKey.isBlank();

        if (!hasV2Creds && !hasV1Key) {
            try {
                ObjectNode dis = mapper.createObjectNode();
                dis.put("status", "DISABLED");
                dis.put("grade", "?");
                dis.put("error", "Censys API credentials not configured");
                mapper.writeValue(out, dis);
            } catch (Exception ignored) {}
            return;
        }

        try {
            // 1. Resolve domain → IP
            SslTargetGuard.Target target = SslTargetGuard.normalize(domain);
            String ip = InetAddress.getByName(target.host()).getHostAddress();

            // 2. Call Censys API with proper auth + endpoint
            HttpHeaders headers = new HttpHeaders();
            String censysUrl;

            if (hasV2Creds) {
                // Search API v2: Basic Auth (App ID + Secret)
                String credentials = apiId + ":" + apiSecret;
                String encoded = Base64.getEncoder().encodeToString(credentials.getBytes());
                headers.set("Authorization", "Basic " + encoded);
                headers.set("Accept", "application/json");
                censysUrl = "https://search.censys.io/api/v2/hosts/" + ip;
            } else {
                // Platform API v3: Bearer Personal Access Token
                headers.set("Authorization", "Bearer " + apiKey);
                headers.set("Accept", "application/vnd.censys.api.v3.host.v1+json");
                censysUrl = API_BASE + ip;
            }

            HttpEntity<Void> req = new HttpEntity<>(headers);
            ResponseEntity<String> resp;
            try {
                resp = restTemplate.exchange(censysUrl, HttpMethod.GET, req, String.class);
            } catch (HttpClientErrorException ex) {
                throw new RuntimeException("Censys HTTP " + ex.getStatusCode().value()
                        + ": " + ex.getResponseBodyAsString());
            }

            if (resp.getStatusCode().value() != 200 || resp.getBody() == null) {
                throw new RuntimeException("Censys returned HTTP " + resp.getStatusCode().value());
            }

            JsonNode root = mapper.readTree(resp.getBody());
            // Platform v3 response: { "result": { "resource": { "services": [...] } } }
            // Search v2 response:   { "result": { "services": [...] } }
            JsonNode resultNode = root.path("result");
            JsonNode resource = resultNode.has("resource") ? resultNode.path("resource") : resultNode;

            mapper.writeValue(out, parseResult(ip, resource, target.port()));

        } catch (Exception e) {
            try {
                ObjectNode err = mapper.createObjectNode();
                err.put("status", "ERROR");
                err.put("grade", "?");
                err.put("error", e.getMessage() != null ? e.getMessage() : "Request failed");
                mapper.writeValue(out, err);
            } catch (Exception ignored) {}
        }
    }

    ObjectNode parseResult(String ip, JsonNode resource, int port) {
        ObjectNode node = mapper.createObjectNode();

        // Find the service on the scanned port
        JsonNode httpsService = null;
        List<Integer> openPorts = new ArrayList<>();

        for (JsonNode svc : resource.path("services")) {
            int svcPort = svc.path("port").asInt(0);
            openPorts.add(svcPort);
            if (svcPort == port && httpsService == null) {
                httpsService = svc;
            }
        }
        // If no port 443, try any TLS service
        if (httpsService == null) {
            for (JsonNode svc : resource.path("services")) {
                if (!svc.path("cert").isMissingNode()) {
                    httpsService = svc;
                    break;
                }
            }
        }

        if (httpsService == null) {
            // Censys works from an Internet index that can be days old: no indexed service is "no data", not F.
            node.put("status", "NO_DATA");
            node.put("grade", "?");
            node.put("ipAddress", ip);
            node.put("error", "Censys n'a indexé aucun service TLS pour cette IP (index parfois en retard de plusieurs jours).");
            node.put("openPorts", openPorts.toString());
            return node;
        }

        JsonNode cert = httpsService.path("cert");
        JsonNode parsed = cert.path("parsed");

        // Expiry
        String notAfterStr = parsed.path("validity_period").path("not_after").asText("");
        String notBeforeStr = parsed.path("validity_period").path("not_before").asText("");
        int daysLeft = -1;
        boolean expired = false;
        if (!notAfterStr.isBlank()) {
            try {
                Instant expiry = Instant.parse(notAfterStr);
                daysLeft = (int) Instant.now().until(expiry, ChronoUnit.DAYS);
                expired = daysLeft < 0;
            } catch (Exception ignored) {}
        }

        // Cert validity
        boolean certValid = cert.path("validation").path("nss").path("is_valid").asBoolean(false);

        // Key info
        String keyAlg = parsed.path("subject_key_info").path("key_algorithm").path("name").asText("RSA");
        int keyBits = keyBits(parsed.path("subject_key_info"));

        // Issuer / subject
        String issuerDn = parsed.path("issuer_dn").asText(parsed.path("issuer").path("organization").path(0).asText("unknown"));
        String subjectDn = parsed.path("subject_dn").asText(parsed.path("subject").path("common_name").path(0).asText("unknown"));

        // Validation level: ev / ov / dv
        String validationLevel = cert.path("validation_level").asText("dv").toUpperCase();

        // Certificate Transparency: the Platform v3 host view no longer carries it. Unknown is not a penalty.
        Boolean ctPresent = cert.has("ct") ? !cert.path("ct").path("entries").isEmpty() : null;

        // SANs count
        int sansCount = cert.path("names").size();

        String grade = certificateGrade(expired, certValid, daysLeft, keyAlg, keyBits, ctPresent);

        node.put("status", "READY");
        node.put("grade", grade);
        node.put("ipAddress", ip);
        node.put("issuer", issuerDn);
        node.put("subject", subjectDn);
        node.put("notBefore", notBeforeStr);
        node.put("notAfter", notAfterStr);
        node.put("daysLeft", daysLeft);
        node.put("expired", expired);
        node.put("certValid", certValid);
        node.put("keyAlgorithm", keyAlg);
        node.put("keySize", keyBits > 0 ? String.valueOf(keyBits) : "unknown");
        node.put("validationLevel", validationLevel);
        node.put("ctPresent", ctPresent);
        node.put("sansCount", sansCount);
        node.put("openPorts", openPorts.stream().map(String::valueOf).reduce((a, b) -> a + ", " + b).orElse(""));
        return node;
    }

    /**
     * Censys only sees the certificate, so its grade is a certificate grade:
     * F expired or not trusted; D under 7 days left; C under 14 days or an RSA key under 2048 bits;
     * B without Certificate Transparency; A otherwise.
     * Not penalised: a 90-day certificate (Let's Encrypt renews at 30 days left), and DV vs EV, which says who
     * the owner is, not how secure the connection is.
     */
    static String certificateGrade(boolean expired, boolean certValid, int daysLeft, String keyAlg, int keyBits,
            Boolean ctPresent) {
        boolean rsa = keyAlg == null || keyAlg.toUpperCase(java.util.Locale.ROOT).contains("RSA");
        if (expired || !certValid) {
            return "F";
        }
        if (daysLeft >= 0 && daysLeft < 7) {
            return "D";
        }
        if ((daysLeft >= 0 && daysLeft < 14) || (rsa && keyBits > 0 && keyBits < 2048)) {
            return "C";
        }
        return Boolean.FALSE.equals(ctPresent) ? "B" : "A";
    }

    /** Key size: v2 gives "length"; Platform v3 gives only the RSA modulus (hex) and the EC curve. */
    static int keyBits(JsonNode keyInfo) {
        int rsaLength = keyInfo.path("rsa").path("length").asInt(0);
        if (rsaLength > 0) return rsaLength;
        String modulus = keyInfo.path("rsa").path("modulus").asText("").replaceFirst("^(00)+", "");
        if (!modulus.isEmpty()) return modulus.length() * 4;
        int ecLength = keyInfo.path("ec").path("length").asInt(0);
        if (ecLength > 0) return ecLength;
        String curve = keyInfo.path("ecdsa").path("curve").asText(keyInfo.path("ec").path("curve").asText(""));
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("(\\d{3})").matcher(curve);
        return m.find() ? Integer.parseInt(m.group(1)) : 0;
    }
}
