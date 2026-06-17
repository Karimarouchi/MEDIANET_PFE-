package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.File;
import java.net.InetAddress;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
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

        if (apiKey == null || apiKey.isBlank()) {
            try {
                ObjectNode dis = mapper.createObjectNode();
                dis.put("status", "DISABLED");
                dis.put("grade", "?");
                mapper.writeValue(out, dis);
            } catch (Exception ignored) {}
            return;
        }

        try {
            // 1. Resolve domain → IP
            String host = domain.contains(":") ? domain.split(":")[0] : domain;
            String ip = InetAddress.getByName(host).getHostAddress();

            // 2. Call Censys API
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + apiKey);
            headers.set("Accept", "application/vnd.censys.api.v3.host.v1+json");

            HttpEntity<Void> req = new HttpEntity<>(headers);
            ResponseEntity<String> resp = restTemplate.exchange(
                    API_BASE + ip, HttpMethod.GET, req, String.class);

            if (resp.getStatusCode().value() != 200 || resp.getBody() == null) {
                throw new RuntimeException("Censys returned HTTP " + resp.getStatusCode().value());
            }

            JsonNode root = mapper.readTree(resp.getBody());
            JsonNode resource = root.path("result").path("resource");

            mapper.writeValue(out, parseResult(ip, resource));

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

    private ObjectNode parseResult(String ip, JsonNode resource) {
        ObjectNode node = mapper.createObjectNode();

        // Find port 443 service (HTTPS)
        JsonNode httpsService = null;
        List<Integer> openPorts = new ArrayList<>();

        for (JsonNode svc : resource.path("services")) {
            int port = svc.path("port").asInt(0);
            openPorts.add(port);
            if (port == 443 && httpsService == null) {
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
            node.put("status", "READY");
            node.put("grade", "F");
            node.put("ipAddress", ip);
            node.put("error", "No HTTPS/TLS service found on this host");
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
        int keyBits = parsed.path("subject_key_info").path("rsa").path("length").asInt(
                parsed.path("subject_key_info").path("ec").path("length").asInt(0));

        // Issuer / subject
        String issuerDn = parsed.path("issuer_dn").asText(parsed.path("issuer").path("organization").path(0).asText("unknown"));
        String subjectDn = parsed.path("subject_dn").asText(parsed.path("subject").path("common_name").path(0).asText("unknown"));

        // Validation level: ev / ov / dv
        String validationLevel = cert.path("validation_level").asText("dv").toUpperCase();

        // Certificate Transparency
        boolean ctPresent = !cert.path("ct").path("entries").isEmpty();

        // SANs count
        int sansCount = cert.path("names").size();

        // ── Grade logic ──────────────────────────────────────────────
        // F: expired or no valid cert
        // D: < 7 days or cert invalid
        // C: < 30 days or key < 2048
        // B: < 90 days or no CT
        // A: valid, ≥ 90 days, key ≥ 2048, CT present
        // A+: valid, ≥ 90 days, key ≥ 2048, CT, EV cert
        String grade;
        if (expired || !certValid) {
            grade = "F";
        } else if (daysLeft < 7) {
            grade = "D";
        } else if (daysLeft < 30 || (keyBits > 0 && keyBits < 2048)) {
            grade = "C";
        } else if (daysLeft < 90 || !ctPresent) {
            grade = "B";
        } else if ("EV".equals(validationLevel)) {
            grade = "A+";
        } else {
            grade = "A";
        }

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
}
