package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Translates text from English to French using the MyMemory free API.
 * No API key required (up to 10 000 chars/day per IP).
 * Configure {@code translation.email} to raise the limit to 100 000 chars/day.
 */
@Service
public class TranslationService {

    private static final Logger log = LoggerFactory.getLogger(TranslationService.class);
    private static final String MYMEMORY_URL = "https://api.mymemory.translated.net/get";

    /** MyMemory hard limit per single request */
    private static final int MAX_CHUNK = 450;

    @Value("${translation.enabled:true}")
    private boolean enabled;

    /**
     * Optional contact e-mail sent to MyMemory to raise the daily quota
     * (10 000 → 100 000 chars/day). Leave empty to use the anonymous quota.
     */
    @Value("${translation.email:}")
    private String email;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Translates {@code text} from English to French.
     *
     * @return French text, or {@code null} if translation is disabled or failed.
     */
    public String translateToFrench(String text) {
        if (!enabled || text == null || text.isBlank())
            return null;

        try {
            if (text.length() <= MAX_CHUNK) {
                return callMyMemory(text);
            }
            return translateChunked(text);
        } catch (Exception e) {
            log.warn("TranslationService error: {}", e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------

    /** Split long text at word boundaries and translate chunk by chunk. */
    private String translateChunked(String text) {
        StringBuilder result = new StringBuilder();
        int start = 0;

        while (start < text.length()) {
            int end = Math.min(start + MAX_CHUNK, text.length());
            if (end < text.length()) {
                int lastSpace = text.lastIndexOf(' ', end);
                if (lastSpace > start)
                    end = lastSpace;
            }

            String chunk = text.substring(start, end).trim();
            String translated = callMyMemory(chunk);
            if (translated == null)
                return null; // abort on failure

            if (!result.isEmpty())
                result.append(' ');
            result.append(translated);
            start = end;

            // Small pause between chunks to respect rate limits
            try {
                Thread.sleep(300);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        return result.isEmpty() ? null : result.toString();
    }

    /** Single MyMemory API call. Returns null on any failure. */
    private String callMyMemory(String text) {
        try {
            String encoded = URLEncoder.encode(text, StandardCharsets.UTF_8);
            StringBuilder url = new StringBuilder(MYMEMORY_URL)
                    .append("?q=").append(encoded)
                    .append("&langpair=en|fr");

            if (!email.isBlank()) {
                url.append("&de=").append(URLEncoder.encode(email, StandardCharsets.UTF_8));
            }

            ResponseEntity<String> response = restTemplate.getForEntity(url.toString(), String.class);
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null)
                return null;

            JsonNode root = mapper.readTree(response.getBody());
            int status = root.has("responseStatus") ? root.get("responseStatus").asInt() : 0;
            if (status != 200) {
                log.debug("MyMemory returned status {} for text snippet", status);
                return null;
            }

            JsonNode data = root.get("responseData");
            if (data == null)
                return null;

            String translated = text(data, "translatedText");
            // Guard: MyMemory sometimes echoes error messages as translatedText
            if (translated == null || translated.toUpperCase().startsWith("PLEASE SELECT"))
                return null;

            return translated;

        } catch (Exception e) {
            log.warn("MyMemory call failed: {}", e.getMessage());
            return null;
        }
    }

    private String text(JsonNode node, String field) {
        JsonNode f = node.get(field);
        return (f != null && !f.isNull()) ? f.asText() : null;
    }
}
