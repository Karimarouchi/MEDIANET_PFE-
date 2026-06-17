package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

/**
 * Calls Google Gemini to generate an AI assessment of an SSL/TLS configuration.
 * Accepts a context map (domain, grades, detected vulns, protocols, cert info, headers)
 * and returns { summary, keyRisks[], recommendations[] }.
 */
@Service
public class SslAiService {

    private static final Logger log = LoggerFactory.getLogger(SslAiService.class);

    @Value("${gemini.api.key}")
    private String geminiApiKey;

    @Value("${gemini.api.url}")
    private String geminiApiUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public Map<String, Object> analyze(Map<String, Object> ctx) {

        String prompt = buildPrompt(ctx);

        try {
            Map<String, Object> textPart = Map.of("text", prompt);
            Map<String, Object> content  = Map.of("parts", List.of(textPart));
            Map<String, Object> body     = Map.of("contents", List.of(content));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            String url = geminiApiUrl + "?key=" + geminiApiKey;

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);

            JsonNode root = objectMapper.readTree(response.getBody());
            String text = root.path("candidates").get(0)
                    .path("content").path("parts").get(0)
                    .path("text").asText().trim();

            // Strip markdown code fences if present
            if (text.startsWith("```")) {
                text = text.replaceAll("```(?:json)?\\n?", "").replaceAll("```", "").trim();
            }

            JsonNode parsed = objectMapper.readTree(text);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("summary", parsed.path("summary").asText(""));

            List<String> risks = new ArrayList<>();
            parsed.path("keyRisks").forEach(n -> risks.add(n.asText()));
            result.put("keyRisks", risks);

            List<String> recs = new ArrayList<>();
            parsed.path("recommendations").forEach(n -> recs.add(n.asText()));
            result.put("recommendations", recs);

            return result;

        } catch (Exception e) {
            log.error("[SslAi] Gemini call failed: {}", e.getMessage());
            Map<String, Object> fallback = new LinkedHashMap<>();
            fallback.put("summary", null);
            fallback.put("keyRisks", List.of());
            fallback.put("recommendations", List.of());
            return fallback;
        }
    }

    private String buildPrompt(Map<String, Object> ctx) {
        return "Tu es un expert en cybersécurité SSL/TLS. Analyse cette configuration SSL et génère une analyse structurée.\n\n"
             + "Domaine analysé : " + ctx.getOrDefault("domain", "inconnu") + "\n"
             + "Grades par source :\n"
             + "  - Kali Linux (scan interne) : " + ctx.getOrDefault("kaliGrade", "?") + "\n"
             + "  - SSL Labs              : " + ctx.getOrDefault("ssllabsGrade", "N/A") + "\n"
             + "  - Censys               : " + ctx.getOrDefault("censysGrade", "N/A") + "\n"
             + "  - SSLyze               : " + ctx.getOrDefault("sslyzeGrade", "N/A") + "\n"
             + "Vulnérabilités SSL/TLS détectées : " + ctx.getOrDefault("detectedVulns", "aucune") + "\n"
             + "Protocoles actifs : " + ctx.getOrDefault("activeProtocols", "inconnus") + "\n"
             + "Certificat valide : " + ctx.getOrDefault("certValid", true) + "\n"
             + "Jours avant expiration du certificat : " + ctx.getOrDefault("certDaysLeft", -1) + "\n"
             + "En-têtes de sécurité HTTP présents : " + ctx.getOrDefault("headers", "aucun") + "\n\n"
             + "Réponds UNIQUEMENT avec un objet JSON valide (pas de markdown, pas de ```) dans ce format EXACT :\n"
             + "{\n"
             + "  \"summary\": \"résumé exécutif de 3-4 phrases en français, clair et actionnable\",\n"
             + "  \"keyRisks\": [\"risque principal 1\", \"risque principal 2\", \"risque principal 3\"],\n"
             + "  \"recommendations\": [\"action prioritaire 1\", \"action prioritaire 2\", \"action prioritaire 3\", \"action prioritaire 4\"]\n"
             + "}";
    }
}
