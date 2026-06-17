package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.CveDto;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class GeminiSummaryService {

    private static final Logger log = LoggerFactory.getLogger(GeminiSummaryService.class);

    @Value("${gemini.api.key}")
    private String geminiApiKey;

    @Value("${gemini.api.url}")
    private String geminiApiUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Generates a concise executive summary of the scan results using Gemini AI.
     * Returns null on failure (frontend will display a computed fallback).
     */
    public String generateScanSummary(List<CveDto> cves) {
        if (cves == null || cves.isEmpty()) {
            return "Aucune vulnérabilité détectée dans ce scan.";
        }

        long critical = cves.stream().filter(c -> "CRITICAL".equals(c.getSeverity())).count();
        long high = cves.stream().filter(c -> "HIGH".equals(c.getSeverity())).count();
        long medium = cves.stream().filter(c -> "MEDIUM".equals(c.getSeverity())).count();
        long low = cves.stream().filter(c -> "LOW".equals(c.getSeverity())).count();
        long withExploit = cves.stream().filter(CveDto::isExploitAvailable).count();
        long kevListed = cves.stream().filter(CveDto::isKevListed).count();

        String topCves = cves.stream()
                .filter(c -> "CRITICAL".equals(c.getSeverity()) || "HIGH".equals(c.getSeverity()))
                .limit(5)
                .map(c -> String.format("- %s (%s, CVSS %.1f) dans %s",
                        c.getCveId() != null ? c.getCveId() : "N/A",
                        c.getSeverity(),
                        c.getCvssScore() != null ? c.getCvssScore() : 0.0,
                        c.getPackageName() != null ? c.getPackageName() : "inconnu"))
                .collect(Collectors.joining("\n"));

        String prompt = "Tu es un expert en cybersécurité. Analyse ces résultats de scan de sécurité et génère un résumé exécutif concis en français (5-7 lignes maximum).\n\n"
                +
                "Statistiques du scan :\n" +
                "- Total : " + cves.size() + " vulnérabilités\n" +
                "- CRITICAL : " + critical + " | HIGH : " + high + " | MEDIUM : " + medium + " | LOW : " + low + "\n" +
                "- Avec exploit public : " + withExploit + "\n" +
                "- Dans le catalogue CISA KEV (exploitées activement) : " + kevListed + "\n" +
                "Top vulnérabilités critiques :\n" + topCves + "\n\n" +
                "Génère un résumé clair et actionnable pour un responsable sécurité. " +
                "Utilise des phrases courtes. Termine par une recommandation prioritaire. " +
                "Ne liste pas toutes les CVEs, donne une vue d'ensemble. " +
                "Réponds uniquement en français, sans markdown, sans titres, juste le texte du résumé.";

        try {
            Map<String, Object> textPart = Map.of("text", prompt);
            Map<String, Object> content = Map.of("parts", List.of(textPart));
            Map<String, Object> requestBody = Map.of("contents", List.of(content));

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            String url = geminiApiUrl + "?key=" + geminiApiKey;

            HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, headers);
            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);

            JsonNode root = objectMapper.readTree(response.getBody());
            return root.path("candidates").get(0)
                    .path("content").path("parts").get(0)
                    .path("text").asText();

        } catch (Exception e) {
            log.error("[GeminiSummary] Failed to generate summary: {}", e.getMessage());
            return null;
        }
    }
}
