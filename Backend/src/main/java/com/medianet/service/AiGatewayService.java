package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

/**
 * Unified AI gateway: routes prompts to Gemini, Claude or OpenAI
 * depending on the user's personal AI settings.
 * Falls back to the system-default Gemini key if the user has no custom key.
 */
@Service
public class AiGatewayService {

    private static final Logger log = LoggerFactory.getLogger(AiGatewayService.class);

    @Value("${gemini.api.key}")
    private String defaultGeminiKey;

    @Value("${gemini.api.url}")
    private String defaultGeminiUrl; // e.g. https://.../{model}:generateContent

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Generate text using the user's configured AI provider, or the system default Gemini.
     *
     * @param prompt    the full prompt text
     * @param user      the authenticated user (may be null)
     * @return generated text, or null on failure
     */
    public String generate(String prompt, User user) {
        // Use user's personal key if fully configured
        if (user != null
                && user.getAiApiKey() != null && !user.getAiApiKey().isBlank()
                && user.getAiProvider() != null && !user.getAiProvider().isBlank()) {

            String provider = user.getAiProvider().toUpperCase();
            String model = user.getAiModel() != null && !user.getAiModel().isBlank()
                    ? user.getAiModel()
                    : defaultModelFor(provider);

            log.info("[AI] Using custom provider={} model={} for user={}", provider, model, user.getLogin());
            try {
                return switch (provider) {
                    case "CLAUDE" -> callClaude(prompt, user.getAiApiKey(), model);
                    case "OPENAI" -> callOpenAi(prompt, user.getAiApiKey(), model);
                    default -> callGemini(prompt, user.getAiApiKey(), buildGeminiUrl(model));
                };
            } catch (Exception e) {
                log.error("[AI] Custom provider {} failed, falling back to system default: {}", provider, e.getMessage());
            }
        }

        // System default: Gemini
        log.debug("[AI] Using system default Gemini");
        try {
            return callGemini(prompt, defaultGeminiKey, defaultGeminiUrl);
        } catch (Exception e) {
            log.error("[AI] System Gemini failed: {}", e.getMessage());
            return null;
        }
    }

    // ── Gemini ────────────────────────────────────────────────────────────────

    private String callGemini(String prompt, String apiKey, String url) throws Exception {
        Map<String, Object> textPart = Map.of("text", prompt);
        Map<String, Object> content = Map.of("parts", List.of(textPart));
        Map<String, Object> body = Map.of("contents", List.of(content));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String fullUrl = url.contains("?") ? url + "&key=" + apiKey : url + "?key=" + apiKey;

        ResponseEntity<String> response = restTemplate.exchange(
                fullUrl, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        return root.path("candidates").get(0)
                .path("content").path("parts").get(0)
                .path("text").asText();
    }

    // ── Claude (Anthropic) ────────────────────────────────────────────────────

    private String callClaude(String prompt, String apiKey, String model) throws Exception {
        Map<String, Object> message = Map.of("role", "user", "content", prompt);
        Map<String, Object> body = Map.of(
                "model", model,
                "max_tokens", 1024,
                "messages", List.of(message));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("x-api-key", apiKey);
        headers.set("anthropic-version", "2023-06-01");

        ResponseEntity<String> response = restTemplate.exchange(
                "https://api.anthropic.com/v1/messages",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        return root.path("content").get(0).path("text").asText();
    }

    // ── OpenAI ────────────────────────────────────────────────────────────────

    private String callOpenAi(String prompt, String apiKey, String model) throws Exception {
        Map<String, Object> message = Map.of("role", "user", "content", prompt);
        Map<String, Object> body = Map.of(
                "model", model,
                "messages", List.of(message));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey);

        ResponseEntity<String> response = restTemplate.exchange(
                "https://api.openai.com/v1/chat/completions",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        return root.path("choices").get(0).path("message").path("content").asText();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String defaultModelFor(String provider) {
        return switch (provider.toUpperCase()) {
            case "CLAUDE" -> "claude-opus-4-5";
            case "OPENAI" -> "gpt-4o";
            default -> "gemini-flash-latest";
        };
    }

    private String buildGeminiUrl(String model) {
        // Replace the model part of the default URL
        String base = defaultGeminiUrl;
        // defaultGeminiUrl = https://.../models/gemini-flash-latest:generateContent
        int modelsIdx = base.lastIndexOf("/models/");
        if (modelsIdx >= 0) {
            return base.substring(0, modelsIdx + "/models/".length()) + model + ":generateContent";
        }
        return base; // fallback: use as-is
    }
}
