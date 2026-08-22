package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.AssistantStatusDto;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unified AI gateway: routes prompts to Gemini, Claude, OpenAI or Grok
 * depending on the user's personal AI / chatbot settings.
 * Falls back to the system-default Gemini key if the user has no custom key.
 */
@Service
public class AiGatewayService {

    private static final Logger log = LoggerFactory.getLogger(AiGatewayService.class);

    @Value("${gemini.api.key}")
    private String defaultGeminiKey;

    @Value("${gemini.api.url}")
    private String defaultGeminiUrl; // e.g. https://.../{model}:generateContent

    @Value("${gemini.chat.api.key:}")
    private String chatGeminiKey;

    @Value("${gemini.chat.api.url:https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent}")
    private String chatGeminiUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ConcurrentHashMap<String, CachedChatStatus> chatStatusCache = new ConcurrentHashMap<>();

    private record CachedChatStatus(AssistantStatusDto status, long expiresAtMillis) {
        boolean fresh() {
            return System.currentTimeMillis() < expiresAtMillis;
        }
    }

    /**
     * Verify that a personal API key works with the given provider/model
     * by sending a tiny live request. Throws IllegalArgumentException with a French message on failure.
     */
    public void verifyApiKey(String provider, String model, String apiKey) {
        if (provider == null || provider.isBlank()) {
            throw new IllegalArgumentException("Le provider IA est requis.");
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("La clé API est requise.");
        }
        String p = provider.trim().toUpperCase();
        String key = apiKey.trim();
        String m = (model != null && !model.isBlank()) ? model.trim() : defaultModelFor(p);
        String ping = "Réponds uniquement par OK.";

        try {
            String reply = switch (p) {
                case "CLAUDE" -> callClaude(ping, key, m, 16);
                case "OPENAI" -> callOpenAi(ping, key, m, 8);
                case "GROK" -> callGrok(ping, key, m, 8);
                case "GEMINI" -> callGemini(ping, key, buildGeminiUrl(m));
                default -> throw new IllegalArgumentException(
                        "Provider IA non supporté : " + provider + ". Utilisez GEMINI, CLAUDE, OPENAI ou GROK.");
            };
            if (reply == null || reply.isBlank()) {
                throw new IllegalArgumentException(
                        "La clé a répondu sans contenu. Vérifiez le modèle (« " + m + " ») et réessayez.");
            }
            log.info("[AI] Key verified OK for provider={} model={}", p, m);
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            throw new IllegalArgumentException(friendlyHttpError(p, m, e));
        } catch (Exception e) {
            String msg = e.getMessage() != null ? e.getMessage() : "erreur inconnue";
            throw new IllegalArgumentException(
                    "Impossible de vérifier la clé " + p + " : " + msg);
        }
    }

    private String friendlyHttpError(String provider, String model,
            org.springframework.web.client.HttpStatusCodeException e) {
        int code = e.getStatusCode().value();
        String body = e.getResponseBodyAsString();
        String bodyLower = body != null ? body.toLowerCase() : "";
        log.warn("[AI] Key verify failed provider={} model={} HTTP {} body={}",
                provider, model, code, body != null && body.length() > 300 ? body.substring(0, 300) : body);

        if (code == 401 || code == 403
                || bodyLower.contains("invalid api key")
                || bodyLower.contains("incorrect api key")
                || bodyLower.contains("api key not valid")
                || bodyLower.contains("authentication")
                || bodyLower.contains("unauthorized")
                || bodyLower.contains("permission denied")) {
            return "Clé API " + provider + " invalide ou non autorisée. Vérifiez la clé et réessayez.";
        }
        if (code == 404
                || bodyLower.contains("model_not_found")
                || bodyLower.contains("not_found")
                || bodyLower.contains("does not exist")) {
            return "Modèle « " + model + " » introuvable pour " + provider
                    + ". Choisissez un modèle valide puis réessayez.";
        }
        if (code == 429
                || bodyLower.contains("rate limit")
                || bodyLower.contains("quota")
                || bodyLower.contains("resource_exhausted")) {
            return "Quota / rate-limit " + provider + " dépassé. Attendez un peu ou vérifiez votre plan, puis réessayez.";
        }
        if (code >= 500) {
            return "Le service " + provider + " est temporairement indisponible (HTTP " + code
                    + "). Réessayez dans quelques instants.";
        }
        return "Échec de vérification de la clé " + provider + " (HTTP " + code
                + "). La clé n'a pas été enregistrée.";
    }

    /**
     * Generate text using the user's configured AI provider, or the system default Gemini.
     *
     * @param prompt    the full prompt text
     * @param user      the authenticated user (may be null)
     * @return generated text, or null on failure
     */
    public String generate(String prompt, User user) {
        return generateInternal(prompt, user, true, 1024);
    }

    /**
     * Chatbot: user chat key + provider (Gemini, OpenAI, Claude, Grok) if set,
     * else {@code GEMINI_CHAT_API_KEY}, else the app {@code GEMINI_API_KEY}.
     */
    public String generateChat(String prompt, User user) {
        String custom = tryUserChat(prompt, user);
        if (custom != null && !custom.isBlank()) {
            rememberChatStatus(user, true, "IA en ligne, tokens disponibles.");
            return custom;
        }
        String cheap = tryCheapSystemChat(prompt);
        if (cheap != null && !cheap.isBlank()) {
            rememberChatStatus(user, true, "IA en ligne, tokens disponibles.");
            return cheap;
        }
        log.warn("[AI] Chat cheap model empty, falling back to app Gemini (same path as CVE summaries)");
        String fallback = generate(prompt, user);
        if (fallback != null && !fallback.isBlank()) {
            rememberChatStatus(user, true, "Clé système Gemini");
        } else {
            rememberChatStatus(user, false, "IA indisponible ou plus de tokens.");
        }
        return fallback;
    }

    /**
     * Point vert/rouge du widget : ping très court (quelques tokens), mis en cache
     * pour ne pas brûler le quota à chaque ouverture du chat.
     */
    public AssistantStatusDto probeChatStatus(User user) {
        String cacheKey = chatStatusCacheKey(user);
        CachedChatStatus cached = chatStatusCache.get(cacheKey);
        if (cached != null && cached.fresh()) {
            return cached.status();
        }
        AssistantStatusDto status = pingChatProvider(user);
        rememberStatus(cacheKey, status);
        return status;
    }

    public void rememberChatStatus(User user, boolean available, String detail) {
        AssistantStatusDto status = AssistantStatusDto.builder()
                .available(available)
                .provider(resolveChatProviderLabel(user))
                .detail(detail)
                .build();
        rememberStatus(chatStatusCacheKey(user), status);
    }

    private void rememberStatus(String cacheKey, AssistantStatusDto status) {
        long ttl = status.isAvailable() ? 90_000L : 25_000L;
        chatStatusCache.put(cacheKey, new CachedChatStatus(status, System.currentTimeMillis() + ttl));
    }

    private String chatStatusCacheKey(User user) {
        return (user != null && user.getId() != null ? user.getId() : 0L)
                + ":" + resolveChatProviderLabel(user);
    }

    private String resolveChatProviderLabel(User user) {
        if (user != null && user.getChatAiApiKey() != null && !user.getChatAiApiKey().isBlank()) {
            return user.getChatAiProvider() != null && !user.getChatAiProvider().isBlank()
                    ? user.getChatAiProvider().toUpperCase()
                    : "GEMINI";
        }
        return "SYSTEM";
    }

    private AssistantStatusDto pingChatProvider(User user) {
        String ping = "Réponds uniquement par OK.";
        String provider = resolveChatProviderLabel(user);
        try {
            String reply;
            if (user != null && user.getChatAiApiKey() != null && !user.getChatAiApiKey().isBlank()) {
                String model = user.getChatAiModel() != null && !user.getChatAiModel().isBlank()
                        ? user.getChatAiModel()
                        : defaultChatModelFor(provider);
                String key = user.getChatAiApiKey();
                reply = switch (provider) {
                    case "CLAUDE" -> callClaude(ping, key, model, 16);
                    case "OPENAI" -> callOpenAi(ping, key, model, 8);
                    case "GROK" -> callGrok(ping, key, model, 8);
                    default -> invokeGeminiPing(ping, key, model);
                };
            } else {
                String key = (chatGeminiKey != null && !chatGeminiKey.isBlank()) ? chatGeminiKey : defaultGeminiKey;
                if (key == null || key.isBlank()) {
                    return AssistantStatusDto.builder()
                            .available(false)
                            .provider(provider)
                            .detail("Aucune clé chatbot configurée.")
                            .build();
                }
                String url = (chatGeminiUrl != null && !chatGeminiUrl.isBlank()) ? chatGeminiUrl : defaultGeminiUrl;
                boolean disableThinking = url.contains("2.5") || url.contains("flash-latest");
                reply = callGeminiOnce(ping, key, url, false, 16, disableThinking);
            }
            boolean ok = reply != null && !reply.isBlank();
            return AssistantStatusDto.builder()
                    .available(ok)
                    .provider(provider)
                    .detail(ok ? "IA en ligne, tokens disponibles." : "Le provider a répondu vide.")
                    .build();
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            return AssistantStatusDto.builder()
                    .available(false)
                    .provider(provider)
                    .detail(friendlyHttpError(provider, "chat", e))
                    .build();
        } catch (Exception e) {
            return AssistantStatusDto.builder()
                    .available(false)
                    .provider(provider)
                    .detail("IA injoignable : " + (e.getMessage() != null ? e.getMessage() : "erreur inconnue"))
                    .build();
        }
    }

    private String invokeGeminiPing(String prompt, String key, String model) throws Exception {
        String url = buildGeminiUrl(model);
        boolean disableThinking = url.contains("2.5") || url.contains("flash-latest");
        return callGeminiOnce(prompt, key, url, false, 16, disableThinking);
    }

    private String tryUserChat(String prompt, User user) {
        if (user == null || user.getChatAiApiKey() == null || user.getChatAiApiKey().isBlank()) {
            return null;
        }
        String provider = user.getChatAiProvider() != null && !user.getChatAiProvider().isBlank()
                ? user.getChatAiProvider().toUpperCase()
                : "GEMINI";
        String model = user.getChatAiModel() != null && !user.getChatAiModel().isBlank()
                ? user.getChatAiModel()
                : defaultChatModelFor(provider);
        String key = user.getChatAiApiKey();
        log.info("[AI] Chat using custom provider={} model={} for user={}", provider, model, user.getLogin());
        try {
            return switch (provider) {
                case "CLAUDE" -> callClaude(prompt, key, model, 512);
                case "OPENAI" -> callOpenAi(prompt, key, model, 512);
                case "GROK" -> callGrok(prompt, key, model, 512);
                default -> invokeGeminiChat(prompt, key, model);
            };
        } catch (Exception e) {
            log.warn("[AI] User chat provider {} failed: {}", provider, e.getMessage());
            return null;
        }
    }

    private String invokeGeminiChat(String prompt, String key, String model) throws Exception {
        String url = buildGeminiUrl(model);
        boolean disableThinking = url.contains("2.5") || url.contains("flash-latest");
        String text = callGeminiOnce(prompt, key, url, false, 512, disableThinking);
        if (text != null && !text.isBlank()) {
            return text;
        }
        return callGeminiOnce(prompt, key, url, true, 512, disableThinking);
    }

    private String tryCheapSystemChat(String prompt) {
        String key = (chatGeminiKey != null && !chatGeminiKey.isBlank()) ? chatGeminiKey : defaultGeminiKey;
        String url = (chatGeminiUrl != null && !chatGeminiUrl.isBlank()) ? chatGeminiUrl : defaultGeminiUrl;
        if (key == null || key.isBlank()) {
            return null;
        }
        boolean disableThinking = url.contains("2.5") || url.contains("flash-latest");
        try {
            String text = callGeminiOnce(prompt, key, url, false, 512, disableThinking);
            if (text != null && !text.isBlank()) {
                return text;
            }
            return callGeminiOnce(prompt, key, url, true, 512, disableThinking);
        } catch (Exception e) {
            log.warn("[AI] Cheap chat Gemini failed: {}", e.getMessage());
            return null;
        }
    }

    private String generateInternal(String prompt, User user, boolean jsonMime, int claudeMaxTokens) {
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
                    case "CLAUDE" -> callClaude(prompt, user.getAiApiKey(), model, claudeMaxTokens);
                    case "OPENAI" -> callOpenAi(prompt, user.getAiApiKey(), model, jsonMime ? null : claudeMaxTokens);
                    case "GROK" -> callGrok(prompt, user.getAiApiKey(), model, jsonMime ? null : claudeMaxTokens);
                    default -> invokeGemini(prompt, user.getAiApiKey(), buildGeminiUrl(model), jsonMime);
                };
            } catch (org.springframework.web.client.HttpStatusCodeException e) {
                log.error("[AI] Custom provider {} failed (HTTP {}): {}, falling back to system default", provider, e.getStatusCode(), e.getResponseBodyAsString());
            } catch (Exception e) {
                log.error("[AI] Custom provider {} failed, falling back to system default: {}", provider, e.getMessage());
            }
        }

        log.debug("[AI] Using system default Gemini");
        try {
            return invokeGemini(prompt, defaultGeminiKey, defaultGeminiUrl, jsonMime);
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            log.error("[AI] System Gemini failed (HTTP {}): {}", e.getStatusCode(), e.getResponseBodyAsString());
            return null;
        } catch (Exception e) {
            log.error("[AI] System Gemini failed: {}", e.getMessage());
            return null;
        }
    }

    private String invokeGemini(String prompt, String apiKey, String url, boolean jsonMime) throws Exception {
        if (jsonMime) {
            return callGemini(prompt, apiKey, url);
        }
        String text = callGeminiOnce(prompt, apiKey, url, false);
        if (text != null && !text.isBlank()) {
            return text;
        }
        throw new IllegalStateException("Réponse Gemini vide");
    }

    // ── Gemini ────────────────────────────────────────────────────────────────

    private String callGemini(String prompt, String apiKey, String url) throws Exception {
        String text = callGeminiOnce(prompt, apiKey, url, true);
        if (text != null && !text.isBlank()) return text;
        // Certains modèles renvoient vide avec responseMimeType=json → retry sans contrainte
        text = callGeminiOnce(prompt, apiKey, url, false);
        if (text != null && !text.isBlank()) return text;
        throw new IllegalStateException("Réponse Gemini vide");
    }

    private String callGeminiOnce(String prompt, String apiKey, String url, boolean jsonMime) throws Exception {
        return callGeminiOnce(prompt, apiKey, url, jsonMime, 8192, false);
    }

    private String callGeminiOnce(String prompt, String apiKey, String url, boolean jsonMime,
            int maxOutputTokens, boolean disableThinking) throws Exception {
        Map<String, Object> textPart = Map.of("text", prompt);
        Map<String, Object> content = Map.of("parts", List.of(textPart));
        Map<String, Object> generationConfig = new LinkedHashMap<>();
        generationConfig.put("temperature", 0.2);
        generationConfig.put("maxOutputTokens", maxOutputTokens);
        if (disableThinking) {
            generationConfig.put("thinkingConfig", Map.of("thinkingBudget", 0));
        }
        if (jsonMime) {
            generationConfig.put("responseMimeType", "application/json");
        }
        Map<String, Object> body = Map.of(
                "contents", List.of(content),
                "generationConfig", generationConfig);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String fullUrl = url.contains("?") ? url + "&key=" + apiKey : url + "?key=" + apiKey;

        ResponseEntity<String> response = restTemplate.exchange(
                fullUrl, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        JsonNode candidates = root.path("candidates");
        if (!candidates.isArray() || candidates.isEmpty()) {
            String block = root.path("promptFeedback").path("blockReason").asText("");
            log.warn("[AI] Gemini sans candidates blockReason={} bodySnippet={}",
                    block,
                    response.getBody() != null && response.getBody().length() > 400
                            ? response.getBody().substring(0, 400) : response.getBody());
            return null;
        }
        JsonNode parts = candidates.get(0).path("content").path("parts");
        if (!parts.isArray() || parts.isEmpty()) {
            // MAX_TOKENS / safety parfois sans parts — tenter texte brut ailleurs
            String finish = candidates.get(0).path("finishReason").asText("");
            log.warn("[AI] Gemini parts vides finishReason={}", finish);
            return null;
        }
        StringBuilder sb = new StringBuilder();
        for (JsonNode part : parts) {
            String t = part.path("text").asText("");
            if (!t.isBlank()) sb.append(t);
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    // ── Claude (Anthropic) ────────────────────────────────────────────────────

    private String callClaude(String prompt, String apiKey, String model, int maxTokens) throws Exception {
        Map<String, Object> message = Map.of("role", "user", "content", prompt);
        Map<String, Object> body = Map.of(
                "model", model,
                "max_tokens", maxTokens,
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

    private String callOpenAi(String prompt, String apiKey, String model, Integer maxTokens) throws Exception {
        return callOpenAiCompatible("https://api.openai.com/v1/chat/completions", prompt, apiKey, model, maxTokens);
    }

    private String callGrok(String prompt, String apiKey, String model, Integer maxTokens) throws Exception {
        return callOpenAiCompatible("https://api.x.ai/v1/chat/completions", prompt, apiKey, model, maxTokens);
    }

    private String callOpenAiCompatible(String url, String prompt, String apiKey, String model, Integer maxTokens)
            throws Exception {
        Map<String, Object> message = Map.of("role", "user", "content", prompt);
        Map<String, Object> body;
        if (maxTokens != null) {
            body = Map.of(
                    "model", model,
                    "max_tokens", maxTokens,
                    "messages", List.of(message));
        } else {
            body = Map.of(
                    "model", model,
                    "messages", List.of(message));
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey);

        ResponseEntity<String> response = restTemplate.exchange(
                url, HttpMethod.POST, new HttpEntity<>(body, headers), String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        return root.path("choices").get(0).path("message").path("content").asText();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String defaultModelFor(String provider) {
        return switch (provider.toUpperCase()) {
            case "CLAUDE" -> "claude-3-opus-20240229";
            case "OPENAI" -> "gpt-4o";
            case "GROK" -> "grok-3-mini";
            default -> "gemini-flash-latest";
        };
    }

    private String defaultChatModelFor(String provider) {
        return switch (provider.toUpperCase()) {
            case "CLAUDE" -> "claude-3-5-haiku-20241022";
            case "OPENAI" -> "gpt-4o-mini";
            case "GROK" -> "grok-3-mini";
            default -> "gemini-2.0-flash";
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
