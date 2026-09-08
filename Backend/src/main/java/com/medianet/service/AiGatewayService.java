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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Unified AI gateway: routes prompts to Gemini, Claude, OpenAI, Grok (xAI) or Groq
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

    @Value("${gemini.chat.api.url:https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent}")
    private String chatGeminiUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private static final ObjectMapper ERROR_JSON = new ObjectMapper();
    private final ConcurrentHashMap<String, CachedChatStatus> chatStatusCache = new ConcurrentHashMap<>();

    private record CachedChatStatus(AssistantStatusDto status, long expiresAtMillis) {
        boolean fresh() {
            return System.currentTimeMillis() < expiresAtMillis;
        }
    }

    /**
     * Verify that a personal API key works with the given provider/model
     * by sending a tiny live request. Returns the model that actually answered
     * (xAI keys are not bound to a model — we pick a live one if needed).
     */
    public String verifyApiKey(String provider, String model, String apiKey) {
        if (provider == null || provider.isBlank()) {
            throw new IllegalArgumentException("Le provider IA est requis.");
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalArgumentException("La clé API est requise.");
        }
        String p = provider.trim().toUpperCase();
        String key = sanitizeApiKey(apiKey);
        String requested = (model != null && !model.isBlank()) ? model.trim() : null;
        if ("GROK".equals(p)) {
            return verifyGrokKey(key, requested);
        }
        if ("GROQ".equals(p)) {
            return verifyGroqKey(key, requested);
        }
        if ("GEMINI".equals(p)) {
            return verifyGeminiKey(key, requested);
        }
        String m = requested != null ? requested : defaultModelFor(p);
        String ping = "Réponds uniquement par OK.";

        try {
            String reply = switch (p) {
                case "CLAUDE" -> callClaude(ping, key, m, 16);
                case "OPENAI" -> callOpenAi(ping, key, m, 8);
                default -> throw new IllegalArgumentException(
                        "Provider IA non supporté : " + provider
                                + ". Utilisez GEMINI, CLAUDE, OPENAI, GROK ou GROQ.");
            };
            if (reply == null || reply.isBlank()) {
                throw new IllegalArgumentException(
                        "La clé a répondu sans contenu. Vérifiez le modèle (« " + m + " ») et réessayez.");
            }
            log.info("[AI] Key verified OK for provider={} model={}", p, m);
            return m;
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

    /**
     * A Grok key from console.x.ai is not tied to a model. Try the requested id,
     * then current chat models, then whatever GET /v1/models returns.
     */
    private String verifyGrokKey(String apiKey, String requestedModel) {
        Set<String> candidates = new LinkedHashSet<>();
        if (requestedModel != null && !requestedModel.isBlank()) {
            candidates.add(requestedModel.trim());
        }
        candidates.addAll(List.of("grok-4.6", "grok-4.5", "grok-4.3", "grok-4"));
        candidates.addAll(listGrokChatModels(apiKey));

        org.springframework.web.client.HttpStatusCodeException lastHttp = null;
        for (String candidate : candidates) {
            try {
                String reply = callGrok("Réponds uniquement par OK.", apiKey, candidate, 8);
                if (reply != null && !reply.isBlank()) {
                    log.info("[AI] Key verified OK for provider=GROK model={}", candidate);
                    return candidate;
                }
            } catch (org.springframework.web.client.HttpStatusCodeException e) {
                int code = e.getStatusCode().value();
                lastHttp = e;
                // 401 = clé vraiment fausse. 403 = souvent crédits / permission modèle, on essaie le suivant.
                if (code == 401) {
                    throw new IllegalArgumentException(friendlyHttpError("GROK", candidate, e));
                }
                log.warn("[AI] Grok model {} rejected (HTTP {}), trying next", candidate, code);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                log.warn("[AI] Grok model {} failed: {}", candidate, e.getMessage());
            }
        }
        if (lastHttp != null) {
            throw new IllegalArgumentException(
                    "La clé Grok n'est pas liée à un modèle (console.x.ai ne donne que la clé). "
                            + "« " + (requestedModel != null ? requestedModel : "grok-2-latest")
                            + " » n'est plus servi. Laisse le modèle vide : on utilisera grok-4.6. "
                            + friendlyHttpError("GROK", requestedModel, lastHttp));
        }
        throw new IllegalArgumentException(
                "Impossible de vérifier la clé GROK. Laisse le modèle vide pour utiliser grok-4.6.");
    }

    /**
     * A Groq console key (gsk_…) is not bound to a model. Try the requested id,
     * then current production chat models, then GET /openai/v1/models.
     */
    private String verifyGroqKey(String apiKey, String requestedModel) {
        Set<String> candidates = new LinkedHashSet<>();
        if (requestedModel != null && !requestedModel.isBlank()) {
            candidates.add(requestedModel.trim());
        }
        candidates.addAll(List.of(
                "openai/gpt-oss-20b",
                "openai/gpt-oss-120b",
                "qwen/qwen3.8-27b",
                "qwen/qwen3.6-27b",
                "llama-3.3-70b-versatile",
                "llama-3.1-8b-instant"));
        candidates.addAll(listGroqChatModels(apiKey));

        org.springframework.web.client.HttpStatusCodeException lastHttp = null;
        for (String candidate : candidates) {
            try {
                String reply = callGroq("Réponds uniquement par OK.", apiKey, candidate, 64);
                if (reply != null && !reply.isBlank()) {
                    log.info("[AI] Key verified OK for provider=GROQ model={}", candidate);
                    return candidate;
                }
            } catch (org.springframework.web.client.HttpStatusCodeException e) {
                int code = e.getStatusCode().value();
                lastHttp = e;
                if (code == 401) {
                    throw new IllegalArgumentException(friendlyHttpError("GROQ", candidate, e));
                }
                log.warn("[AI] Groq model {} rejected (HTTP {}), trying next", candidate, code);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                log.warn("[AI] Groq model {} failed: {}", candidate, e.getMessage());
            }
        }
        if (lastHttp != null) {
            throw new IllegalArgumentException(
                    "La clé Groq n'est pas liée à un modèle (console.groq.com donne seulement gsk_…). "
                            + "Laisse le modèle vide : on utilisera openai/gpt-oss-20b. "
                            + friendlyHttpError("GROQ", requestedModel, lastHttp));
        }
        throw new IllegalArgumentException(
                "Impossible de vérifier la clé GROQ. Laisse le modèle vide pour openai/gpt-oss-20b.");
    }

    /**
     * An AI Studio / Gemini key is not tied to a model. Try the requested id,
     * then official aliases, then GET /v1beta/models.
     */
    private String verifyGeminiKey(String apiKey, String requestedModel) {
        Set<String> candidates = new LinkedHashSet<>();
        // AI Studio never binds a key to a model — always try official aliases,
        // even if the user typed a chip that no longer exists.
        candidates.addAll(List.of(
                "gemini-flash-latest",
                "gemini-3.7-flash",
                "gemini-3.6-flash",
                "gemini-3.5-flash",
                "gemini-3.5-flash-lite",
                "gemini-2.5-flash"));
        if (requestedModel != null && !requestedModel.isBlank()) {
            candidates.add(requestedModel.trim());
        }
        candidates.addAll(listGeminiChatModels(apiKey));

        org.springframework.web.client.HttpStatusCodeException lastHttp = null;
        Exception lastError = null;
        for (String candidate : candidates) {
            try {
                String reply = callGeminiOnce("Réponds uniquement par OK.", apiKey,
                        publicGeminiUrl(candidate), false, 16, true);
                if (reply != null && !reply.isBlank()) {
                    log.info("[AI] Key verified OK for provider=GEMINI model={}", candidate);
                    return candidate;
                }
            } catch (org.springframework.web.client.HttpStatusCodeException e) {
                int code = e.getStatusCode().value();
                lastHttp = e;
                if (isFatalGeminiAuthError(e)) {
                    throw new IllegalArgumentException(friendlyHttpError("GEMINI", candidate, e));
                }
                log.warn("[AI] Gemini model {} rejected (HTTP {}), trying next", candidate, code);
            } catch (IllegalArgumentException e) {
                throw e;
            } catch (Exception e) {
                lastError = e;
                log.warn("[AI] Gemini model {} failed: {}", candidate, e.getMessage());
            }
        }
        if (lastHttp != null) {
            throw new IllegalArgumentException(
                    "Google AI Studio ne lie pas la clé à un modèle. Laisse « Auto » : "
                            + "on teste gemini-flash-latest puis les Flash 3.x. "
                            + friendlyHttpError("GEMINI", requestedModel, lastHttp));
        }
        String extra = lastError != null && lastError.getMessage() != null ? lastError.getMessage() : "";
        throw new IllegalArgumentException(
                "Impossible de vérifier la clé GEMINI. Laisse le modèle sur Auto. " + extra);
    }

    static boolean isFatalGeminiAuthError(org.springframework.web.client.HttpStatusCodeException e) {
        int code = e.getStatusCode().value();
        String body = e.getResponseBodyAsString();
        String lower = body != null ? body.toLowerCase() : "";
        if (code == 401) {
            return true;
        }
        return lower.contains("api key not valid")
                || lower.contains("api_key_invalid")
                || lower.contains("invalid api key")
                || lower.contains("access_token_type_unsupported")
                || lower.contains("has not been used")
                || lower.contains("is disabled")
                || lower.contains("referer")
                || lower.contains("android apps")
                || lower.contains("ios apps")
                || lower.contains("ip address");
    }

    private String publicGeminiUrl(String model) {
        String id = model == null ? "gemini-flash-latest" : model.trim();
        if (id.startsWith("models/")) {
            id = id.substring("models/".length());
        }
        if (id.isBlank()) {
            id = "gemini-flash-latest";
        }
        return "https://generativelanguage.googleapis.com/v1beta/models/" + id + ":generateContent";
    }

    /** Classic AI Studio keys (AIza…). New 2026 keys (AQ.…) must not go in ?key=. */
    static boolean isClassicGoogleAiKey(String apiKey) {
        return apiKey != null && apiKey.startsWith("AIza");
    }

    private HttpHeaders geminiAuthHeaders(String apiKey, boolean jsonContent) {
        HttpHeaders headers = new HttpHeaders();
        if (jsonContent) {
            headers.setContentType(MediaType.APPLICATION_JSON);
        }
        headers.set("x-goog-api-key", apiKey);
        return headers;
    }

    private String geminiUrlWithKey(String url, String apiKey) {
        if (!isClassicGoogleAiKey(apiKey)) {
            return url;
        }
        String encoded = java.net.URLEncoder.encode(apiKey, java.nio.charset.StandardCharsets.UTF_8);
        return url.contains("?") ? url + "&key=" + encoded : url + "?key=" + encoded;
    }

    static String extractGoogleErrorMessage(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            JsonNode message = ERROR_JSON.readTree(body).path("error").path("message");
            String text = message.asText("");
            return text.isBlank() ? null : text;
        } catch (Exception e) {
            return null;
        }
    }

    private List<String> listGeminiChatModels(String apiKey) {
        try {
            String url = geminiUrlWithKey("https://generativelanguage.googleapis.com/v1beta/models", apiKey);
            HttpHeaders headers = geminiAuthHeaders(apiKey, false);
            ResponseEntity<String> response = restTemplate.exchange(
                    url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
            JsonNode models = objectMapper.readTree(response.getBody()).path("models");
            List<String> ids = new ArrayList<>();
            if (models.isArray()) {
                for (JsonNode node : models) {
                    String name = node.path("name").asText("");
                    String id = name.startsWith("models/") ? name.substring("models/".length()) : name;
                    if (!isGeminiChatModelId(id)) {
                        continue;
                    }
                    JsonNode methods = node.path("supportedGenerationMethods");
                    boolean canGenerate = !methods.isArray();
                    if (methods.isArray()) {
                        for (JsonNode method : methods) {
                            if ("generateContent".equalsIgnoreCase(method.asText())) {
                                canGenerate = true;
                                break;
                            }
                        }
                    }
                    if (canGenerate) {
                        ids.add(id);
                    }
                }
            }
            return ids;
        } catch (Exception e) {
            log.warn("[AI] Could not list Gemini models: {}", e.getMessage());
            return List.of();
        }
    }

    private boolean isGeminiChatModelId(String id) {
        if (id == null || !id.toLowerCase().startsWith("gemini-")) {
            return false;
        }
        String lower = id.toLowerCase();
        return !lower.contains("image")
                && !lower.contains("tts")
                && !lower.contains("live")
                && !lower.contains("veo")
                && !lower.contains("embed")
                && !lower.contains("imagen")
                && !lower.contains("robotics")
                && !lower.contains("computer-use");
    }

    private List<String> listGrokChatModels(String apiKey) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(apiKey);
            ResponseEntity<String> response = restTemplate.exchange(
                    "https://api.x.ai/v1/models",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class);
            JsonNode data = objectMapper.readTree(response.getBody()).path("data");
            List<String> ids = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    String id = node.path("id").asText("");
                    if (isGrokChatModelId(id)) {
                        ids.add(id);
                    }
                }
            }
            return ids;
        } catch (Exception e) {
            log.warn("[AI] Could not list Grok models: {}", e.getMessage());
            return List.of();
        }
    }

    private boolean isGrokChatModelId(String id) {
        if (id == null || !id.startsWith("grok-")) {
            return false;
        }
        String lower = id.toLowerCase();
        return !lower.contains("imagine")
                && !lower.contains("image")
                && !lower.contains("video")
                && !lower.contains("voice")
                && !lower.contains("tts")
                && !lower.contains("stt");
    }

    private String friendlyHttpError(String provider, String model,
            org.springframework.web.client.HttpStatusCodeException e) {
        int code = e.getStatusCode().value();
        String body = e.getResponseBodyAsString();
        log.warn("[AI] Key verify failed provider={} model={} HTTP {} body={}",
                provider, model, code, body != null && body.length() > 300 ? body.substring(0, 300) : body);
        return describeKeyError(provider, model, code, body);
    }

    static String describeKeyError(String provider, String model, int code, String body) {
        String bodyLower = body != null ? body.toLowerCase() : "";
        boolean grok = "GROK".equalsIgnoreCase(provider);
        boolean groq = "GROQ".equalsIgnoreCase(provider);
        boolean gemini = "GEMINI".equalsIgnoreCase(provider);

        if (bodyLower.contains("credit")
                || bodyLower.contains("billing")
                || bodyLower.contains("subscription")
                || bodyLower.contains("spend limit")
                || bodyLower.contains("out of credits")) {
            if (grok) {
                return "La clé GROK est reconnue, mais le compte n'a plus de crédits. "
                        + "Ajoute des crédits sur https://console.x.ai (Credits) puis réessaie.";
            }
            if (groq) {
                return "La clé GROQ est reconnue, mais le quota / crédits Groq bloquent l'appel. "
                        + "Vérifie https://console.groq.com (Limits / billing) puis réessaie.";
            }
            if (gemini) {
                return "La clé GEMINI est reconnue, mais le quota / facturation Google bloque l'appel. "
                        + "Vérifie AI Studio → usage / billing, puis réessaie.";
            }
            return "La clé " + provider + " est reconnue, mais le compte n'a plus de crédits.";
        }
        if (code == 401
                || bodyLower.contains("invalid api key")
                || bodyLower.contains("incorrect api key")
                || bodyLower.contains("api key not valid")
                || bodyLower.contains("access_token_type_unsupported")
                || bodyLower.contains("unauthenticated")) {
            if (gemini) {
                String google = extractGoogleErrorMessage(body);
                return "Clé GEMINI non acceptée par Google. Les nouvelles clés AQ.… doivent être envoyées "
                        + "via l'en-tête x-goog-api-key (Vulnix le fait déjà). "
                        + "Recrée une clé dans AI Studio, restreinte à l'API Gemini, sans filtre HTTP/IP. "
                        + (google != null ? "Google : " + google : "");
            }
            return "Clé API " + provider + " invalide. Recopie-la depuis la console (sans espace ni saut de ligne).";
        }
        if (code == 403 || bodyLower.contains("permission denied") || bodyLower.contains("forbidden")) {
            if (gemini) {
                String google = extractGoogleErrorMessage(body);
                if (bodyLower.contains("consumer_suspended") || bodyLower.contains("has been suspended")) {
                    return "Clé GEMINI refusée : Google a suspendu ce projet / cette clé "
                            + "(CONSUMER_SUSPENDED). Ce n'est pas Auto ni le nom du modèle. "
                            + "Dans AI Studio : crée un nouveau projet (ou réactive la facturation), "
                            + "puis une nouvelle clé restreinte à l'API Gemini, sans filtre HTTP/IP. "
                            + (google != null ? "Google : " + google : "");
                }
                return "Clé GEMINI refusée (HTTP 403) — ce n'est pas le nom du modèle (Auto). "
                        + "Depuis juin 2026 Google refuse les clés sans restriction API. "
                        + "Dans AI Studio / Google Cloud → identifiants : restreins la clé à « Gemini API » "
                        + "(generativelanguage.googleapis.com), SANS restriction HTTP ni IP "
                        + "(le serveur Vulnix n'envoie pas de referer). "
                        + "Les clés AQ.… doivent partir en en-tête, pas en ?key=. "
                        + (google != null ? "Google : " + google : "");
            }
            if (grok) {
                return "Clé GROK refusée (HTTP 403). Sur console.x.ai : crédits > 0, "
                        + "et la clé a le droit « API ». Ce n'est pas un problème de nom de modèle.";
            }
            if (groq) {
                return "Clé GROQ refusée (HTTP 403). Sur console.groq.com : clé gsk_… active, "
                        + "sans restriction IP trop serrée. Groq n'est pas Grok (xAI).";
            }
            return "Clé " + provider + " refusée (HTTP 403). Vérifie les droits de la clé dans la console du provider.";
        }
        if (code == 404
                || bodyLower.contains("model_not_found")
                || bodyLower.contains("invalid model")
                || bodyLower.contains("not_found")
                || bodyLower.contains("does not exist")) {
            if ("GROK".equalsIgnoreCase(provider)) {
                return "Modèle Grok « " + model + " » inconnu ou retiré (ex. grok-2-latest). "
                        + "La clé xAI n'est pas liée à un modèle : laisse vide pour grok-4.6.";
            }
            if (groq) {
                return "Modèle Groq « " + model + " » inconnu ou retiré (ex. llama-3.3-70b-versatile). "
                        + "Laisse le modèle vide : Vulnix choisit openai/gpt-oss-20b.";
            }
            if ("GEMINI".equalsIgnoreCase(provider)) {
                return "Modèle Gemini « " + model + " » inconnu ou retiré. "
                        + "Laisse le modèle sur Auto : Vulnix choisit gemini-flash-latest.";
            }
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
     * Chatbot: user chat key + provider (Gemini, OpenAI, Claude, Grok, Groq) if set,
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
                    case "GROQ" -> callGroq(ping, key, model, 64);
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
                case "CLAUDE" -> callClaude(prompt, key, model, 360);
                case "OPENAI" -> callOpenAi(prompt, key, model, 360);
                case "GROK" -> callGrok(prompt, key, model, 360);
                case "GROQ" -> callGroq(prompt, key, model, 360);
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
        String text = callGeminiOnce(prompt, key, url, false, 320, disableThinking);
        if (text != null && !text.isBlank()) {
            return text;
        }
        return callGeminiOnce(prompt, key, url, true, 320, disableThinking);
    }

    private String tryCheapSystemChat(String prompt) {
        String key = (chatGeminiKey != null && !chatGeminiKey.isBlank()) ? chatGeminiKey : defaultGeminiKey;
        String url = (chatGeminiUrl != null && !chatGeminiUrl.isBlank()) ? chatGeminiUrl : defaultGeminiUrl;
        if (key == null || key.isBlank()) {
            return null;
        }
        boolean disableThinking = url.contains("2.5") || url.contains("flash-latest");
        try {
            String text = callGeminiOnce(prompt, key, url, false, 320, disableThinking);
            if (text != null && !text.isBlank()) {
                return text;
            }
            return callGeminiOnce(prompt, key, url, true, 320, disableThinking);
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
                    case "GROQ" -> callGroq(prompt, user.getAiApiKey(), model, jsonMime ? null : claudeMaxTokens);
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

        HttpHeaders headers = geminiAuthHeaders(apiKey, true);
        String fullUrl = geminiUrlWithKey(url, apiKey);

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

    private String callGroq(String prompt, String apiKey, String model, Integer maxTokens) throws Exception {
        Map<String, Object> message = Map.of("role", "user", "content", prompt);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", model);
        body.put("messages", List.of(message));
        if (maxTokens != null) {
            // gpt-oss and newer Groq models reject OpenAI's legacy max_tokens.
            body.put("max_completion_tokens", maxTokens);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(sanitizeApiKey(apiKey));

        ResponseEntity<String> response = restTemplate.exchange(
                "https://api.groq.com/openai/v1/chat/completions",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);

        JsonNode root = objectMapper.readTree(response.getBody());
        JsonNode choices = root.path("choices");
        if (!choices.isArray() || choices.isEmpty()) {
            return null;
        }
        String content = choices.get(0).path("message").path("content").asText("");
        if (content.isBlank()) {
            content = choices.get(0).path("message").path("reasoning").asText("");
        }
        return content.isBlank() ? null : content;
    }

    private List<String> listGroqChatModels(String apiKey) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(sanitizeApiKey(apiKey));
            ResponseEntity<String> response = restTemplate.exchange(
                    "https://api.groq.com/openai/v1/models",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class);
            JsonNode data = objectMapper.readTree(response.getBody()).path("data");
            List<String> ids = new ArrayList<>();
            if (data.isArray()) {
                for (JsonNode node : data) {
                    String id = node.path("id").asText("");
                    if (isGroqChatModelId(id)) {
                        ids.add(id);
                    }
                }
            }
            return ids;
        } catch (Exception e) {
            log.warn("[AI] Could not list Groq models: {}", e.getMessage());
            return List.of();
        }
    }

    private boolean isGroqChatModelId(String id) {
        if (id == null || id.isBlank()) {
            return false;
        }
        String lower = id.toLowerCase();
        return !lower.contains("whisper")
                && !lower.contains("tts")
                && !lower.contains("guard")
                && !lower.contains("playai")
                && !lower.contains("distil")
                && !lower.contains("orpheus");
    }

    private String callGrok(String prompt, String apiKey, String model, Integer maxTokens) throws Exception {
        String key = sanitizeApiKey(apiKey);
        try {
            return callGrokResponses(prompt, key, model, maxTokens);
        } catch (org.springframework.web.client.HttpStatusCodeException responsesError) {
            int code = responsesError.getStatusCode().value();
            if (code == 401) {
                throw responsesError;
            }
            try {
                return callOpenAiCompatible(
                        "https://api.x.ai/v1/chat/completions", prompt, key, model, null);
            } catch (org.springframework.web.client.HttpStatusCodeException chatError) {
                throw responsesError.getStatusCode().value() >= 400 ? responsesError : chatError;
            }
        }
    }

    /** Current xAI docs: POST /v1/responses is the primary chat endpoint (chat/completions is legacy). */
    private String callGrokResponses(String prompt, String apiKey, String model, Integer maxTokens) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("model", model);
        body.put("input", prompt);
        body.put("store", false);
        if (maxTokens != null && maxTokens > 0) {
            body.put("max_output_tokens", maxTokens);
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(apiKey);

        ResponseEntity<String> response = restTemplate.exchange(
                "https://api.x.ai/v1/responses",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class);
        return extractGrokResponsesText(objectMapper.readTree(response.getBody()));
    }

    private String extractGrokResponsesText(JsonNode root) {
        if (root == null) {
            return null;
        }
        String direct = root.path("output_text").asText("");
        if (!direct.isBlank()) {
            return direct;
        }
        StringBuilder sb = new StringBuilder();
        JsonNode output = root.path("output");
        if (output.isArray()) {
            for (JsonNode item : output) {
                JsonNode content = item.path("content");
                if (content.isArray()) {
                    for (JsonNode part : content) {
                        String t = part.path("text").asText("");
                        if (!t.isBlank()) {
                            sb.append(t);
                        }
                    }
                }
            }
        }
        if (sb.length() == 0) {
            JsonNode choices = root.path("choices");
            if (choices.isArray() && !choices.isEmpty()) {
                String t = choices.get(0).path("message").path("content").asText("");
                return t.isBlank() ? null : t;
            }
        }
        return sb.length() == 0 ? null : sb.toString();
    }

    private String sanitizeApiKey(String apiKey) {
        if (apiKey == null) {
            return "";
        }
        return apiKey.replace("\u00a0", " ").replaceAll("[\\r\\n\\t ]", "").trim();
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
            case "GROK" -> "grok-4.6";
            case "GROQ" -> "openai/gpt-oss-20b";
            default -> "gemini-flash-latest";
        };
    }

    private String defaultChatModelFor(String provider) {
        return switch (provider.toUpperCase()) {
            case "CLAUDE" -> "claude-3-5-haiku-20241022";
            case "OPENAI" -> "gpt-4o-mini";
            case "GROK" -> "grok-4.6";
            case "GROQ" -> "openai/gpt-oss-20b";
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
