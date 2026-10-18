package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Woodpecker REST API, called with the admin's personal token (vulnix.ci.woodpecker.token, from vulnix-token.py).
 * Errors become 502 with a short French message; the token and response bodies never reach the browser.
 */
@Component
public class WoodpeckerClient {

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final ObjectMapper json;
    private final String baseUrl;
    private final String token;
    private volatile PublicKey publicKey;

    public WoodpeckerClient(ObjectMapper json,
            @Value("${vulnix.ci.woodpecker.url:http://localhost:8000}") String baseUrl,
            @Value("${vulnix.ci.woodpecker.token:}") String token) {
        this.json = json;
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.token = token == null ? "" : token.trim();
    }

    public boolean isConfigured() {
        return !token.isEmpty();
    }

    /** The forge repository (GitHub) as Woodpecker sees it, active or not. */
    public JsonNode findForgeRepo(String fullName) {
        for (JsonNode r : call("GET", "/api/user/repos?all=true", null)) {
            if (r.path("full_name").asText().equalsIgnoreCase(fullName)) return r;
        }
        return null;
    }

    public JsonNode activate(String forgeRemoteId) {
        return call("POST", "/api/repos?forge_remote_id=" + enc(forgeRemoteId), null);
    }

    public JsonNode patchRepo(long repoId, Map<String, Object> patch) {
        return call("PATCH", "/api/repos/" + repoId, patch);
    }

    /** Removes the webhook and deactivates the repo; its pipeline history stays (no ?remove=true). */
    public void deactivate(long repoId) {
        call("DELETE", "/api/repos/" + repoId, null);
    }

    /** Creates or replaces a repo secret. */
    public void putSecret(long repoId, String name, String value, List<String> events) {
        Map<String, Object> body = Map.of("name", name, "value", value, "events", events);
        int status = send("GET", "/api/repos/" + repoId + "/secrets/" + enc(name), null).statusCode();
        if (status == 200) {
            call("PATCH", "/api/repos/" + repoId + "/secrets/" + enc(name), body);
        } else {
            call("POST", "/api/repos/" + repoId + "/secrets", body);
        }
    }

    public JsonNode createPipeline(long repoId, String branch) {
        return call("POST", "/api/repos/" + repoId + "/pipelines", Map.of("branch", branch));
    }

    public JsonNode pipelines(long repoId, int perPage) {
        return call("GET", "/api/repos/" + repoId + "/pipelines?per_page=" + perPage, null);
    }

    public JsonNode pipeline(long repoId, long number) {
        return call("GET", "/api/repos/" + repoId + "/pipelines/" + number, null);
    }

    public JsonNode cancel(long repoId, long number) {
        return call("POST", "/api/repos/" + repoId + "/pipelines/" + number + "/cancel", null);
    }

    public JsonNode stepLogs(long repoId, long number, long stepId) {
        return call("GET", "/api/repos/" + repoId + "/logs/" + number + "/" + stepId, null);
    }

    /** Key that signs config-extension requests; cached, it only changes if Woodpecker's database is reset. */
    public PublicKey publicKey(boolean refresh) {
        if (publicKey == null || refresh) {
            HttpResponse<String> r = send("GET", "/api/signature/public-key", null);
            if (r.statusCode() != 200) throw unavailable(r.statusCode(), null);
            try {
                publicKey = WoodpeckerSignatureVerifier.parsePem(r.body());
            } catch (Exception e) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Clé publique Woodpecker illisible");
            }
        }
        return publicKey;
    }

    private JsonNode call(String method, String path, Object body) {
        if (!isConfigured()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "La CI n'est pas configurée sur ce serveur (jeton Woodpecker absent).");
        }
        HttpResponse<String> r = send(method, path, body);
        if (r.statusCode() / 100 != 2) throw unavailable(r.statusCode(), r.body());
        try {
            String text = r.body();
            return text == null || text.isBlank() ? json.nullNode() : json.readTree(text);
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Réponse Woodpecker illisible");
        }
    }

    private HttpResponse<String> send(String method, String path, Object body) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(baseUrl + path))
                    .timeout(Duration.ofSeconds(20))
                    .header("Authorization", "Bearer " + token)
                    .header("Accept", "application/json");
            if (body != null) {
                b.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
            } else {
                b.method(method, HttpRequest.BodyPublishers.noBody());
            }
            return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Woodpecker injoignable");
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Woodpecker injoignable (" + baseUrl + ")");
        }
    }

    private static ResponseStatusException unavailable(int status, String body) {
        String msg = switch (status) {
            case 401, 403 -> "Woodpecker refuse le jeton de Vulnix : régénérez-le avec vulnix-token.py.";
            case 404 -> "Élément introuvable dans Woodpecker.";
            default -> "Woodpecker a répondu " + status + woodpeckerReason(body);
        };
        return new ResponseStatusException(HttpStatus.BAD_GATEWAY, msg);
    }

    /**
     * Woodpecker's own error text ("could not fetch branch head: dial tcp: lookup api.github.com…"), one line and
     * short. It comes from our Woodpecker and names hosts, never tokens. Package-private for tests.
     */
    static String woodpeckerReason(String body) {
        if (body == null || body.isBlank()) return ".";
        String line = body.replaceAll("(?s)^\\s*Error #\\d+:\\s*", "").split("\\R", 2)[0].trim();
        if (line.startsWith("{") || line.startsWith("<")) return ".";
        if (line.contains("lookup ") || line.contains("dial tcp")) {
            return " : Woodpecker n'arrive pas à joindre GitHub (réseau ou DNS de Docker). Réessayez dans un instant.";
        }
        return " : " + (line.length() > 200 ? line.substring(0, 200) + "…" : line);
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
