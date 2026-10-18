package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * File list and small files of a GitHub repository at a commit or branch, through the GitHub API. Used to write the
 * CI pipeline and to analyse what the CI will run; never clones. The token (optional for public repositories) is
 * only sent to GitHub.
 */
@Component
public class GitHubRepoFiles {

    /** Woodpecker waits 10 s for the pipeline: every call must end well before. */
    private static final Duration TIMEOUT = Duration.ofSeconds(6);
    static final int MAX_FILES_READ = 12;

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(4)).build();
    private final ObjectMapper json;
    private final String api;

    public GitHubRepoFiles(ObjectMapper json, @Value("${vulnix.ci.github-api:https://api.github.com}") String api) {
        this.json = json;
        this.api = api.replaceAll("/+$", "");
    }

    /** Paths of every file at {@code ref} (commit SHA or branch). */
    public List<String> list(String fullName, String ref, String token) throws Exception {
        HttpResponse<String> r = get("/repos/" + fullName + "/git/trees/" + enc(ref) + "?recursive=1", token, false).join();
        if (r.statusCode() == 404) throw new IllegalStateException("dépôt ou branche introuvable sur GitHub (ou privé sans accès)");
        if (r.statusCode() != 200) throw new IllegalStateException("GitHub a répondu " + r.statusCode());
        List<String> files = new ArrayList<>();
        for (JsonNode n : json.readTree(r.body()).path("tree")) {
            if ("blob".equals(n.path("type").asText())) files.add(n.path("path").asText());
        }
        return files;
    }

    /** Raw content of up to {@link #MAX_FILES_READ} files, fetched in parallel; missing ones are left out. */
    public Map<String, String> read(String fullName, String ref, String token, List<String> paths) {
        Map<String, CompletableFuture<HttpResponse<String>>> pending = new HashMap<>();
        for (String p : paths.subList(0, Math.min(paths.size(), MAX_FILES_READ))) {
            String encoded = String.join("/", Arrays.stream(p.split("/")).map(GitHubRepoFiles::enc).toList());
            pending.put(p, get("/repos/" + fullName + "/contents/" + encoded + "?ref=" + enc(ref), token, true));
        }
        Map<String, String> out = new HashMap<>();
        pending.forEach((p, f) -> {
            try {
                HttpResponse<String> r = f.join();
                if (r.statusCode() == 200) out.put(p, r.body());
            } catch (RuntimeException ignored) {
                // one unreadable manifest only makes that part less precise
            }
        });
        return out;
    }

    private CompletableFuture<HttpResponse<String>> get(String path, String token, boolean raw) {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(api + path)).timeout(TIMEOUT)
                .header("Accept", raw ? "application/vnd.github.raw" : "application/vnd.github+json")
                .header("User-Agent", "vulnix-ci");
        if (token != null && !token.isBlank()) b.header("Authorization", "Bearer " + token);
        return http.sendAsync(b.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
