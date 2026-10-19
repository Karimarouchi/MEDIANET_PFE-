package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Commits of a repository, read from GitHub or GitLab: the list (author, message, date) and one commit's detail
 * (files, added / removed lines). Token: the viewer's own, then the repository owner's, then none (public repository).
 * Results are kept two minutes, so a page refresh does not spend the API quota again.
 */
@Service
public class RepoCommitService {

    private static final Logger log = LoggerFactory.getLogger(RepoCommitService.class);
    private static final Pattern SHA = Pattern.compile("^[0-9a-fA-F]{7,40}$");
    private static final Duration TTL = Duration.ofMinutes(2);
    /** GitHub and GitLab pages hold at most 100 commits; 5 pages are plenty for a project view. */
    private static final int MAX_PAGES = 5;

    public record CommitInfo(String sha, String shortSha, String title, String message, String authorName,
                             String authorEmail, String authorLogin, Instant date, String url) {
    }

    public record FileChange(String path, String status, int additions, int deletions) {
    }

    public record CommitDetail(CommitInfo commit, int additions, int deletions, List<FileChange> files, boolean truncated) {
    }

    private record Cached(Object value, Instant until) {
    }

    private final UserService userService;
    private final GitLabService gitLabService;
    private final ObjectMapper json;
    private final String githubApi;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL).build();
    private final Map<String, Cached> cache = new ConcurrentHashMap<>();

    public RepoCommitService(UserService userService, GitLabService gitLabService, ObjectMapper json,
            @Value("${vulnix.ci.github-api:https://api.github.com}") String githubApi) {
        this.userService = userService;
        this.gitLabService = gitLabService;
        this.json = json;
        this.githubApi = githubApi.replaceAll("/+$", "");
    }

    /** Commits of {@code branch} (default branch when blank), newest first, since {@code since} (all when null). */
    public List<CommitInfo> list(User viewer, Repository repo, String branch, Instant since, int max) {
        String key = "list|" + repo.getId() + "|" + branch + "|" + since + "|" + max;
        @SuppressWarnings("unchecked")
        List<CommitInfo> hit = (List<CommitInfo>) fromCache(key);
        if (hit != null) return hit;
        List<CommitInfo> out = isGitLab(repo) ? listGitLab(viewer, repo, branch, since, max) : listGitHub(viewer, repo, branch, since, max);
        cache.put(key, new Cached(out, Instant.now().plus(TTL)));
        return out;
    }

    public CommitDetail detail(User viewer, Repository repo, String sha) {
        if (sha == null || !SHA.matcher(sha.trim()).matches()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Identifiant de commit invalide.");
        }
        String key = "detail|" + repo.getId() + "|" + sha.toLowerCase();
        CommitDetail hit = (CommitDetail) fromCache(key);
        if (hit != null) return hit;
        CommitDetail out = isGitLab(repo) ? detailGitLab(viewer, repo, sha.trim()) : detailGitHub(viewer, repo, sha.trim());
        cache.put(key, new Cached(out, Instant.now().plus(Duration.ofHours(1))));
        return out;
    }

    // ───────────────────────── GitHub ─────────────────────────

    private List<CommitInfo> listGitHub(User viewer, Repository repo, String branch, Instant since, int max) {
        String full = githubFullName(repo.getRepoUrl());
        String token = token(viewer, repo, AuthProvider.GITHUB);
        List<CommitInfo> out = new ArrayList<>();
        for (int page = 1; page <= MAX_PAGES && out.size() < max; page++) {
            StringBuilder url = new StringBuilder(githubApi).append("/repos/").append(full).append("/commits?per_page=100&page=").append(page);
            if (branch != null && !branch.isBlank()) url.append("&sha=").append(enc(branch));
            if (since != null) url.append("&since=").append(enc(since.toString()));
            JsonNode arr = get(url.toString(), token == null ? null : "Bearer " + token, true, full);
            if (!arr.isArray() || arr.isEmpty()) break;
            for (JsonNode c : arr) {
                if (out.size() >= max) break;
                out.add(githubCommit(c));
            }
            if (arr.size() < 100) break;
        }
        return out;
    }

    private CommitDetail detailGitHub(User viewer, Repository repo, String sha) {
        String full = githubFullName(repo.getRepoUrl());
        String token = token(viewer, repo, AuthProvider.GITHUB);
        JsonNode c = get(githubApi + "/repos/" + full + "/commits/" + sha, token == null ? null : "Bearer " + token, true, full);
        List<FileChange> files = new ArrayList<>();
        for (JsonNode f : c.path("files")) {
            files.add(new FileChange(f.path("filename").asText(), f.path("status").asText(),
                    f.path("additions").asInt(), f.path("deletions").asInt()));
        }
        // GitHub returns at most 300 files per commit.
        return new CommitDetail(githubCommit(c), c.path("stats").path("additions").asInt(),
                c.path("stats").path("deletions").asInt(), files, files.size() >= 300);
    }

    private static CommitInfo githubCommit(JsonNode c) {
        JsonNode commit = c.path("commit");
        JsonNode author = commit.path("author");
        String message = commit.path("message").asText("");
        String sha = c.path("sha").asText();
        String login = c.path("author").isObject() ? c.path("author").path("login").asText(null) : null;
        return new CommitInfo(sha, sha.length() > 7 ? sha.substring(0, 7) : sha, firstLine(message), message,
                author.path("name").asText(null), author.path("email").asText(null), login,
                parseInstant(author.path("date").asText(null)), c.path("html_url").asText(null));
    }

    // ───────────────────────── GitLab ─────────────────────────

    private List<CommitInfo> listGitLab(User viewer, Repository repo, String branch, Instant since, int max) {
        GitLabRef ref = gitLabRef(repo);
        String token = token(viewer, repo, AuthProvider.GITLAB);
        List<CommitInfo> out = new ArrayList<>();
        for (int page = 1; page <= MAX_PAGES && out.size() < max; page++) {
            StringBuilder url = new StringBuilder(ref.api()).append("/projects/").append(enc(ref.path()))
                    .append("/repository/commits?per_page=100&page=").append(page);
            if (branch != null && !branch.isBlank()) url.append("&ref_name=").append(enc(branch));
            if (since != null) url.append("&since=").append(enc(since.toString()));
            JsonNode arr = get(url.toString(), token == null ? null : "Bearer " + token, false, ref.path());
            if (!arr.isArray() || arr.isEmpty()) break;
            for (JsonNode c : arr) {
                if (out.size() >= max) break;
                out.add(gitlabCommit(c));
            }
            if (arr.size() < 100) break;
        }
        return out;
    }

    private CommitDetail detailGitLab(User viewer, Repository repo, String sha) {
        GitLabRef ref = gitLabRef(repo);
        String token = token(viewer, repo, AuthProvider.GITLAB);
        String auth = token == null ? null : "Bearer " + token;
        String base = ref.api() + "/projects/" + enc(ref.path()) + "/repository/commits/" + sha;
        JsonNode c = get(base + "?stats=true", auth, false, ref.path());
        JsonNode diff = get(base + "/diff?per_page=100", auth, false, ref.path());
        List<FileChange> files = new ArrayList<>();
        for (JsonNode f : diff) {
            String status = f.path("new_file").asBoolean() ? "added" : f.path("deleted_file").asBoolean() ? "removed"
                    : f.path("renamed_file").asBoolean() ? "renamed" : "modified";
            int[] counts = countDiff(f.path("diff").asText(""));
            files.add(new FileChange(f.path("new_path").asText(), status, counts[0], counts[1]));
        }
        return new CommitDetail(gitlabCommit(c), c.path("stats").path("additions").asInt(),
                c.path("stats").path("deletions").asInt(), files, files.size() >= 100);
    }

    private static CommitInfo gitlabCommit(JsonNode c) {
        String sha = c.path("id").asText();
        String message = c.path("message").asText(c.path("title").asText(""));
        return new CommitInfo(sha, c.path("short_id").asText(sha.length() > 7 ? sha.substring(0, 7) : sha),
                c.path("title").asText(firstLine(message)), message, c.path("author_name").asText(null),
                c.path("author_email").asText(null), null,
                parseInstant(c.path("authored_date").asText(c.path("created_at").asText(null))), c.path("web_url").asText(null));
    }

    private record GitLabRef(String api, String path) {
    }

    private GitLabRef gitLabRef(Repository repo) {
        URI uri = URI.create(repo.getRepoUrl().trim().replaceAll("\\.git$", ""));
        String path = uri.getPath().replaceAll("^/+|/+$", "");
        // Validated like any user-provided GitLab URL: https, no credentials, public address only.
        String base = gitLabService.resolveBaseUrl(uri.getScheme() + "://" + uri.getHost() + (uri.getPort() > 0 ? ":" + uri.getPort() : ""));
        return new GitLabRef(base.replaceAll("/+$", "") + "/api/v4", path);
    }

    /** Added / removed lines of a unified diff (GitLab gives no per-file counts). */
    static int[] countDiff(String diff) {
        int add = 0;
        int del = 0;
        for (String line : diff.split("\n")) {
            if (line.startsWith("+") && !line.startsWith("+++")) add++;
            else if (line.startsWith("-") && !line.startsWith("---")) del++;
        }
        return new int[] { add, del };
    }

    // ───────────────────────── plumbing ─────────────────────────

    /** The viewer's token for this provider, then the repository owner's (the person who linked it). */
    private String token(User viewer, Repository repo, AuthProvider provider) {
        Set<User> candidates = new LinkedHashSet<>();
        if (viewer != null) candidates.add(viewer);
        if (repo.getOwnerUser() != null) candidates.add(repo.getOwnerUser());
        for (User u : candidates) {
            try {
                String t = userService.getAccessToken(u, provider);
                if (t != null && !t.isBlank()) return t;
            } catch (RuntimeException ignored) {
                // this account has no token for the provider: try the next one
            }
        }
        return null;
    }

    private JsonNode get(String url, String authorization, boolean github, String what) {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(20)).GET()
                    .header("User-Agent", "Vulnix");
            if (github) b.header("Accept", "application/vnd.github+json");
            if (authorization != null) b.header("Authorization", authorization);
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            // GitHub answers 422 "No commit found for SHA" for an unknown commit.
            if (r.statusCode() == 404 || r.statusCode() == 422) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Commit ou dépôt introuvable sur " + (github ? "GitHub" : "GitLab") + " (" + what + "). Dépôt privé : reliez un compte qui y a accès dans le profil.");
            }
            if (r.statusCode() == 401 || r.statusCode() == 403) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, (github ? "GitHub" : "GitLab")
                        + " refuse l'accès (" + r.statusCode() + ") : jeton absent ou expiré, ou limite d'appels atteinte.");
            }
            if (r.statusCode() >= 400) {
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, (github ? "GitHub" : "GitLab") + " a répondu " + r.statusCode() + ".");
            }
            return json.readTree(r.body());
        } catch (ResponseStatusException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Lecture des commits interrompue.");
        } catch (Exception e) {
            log.warn("Commit API call failed for {}: {}", what, e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Impossible de lire les commits : " + e.getMessage());
        }
    }

    private Object fromCache(String key) {
        Cached c = cache.get(key);
        if (c == null) return null;
        if (Instant.now().isAfter(c.until())) {
            cache.remove(key);
            return null;
        }
        return c.value();
    }

    static boolean isGitLab(Repository repo) {
        return repo.getGitProvider() == AuthProvider.GITLAB
                || (repo.getRepoUrl() != null && repo.getRepoUrl().toLowerCase().contains("gitlab"));
    }

    /** "owner/name" of a github.com URL. */
    static String githubFullName(String repoUrl) {
        Matcher m = Pattern.compile("github\\.com[/:]([^/]+)/([^/?#]+?)(?:\\.git)?/?$", Pattern.CASE_INSENSITIVE)
                .matcher(repoUrl == null ? "" : repoUrl.trim());
        if (!m.find()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Adresse GitHub non reconnue : " + repoUrl);
        }
        return m.group(1) + "/" + m.group(2);
    }

    private static String firstLine(String message) {
        int nl = message.indexOf('\n');
        return (nl >= 0 ? message.substring(0, nl) : message).trim();
    }

    private static Instant parseInstant(String s) {
        try {
            return s == null ? null : java.time.OffsetDateTime.parse(s).toInstant();
        } catch (Exception e) {
            return null;
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
