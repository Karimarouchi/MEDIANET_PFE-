package com.medianet.service;

import com.medianet.dto.GitRepoDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class GitLabService {

    private static final Logger log = LoggerFactory.getLogger(GitLabService.class);
    private static final Pattern NUMERIC_ID = Pattern.compile("^\\d+$");

    @Value("${gitlab.client.id:}")
    private String gitlabClientId;

    @Value("${gitlab.client.secret:}")
    private String gitlabClientSecret;

    @Value("${gitlab.oauth.redirect-uri:}")
    private String gitlabRedirectUri;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private String resolveBaseUrl(String gitlabUrl) {
        if (gitlabUrl == null || gitlabUrl.trim().isBlank()) {
            return "https://gitlab.com";
        }
        String url = gitlabUrl.trim();
        if (url.endsWith("/")) {
            url = url.substring(0, url.length() - 1);
        }
        return url;
    }

    /**
     * GitLab docs: PAT → PRIVATE-TOKEN (or Bearer). OAuth access token → Bearer.
     * https://docs.gitlab.com/ee/api/rest/authentication.html
     */
    private HttpHeaders gitlabHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        if (accessToken != null && !accessToken.isBlank()) {
            if (accessToken.startsWith("glpat-") || accessToken.length() < 40) {
                headers.set("PRIVATE-TOKEN", accessToken);
            } else {
                headers.setBearerAuth(accessToken);
            }
        }
        return headers;
    }

    public String buildLinkAuthorizationUrl(String state) {
        ensureOAuthConfigured();
        String encodedRedirect = URLEncoder.encode(gitlabRedirectUri, StandardCharsets.UTF_8);
        String encodedState = URLEncoder.encode(state, StandardCharsets.UTF_8);
        return "https://gitlab.com/oauth/authorize"
                + "?client_id=" + gitlabClientId
                + "&redirect_uri=" + encodedRedirect
                + "&response_type=code"
                + "&scope=api%20read_user%20offline_access"
                + "&state=" + encodedState;
    }

    public record GitlabOAuthTokens(String accessToken, String refreshToken, java.time.Instant expiresAt) {
    }

    public String exchangeCodeForToken(String code) {
        return exchangeCodeForTokens(code).accessToken();
    }

    public GitlabOAuthTokens exchangeCodeForTokens(String code) {
        ensureOAuthConfigured();
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", gitlabClientId);
        body.add("client_secret", gitlabClientSecret);
        body.add("code", code);
        body.add("grant_type", "authorization_code");
        body.add("redirect_uri", gitlabRedirectUri);
        return requestOAuthTokens("https://gitlab.com/oauth/token", body);
    }

    public GitlabOAuthTokens refreshTokens(String gitlabUrl, String refreshToken) {
        ensureOAuthConfigured();
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new IllegalStateException("GitLab refresh token manquant.");
        }
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", gitlabClientId);
        body.add("client_secret", gitlabClientSecret);
        body.add("grant_type", "refresh_token");
        body.add("refresh_token", refreshToken);
        body.add("redirect_uri", gitlabRedirectUri);
        return requestOAuthTokens(resolveBaseUrl(gitlabUrl) + "/oauth/token", body);
    }

    @SuppressWarnings("unchecked")
    private GitlabOAuthTokens requestOAuthTokens(String tokenUrl, MultiValueMap<String, String> body) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        ResponseEntity<Map> response = restTemplate.exchange(
                tokenUrl,
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                Map.class);
        Map<?, ?> payload = response.getBody();
        if (payload == null || payload.get("access_token") == null) {
            throw new IllegalStateException("GitLab OAuth token exchange failed");
        }
        String access = String.valueOf(payload.get("access_token"));
        Object refreshObj = payload.get("refresh_token");
        String refresh = refreshObj != null && !String.valueOf(refreshObj).isBlank()
                ? String.valueOf(refreshObj)
                : null;
        long expiresIn = 7200;
        Object expiresObj = payload.get("expires_in");
        if (expiresObj instanceof Number n) {
            expiresIn = Math.max(60, n.longValue());
        }
        return new GitlabOAuthTokens(access, refresh, java.time.Instant.now().plusSeconds(expiresIn));
    }

    public static boolean isExpiredOAuthError(Throwable error) {
        if (!(error instanceof HttpClientErrorException httpErr)) {
            return false;
        }
        if (httpErr.getStatusCode().value() != 401) {
            return false;
        }
        String body = httpErr.getResponseBodyAsString();
        if (body == null) {
            return false;
        }
        String lower = body.toLowerCase(java.util.Locale.ROOT);
        return lower.contains("invalid_token")
                || lower.contains("token is expired")
                || lower.contains("expired");
    }

    private void ensureOAuthConfigured() {
        boolean missingClientId = gitlabClientId == null || gitlabClientId.isBlank();
        boolean missingClientSecret = gitlabClientSecret == null || gitlabClientSecret.isBlank();
        boolean missingRedirectUri = gitlabRedirectUri == null || gitlabRedirectUri.isBlank();

        if (!missingClientId && !missingClientSecret && !missingRedirectUri) {
            return;
        }

        StringBuilder missing = new StringBuilder();
        if (missingClientId) {
            missing.append("gitlab.client.id");
        }
        if (missingClientSecret) {
            if (missing.length() > 0) {
                missing.append(", ");
            }
            missing.append("gitlab.client.secret");
        }
        if (missingRedirectUri) {
            if (missing.length() > 0) {
                missing.append(", ");
            }
            missing.append("gitlab.oauth.redirect-uri");
        }

        throw new ResponseStatusException(
                HttpStatus.SERVICE_UNAVAILABLE,
                "GitLab OAuth is not configured on the backend. Missing: " + missing
                        + ". Fill these properties in application.properties or use the manual GitLab token link.");
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetchCurrentUser(String accessToken) {
        return fetchCurrentUser(null, accessToken);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> fetchCurrentUser(String gitlabUrl, String accessToken) {
        HttpHeaders headers = gitlabHeaders(accessToken);
        URI url = URI.create(resolveBaseUrl(gitlabUrl) + "/api/v4/user");
        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                Map.class);
        return response.getBody() != null ? response.getBody() : Map.of();
    }

    public Map<String, Object> validatePersonalAccessToken(String token) {
        return validatePersonalAccessToken(null, token);
    }

    public Map<String, Object> validatePersonalAccessToken(String gitlabUrl, String token) {
        return fetchCurrentUser(gitlabUrl, token);
    }

    @SuppressWarnings("unchecked")
    public String getProjectDefaultBranch(String projectPath, String accessToken) {
        return getProjectDefaultBranch(null, projectPath, accessToken);
    }

    @SuppressWarnings("unchecked")
    public String getProjectDefaultBranch(String gitlabUrl, String projectPath, String accessToken) {
        try {
            Map<String, Object> body = getProject(gitlabUrl, projectPath, accessToken);
            Object defaultBranch = body.get("default_branch");
            if (defaultBranch != null && !String.valueOf(defaultBranch).isBlank()) {
                return String.valueOf(defaultBranch);
            }
        } catch (Exception e) {
            log.warn("[GitLab] Could not read default branch for {}: {}", projectPath, e.getMessage());
        }
        return "main";
    }

    /**
     * Resolves a GitLab project and returns the API payload (includes numeric {@code id}).
     * GitLab requires {@code path_with_namespace} with {@code /} encoded as {@code %2F},
     * or the numeric project id. Display names (e.g. "Pfe mediannet") are not valid ids.
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> getProject(String gitlabUrl, String projectPath, String accessToken) {
        String projectId = resolveProjectApiId(gitlabUrl, projectPath, accessToken);
        URI url = projectUri(gitlabUrl, projectId);
        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(gitlabHeaders(accessToken)),
                Map.class);
        return response.getBody() != null ? response.getBody() : Map.of();
    }

    /**
     * GitLab Developer (30+) can push to unprotected branches — same role GitHub "push" maps to.
     */
    public void assertPushAccess(String gitlabUrl, String projectPath, String accessToken) {
        Map<String, Object> project = getProject(gitlabUrl, projectPath, accessToken);
        Object permsObj = project.get("permissions");
        if (!(permsObj instanceof Map<?, ?> perms)) {
            return;
        }
        int level = Math.max(accessLevel(perms.get("project_access")), accessLevel(perms.get("group_access")));
        if (level > 0 && level < 30) {
            throw new IllegalStateException(
                    "Votre token GitLab peut LIRE le projet '" + projectPath
                            + "' mais n'a PAS le droit d'ÉCRITURE (niveau " + level
                            + ", Developer=30 requis). "
                            + "Créez un PAT avec les scopes 'api' et 'write_repository', "
                            + "ou demandez le rôle Developer/Maintainer sur ce projet. "
                            + "Les dépôts privés GitLab renvoient 404 si le token n'a pas accès.");
        }
        log.info("[GitLab] Push access OK for {} (access_level={})", projectPath, level);
    }

    private static int accessLevel(Object accessObj) {
        if (!(accessObj instanceof Map<?, ?> access)) {
            return 0;
        }
        Object level = access.get("access_level");
        if (level instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(level));
        } catch (Exception ignored) {
            return 0;
        }
    }

    @SuppressWarnings("unchecked")
    public List<GitRepoDto> listProjects(String accessToken) {
        return listProjects(null, accessToken);
    }

    @SuppressWarnings("unchecked")
    public List<GitRepoDto> listProjects(String gitlabUrl, String accessToken) {
        List<Map<String, Object>> projects = listMembershipProjects(gitlabUrl, accessToken);
        List<GitRepoDto> result = new ArrayList<>();
        for (Map<String, Object> project : projects) {
            result.add(GitRepoDto.builder()
                    .name(project.get("name") != null ? String.valueOf(project.get("name")) : "")
                    .fullName(project.get("path_with_namespace") != null
                            ? String.valueOf(project.get("path_with_namespace"))
                            : "")
                    .description(project.get("description") != null ? String.valueOf(project.get("description")) : "")
                    .language(project.get("language") != null ? String.valueOf(project.get("language")) : "")
                    .isPrivate(!Boolean.TRUE.equals(project.get("public")))
                    .stars(project.get("star_count") instanceof Number n ? n.intValue() : 0)
                    .htmlUrl(project.get("web_url") != null ? String.valueOf(project.get("web_url")) : "")
                    .updatedAt(project.get("last_activity_at") != null ? String.valueOf(project.get("last_activity_at"))
                            : "")
                    .provider("GITLAB")
                    .build());
        }
        return result;
    }

    public String getFileContent(String projectPath, String filePath, String accessToken, String ref) throws Exception {
        return getFileContent(null, projectPath, filePath, accessToken, ref);
    }

    public String getFileContent(String gitlabUrl, String projectPath, String filePath, String accessToken, String ref) throws Exception {
        String projectId = resolveProjectApiId(gitlabUrl, projectPath, accessToken);
        String branch = normalizeGitRef(ref);
        if (branch == null) {
            branch = getProjectDefaultBranch(gitlabUrl, projectPath, accessToken);
        }
        URI url = repositoryFileUri(gitlabUrl, projectId, filePath, branch);
        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(gitlabHeaders(accessToken)),
                String.class);
        JsonNode root = objectMapper.readTree(response.getBody());
        String base64 = root.path("content").asText("");
        byte[] decoded = java.util.Base64.getDecoder().decode(base64.replace("\n", ""));
        return new String(decoded, StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRepositoryTree(String projectPath, String accessToken, String path, String ref) {
        return listRepositoryTree(null, projectPath, accessToken, path, ref);
    }

    @SuppressWarnings("unchecked")
    public List<Map<String, Object>> listRepositoryTree(String gitlabUrl, String projectPath, String accessToken, String path, String ref) {
        String projectId = resolveProjectApiId(gitlabUrl, projectPath, accessToken);
        String branch = normalizeGitRef(ref);
        if (branch == null) {
            branch = getProjectDefaultBranch(gitlabUrl, projectPath, accessToken);
        }
        StringBuilder raw = new StringBuilder(resolveBaseUrl(gitlabUrl))
                .append("/api/v4/projects/")
                .append(encodeGitlabPath(projectId))
                .append("/repository/tree?per_page=100&recursive=true&ref=")
                .append(encodeGitlabPath(branch));
        if (path != null && !path.isBlank()) {
            raw.append("&path=").append(encodeGitlabPath(path));
        }

        ResponseEntity<List> response = restTemplate.exchange(
                URI.create(raw.toString()),
                HttpMethod.GET,
                new HttpEntity<>(gitlabHeaders(accessToken)),
                List.class);

        List<?> body = response.getBody();
        List<Map<String, Object>> result = new ArrayList<>();
        if (body == null) {
            return result;
        }
        for (Object entry : body) {
            if (entry instanceof Map<?, ?> map) {
                result.add((Map<String, Object>) map);
            }
        }
        return result;
    }

    public Map<String, Object> updateFile(String projectPath, String filePath, String content, String accessToken,
            String branch, String commitMessage) {
        return updateFile(null, projectPath, filePath, content, accessToken, branch, commitMessage);
    }

    public Map<String, Object> updateFile(String gitlabUrl, String projectPath, String filePath, String content, String accessToken,
            String branch, String commitMessage) {
        String projectId = resolveProjectApiId(gitlabUrl, projectPath, accessToken);
        String resolvedBranch = normalizeGitRef(branch);
        if (resolvedBranch == null) {
            resolvedBranch = getProjectDefaultBranch(gitlabUrl, projectPath, accessToken);
        }
        HttpHeaders headers = gitlabHeaders(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new HashMap<>();
        body.put("branch", resolvedBranch);
        body.put("content", content != null ? content : "");
        body.put("commit_message", commitMessage != null && !commitMessage.isBlank()
                ? commitMessage
                : "fix: auto-fix CVE via Vulnix Auto-Fix");
        body.put("encoding", "text");

        URI url = repositoryFileUri(gitlabUrl, projectId, filePath, null);
        Map<String, Object> responseBody = writeRepositoryFile(url, headers, body);

        String commitId = str(responseBody != null ? responseBody.get("commit_id") : null);
        String webUrl = projectWebUrl(gitlabUrl, projectPath, accessToken);
        String commitUrl;
        if (webUrl != null && commitId != null && !commitId.isBlank()) {
            commitUrl = webUrl.replaceFirst("/+$", "") + "/-/commit/" + commitId;
        } else if (webUrl != null) {
            commitUrl = webUrl.replaceFirst("/+$", "") + "/-/commits/" + resolvedBranch;
        } else {
            commitUrl = resolveBaseUrl(gitlabUrl) + "/" + normalizeProjectPath(projectPath)
                    + "/-/commits/" + resolvedBranch;
        }
        return Map.of(
                "commitUrl", commitUrl,
                "htmlUrl", commitUrl,
                "sha", commitId != null ? commitId : "");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> writeRepositoryFile(URI url, HttpHeaders headers, Map<String, Object> body) {
        try {
            ResponseEntity<Map> updated = restTemplate.exchange(
                    url, HttpMethod.PUT, new HttpEntity<>(body, headers), Map.class);
            return updated.getBody() != null ? updated.getBody() : Map.of();
        } catch (HttpClientErrorException httpErr) {
            int status = httpErr.getStatusCode().value();
            String detail = httpErr.getResponseBodyAsString() != null
                    ? httpErr.getResponseBodyAsString().toLowerCase(java.util.Locale.ROOT)
                    : "";
            boolean missingFile = status == 400 || status == 404;
            if (missingFile && (detail.contains("doesn't exist") || detail.contains("does not exist")
                    || detail.contains("file not found") || detail.contains("404 file"))) {
                ResponseEntity<Map> created = restTemplate.exchange(
                        url, HttpMethod.POST, new HttpEntity<>(body, headers), Map.class);
                return created.getBody() != null ? created.getBody() : Map.of();
            }
            throw httpErr;
        }
    }

    private String projectWebUrl(String gitlabUrl, String projectPath, String accessToken) {
        try {
            Map<String, Object> project = getProject(gitlabUrl, projectPath, accessToken);
            return str(project.get("web_url"));
        } catch (Exception e) {
            log.warn("[GitLab] Could not read web_url for {}: {}", projectPath, e.getMessage());
            return null;
        }
    }

    /**
     * Prefer the numeric GitLab project id (stable). Falls back to URL-encoded
     * {@code path_with_namespace}, then membership search by display name.
     */
    String resolveProjectApiId(String gitlabUrl, String projectPath, String accessToken) {
        String normalized = normalizeProjectPath(projectPath);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Chemin de projet GitLab vide.");
        }
        if (NUMERIC_ID.matcher(normalized).matches()) {
            return normalized;
        }

        try {
            Map<?, ?> project = fetchProjectRaw(gitlabUrl, normalized, accessToken);
            if (project != null && project.get("id") != null) {
                return String.valueOf(project.get("id"));
            }
        } catch (HttpClientErrorException httpErr) {
            if (httpErr.getStatusCode().value() != 404) {
                throw httpErr;
            }
            log.warn("[GitLab] Project path '{}' not found ({}), searching memberships",
                    normalized, httpErr.getStatusCode());
        }

        Map<String, Object> match = findMembershipProject(gitlabUrl, normalized, accessToken);
        if (match != null && match.get("id") != null) {
            log.info("[GitLab] Resolved '{}' → {} (id={})",
                    normalized, match.get("path_with_namespace"), match.get("id"));
            return String.valueOf(match.get("id"));
        }

        throw new HttpClientErrorException(
                HttpStatus.NOT_FOUND,
                "404 Project Not Found",
                ("{\"message\":\"404 Project Not Found — GitLab n'a pas trouvé '" + normalized
                        + "'. Utilisez path_with_namespace (ex. antigone-agency/pfe-mediannet), "
                        + "pas le nom affiché. PAT privé : scopes api + write_repository.\"}").getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchProjectRaw(String gitlabUrl, String projectPath, String accessToken) {
        URI url = projectUri(gitlabUrl, projectPath);
        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(gitlabHeaders(accessToken)),
                Map.class);
        return response.getBody();
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> listMembershipProjects(String gitlabUrl, String accessToken) {
        URI url = URI.create(resolveBaseUrl(gitlabUrl)
                + "/api/v4/projects?membership=true&per_page=100&simple=true");
        ResponseEntity<List> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(gitlabHeaders(accessToken)),
                List.class);
        List<?> projects = response.getBody();
        List<Map<String, Object>> result = new ArrayList<>();
        if (projects == null) {
            return result;
        }
        for (Object projectObj : projects) {
            if (projectObj instanceof Map<?, ?> project) {
                result.add((Map<String, Object>) project);
            }
        }
        return result;
    }

    private Map<String, Object> findMembershipProject(String gitlabUrl, String needle, String accessToken) {
        String wanted = needle.toLowerCase(java.util.Locale.ROOT).replace(' ', '-');
        String wantedName = needle.toLowerCase(java.util.Locale.ROOT).replace('-', ' ').trim();
        String lastSegment = needle.contains("/")
                ? needle.substring(needle.lastIndexOf('/') + 1)
                : needle;
        String lastSlug = lastSegment.toLowerCase(java.util.Locale.ROOT).replace(' ', '-');
        String lastName = lastSegment.toLowerCase(java.util.Locale.ROOT).replace('-', ' ').trim();

        for (Map<String, Object> project : listMembershipProjects(gitlabUrl, accessToken)) {
            String pathNs = str(project.get("path_with_namespace"));
            String path = str(project.get("path"));
            String name = str(project.get("name"));
            String webUrl = str(project.get("web_url"));
            if (equalsFold(pathNs, needle) || equalsFold(pathNs, wanted)
                    || equalsFold(path, lastSegment) || equalsFold(path, lastSlug)
                    || equalsFold(name, lastSegment) || equalsFold(name, lastName) || equalsFold(name, wantedName)
                    || (webUrl != null && webUrl.toLowerCase(java.util.Locale.ROOT).contains("/" + lastSlug))) {
                return project;
            }
        }
        return null;
    }

    private static boolean equalsFold(String a, String b) {
        if (a == null || b == null || a.isBlank() || b.isBlank()) {
            return false;
        }
        return a.trim().equalsIgnoreCase(b.trim());
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    /** GitLab file APIs want {@code main}, not {@code refs/heads/main}. */
    static String normalizeGitRef(String ref) {
        if (ref == null || ref.isBlank()) {
            return null;
        }
        String value = ref.trim();
        if (value.startsWith("refs/heads/")) {
            value = value.substring("refs/heads/".length());
        } else if (value.startsWith("refs/tags/")) {
            value = value.substring("refs/tags/".length());
        }
        return value.isBlank() ? null : value;
    }

    /**
     * GitLab namespaced paths: {@code /} must be {@code %2F}. Space must be {@code %20}
     * (not {@code +} from {@link URLEncoder}). Callers MUST pass the result via {@link URI}
     * so RestTemplate does not encode a second time ({@code %252F} → 404 Project Not Found).
     * https://docs.gitlab.com/ee/api/rest/#namespaced-paths
     */
    static String encodeGitlabPath(String value) {
        if (value == null) {
            return "";
        }
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /**
     * Accepts clone URLs, web URLs, or {@code group/project}. Strips {@code .git} and GitLab UI suffixes ({@code /-/tree/...}).
     */
    static String normalizeProjectPath(String projectPath) {
        if (projectPath == null) {
            return "";
        }
        String raw = projectPath.trim();
        if (raw.isEmpty()) {
            return "";
        }
        if (raw.startsWith("git@")) {
            int colon = raw.indexOf(':');
            if (colon >= 0) {
                raw = raw.substring(colon + 1);
            }
        } else if (raw.contains("://")) {
            try {
                URI uri = URI.create(raw);
                String path = uri.getPath();
                raw = path != null ? path : raw;
            } catch (IllegalArgumentException ignored) {
            }
        }
        raw = raw.replaceFirst("^/+", "");
        raw = raw.replaceFirst("(?i)\\.git$", "");
        int webSuffix = raw.indexOf("/-/");
        if (webSuffix >= 0) {
            raw = raw.substring(0, webSuffix);
        }
        raw = raw.replaceFirst("/+$", "");
        try {
            raw = URLDecoder.decode(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ignored) {
        }
        return raw;
    }

    static URI projectUri(String gitlabUrl, String projectPathOrId) {
        String base = gitlabUrl == null || gitlabUrl.isBlank() ? "https://gitlab.com" : gitlabUrl.trim();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        String id = NUMERIC_ID.matcher(projectPathOrId).matches()
                ? projectPathOrId
                : encodeGitlabPath(normalizeProjectPath(projectPathOrId));
        return URI.create(base + "/api/v4/projects/" + id);
    }

    static URI repositoryFileUri(String gitlabUrl, String projectPathOrId, String filePath, String ref) {
        String base = gitlabUrl == null || gitlabUrl.isBlank() ? "https://gitlab.com" : gitlabUrl.trim();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        String id = NUMERIC_ID.matcher(projectPathOrId).matches()
                ? projectPathOrId
                : encodeGitlabPath(normalizeProjectPath(projectPathOrId));
        StringBuilder raw = new StringBuilder(base)
                .append("/api/v4/projects/")
                .append(id)
                .append("/repository/files/")
                .append(encodeGitlabPath(filePath));
        if (ref != null && !ref.isBlank()) {
            raw.append("?ref=").append(encodeGitlabPath(ref));
        }
        return URI.create(raw.toString());
    }
}
