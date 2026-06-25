package com.medianet.service;

import com.medianet.dto.GitRepoDto;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpStatus;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class GitLabService {

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
                + "&scope=api%20read_user"
                + "&state=" + encodedState;
    }

    public String exchangeCodeForToken(String code) {
        ensureOAuthConfigured();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", gitlabClientId);
        body.add("client_secret", gitlabClientSecret);
        body.add("code", code);
        body.add("grant_type", "authorization_code");
        body.add("redirect_uri", gitlabRedirectUri);

        ResponseEntity<Map> response = restTemplate.exchange(
                "https://gitlab.com/oauth/token",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                Map.class);
        Map<?, ?> payload = response.getBody();
        if (payload == null || payload.get("access_token") == null) {
            throw new IllegalStateException("GitLab OAuth token exchange failed");
        }
        return String.valueOf(payload.get("access_token"));
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
        String url = resolveBaseUrl(gitlabUrl) + "/api/v4/user";
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
            String encodedProject = URLEncoder.encode(projectPath, StandardCharsets.UTF_8);
            HttpHeaders headers = gitlabHeaders(accessToken);
            String url = resolveBaseUrl(gitlabUrl) + "/api/v4/projects/" + encodedProject;
            ResponseEntity<Map> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    Map.class);
            Map<String, Object> body = response.getBody() != null ? response.getBody() : Map.of();
            Object defaultBranch = body.get("default_branch");
            if (defaultBranch != null && !String.valueOf(defaultBranch).isBlank()) {
                return String.valueOf(defaultBranch);
            }
        } catch (Exception ignored) {
        }
        return "main";
    }

    @SuppressWarnings("unchecked")
    public List<GitRepoDto> listProjects(String accessToken) {
        return listProjects(null, accessToken);
    }

    @SuppressWarnings("unchecked")
    public List<GitRepoDto> listProjects(String gitlabUrl, String accessToken) {
        HttpHeaders headers = gitlabHeaders(accessToken);
        String url = resolveBaseUrl(gitlabUrl) + "/api/v4/projects?membership=true&per_page=50&simple=true";
        ResponseEntity<List> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                List.class);

        List<?> projects = response.getBody();
        List<GitRepoDto> result = new ArrayList<>();
        if (projects == null) {
            return result;
        }

        for (Object projectObj : projects) {
            if (!(projectObj instanceof Map<?, ?> project)) {
                continue;
            }
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
        String encodedProject = URLEncoder.encode(projectPath, StandardCharsets.UTF_8);
        String encodedFile = URLEncoder.encode(filePath, StandardCharsets.UTF_8);
        String branch = ref != null && !ref.isBlank() ? ref : getProjectDefaultBranch(gitlabUrl, projectPath, accessToken);
        HttpHeaders headers = gitlabHeaders(accessToken);
        String url = resolveBaseUrl(gitlabUrl) + "/api/v4/projects/" + encodedProject + "/repository/files/" + encodedFile + "?ref="
                + URLEncoder.encode(branch, StandardCharsets.UTF_8);
        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
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
        String encodedProject = URLEncoder.encode(projectPath, StandardCharsets.UTF_8);
        String branch = ref != null && !ref.isBlank() ? ref : getProjectDefaultBranch(gitlabUrl, projectPath, accessToken);
        HttpHeaders headers = gitlabHeaders(accessToken);
        StringBuilder url = new StringBuilder(resolveBaseUrl(gitlabUrl))
                .append("/api/v4/projects/")
                .append(encodedProject)
                .append("/repository/tree?per_page=100&ref=")
                .append(URLEncoder.encode(branch, StandardCharsets.UTF_8));
        if (path != null && !path.isBlank()) {
            url.append("&path=").append(URLEncoder.encode(path, StandardCharsets.UTF_8));
        }

        ResponseEntity<List> response = restTemplate.exchange(
                url.toString(),
                HttpMethod.GET,
                new HttpEntity<>(headers),
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
        String encodedProject = URLEncoder.encode(projectPath, StandardCharsets.UTF_8);
        String encodedFile = URLEncoder.encode(filePath, StandardCharsets.UTF_8);
        HttpHeaders headers = gitlabHeaders(accessToken);
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> body = new HashMap<>();
        body.put("branch",
                branch != null && !branch.isBlank() ? branch : getProjectDefaultBranch(gitlabUrl, projectPath, accessToken));
        body.put("content", content);
        body.put("commit_message", commitMessage);
        body.put("encoding", "text");

        String baseUrl = resolveBaseUrl(gitlabUrl);
        restTemplate.exchange(
                baseUrl + "/api/v4/projects/" + encodedProject + "/repository/files/" + encodedFile,
                HttpMethod.PUT,
                new HttpEntity<>(body, headers),
                Map.class);

        return Map.of(
                "commitUrl", baseUrl + "/" + projectPath + "/-/commits",
                "sha", "");
    }
}