package com.medianet.service;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds masked token status for Profile UI. Never returns the raw secret.
 */
@Service
public class GitTokenStatusService {

    private final UserService userService;
    private final GitLabService gitLabService;
    private final RestTemplate restTemplate = new RestTemplate();

    public GitTokenStatusService(UserService userService, GitLabService gitLabService) {
        this.userService = userService;
        this.gitLabService = gitLabService;
    }

    public Map<String, Object> fullStatus(User user, String repoFullName) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("github", buildGithubStatus(user, repoFullName));
        result.put("gitlab", buildGitlabStatus(user));
        return result;
    }

    public Map<String, Object> buildGithubStatus(User user, String repoFullName) {
        Map<String, Object> status = new LinkedHashMap<>();
        String token = userService.getAccessToken(user, AuthProvider.GITHUB);
        boolean linked = token != null && !token.isBlank();
        status.put("linked", linked);
        if (!linked) {
            status.put("tokenKind", "NONE");
            status.put("maskedToken", null);
            status.put("valid", false);
            status.put("warning", "Aucun token GitHub enregistré.");
            return status;
        }

        String kind = detectGithubTokenKind(token);
        status.put("tokenKind", kind);
        status.put("maskedToken", maskSecret(token));
        status.put("warning", "FINE_GRAINED".equals(kind)
                ? "ATTENTION : token Fine-grained (github_pat_…). Ce n'est PAS un Classic. "
                + "Pour les commits, créez un Classic PAT (ghp_) avec le scope repo, "
                + "supprimez celui-ci, puis liez le nouveau."
                : null);

        try {
            HttpHeaders headers = githubHeaders(token);
            ResponseEntity<Map<String, Object>> userResp = restTemplate.exchange(
                    "https://api.github.com/user",
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    new ParameterizedTypeReference<>() {
                    });
            Map<String, Object> ghUser = userResp.getBody() != null ? userResp.getBody() : Map.of();
            status.put("valid", true);
            status.put("githubLogin", ghUser.get("login"));
            status.put("githubName", ghUser.get("name"));
            String scopes = userResp.getHeaders().getFirst("X-OAuth-Scopes");
            status.put("scopes", scopes != null ? scopes : "(non exposés — normal pour Fine-grained)");
            boolean hasRepoScope = scopes != null && (scopes.contains("repo") || scopes.contains("public_repo"));
            status.put("hasRepoScope", hasRepoScope);

            if (repoFullName != null && !repoFullName.isBlank()) {
                try {
                    ResponseEntity<Map<String, Object>> repoResp = restTemplate.exchange(
                            "https://api.github.com/repos/" + repoFullName,
                            HttpMethod.GET,
                            new HttpEntity<>(headers),
                            new ParameterizedTypeReference<>() {
                            });
                    Map<String, Object> repo = repoResp.getBody() != null ? repoResp.getBody() : Map.of();
                    Object permsObj = repo.get("permissions");
                    boolean canPush = false;
                    if (permsObj instanceof Map<?, ?> perms) {
                        canPush = Boolean.TRUE.equals(perms.get("push"));
                        status.put("permissions", perms);
                    }
                    status.put("repoFullName", repoFullName);
                    status.put("canPush", canPush);
                    if (!canPush) {
                        status.put("pushError",
                                "push=false sur " + repoFullName
                                        + ". Le token ne peut pas committer sur ce dépôt.");
                    }
                } catch (org.springframework.web.client.HttpClientErrorException repoErr) {
                    status.put("repoFullName", repoFullName);
                    status.put("canPush", false);
                    status.put("pushError", "Impossible d'accéder au dépôt " + repoFullName
                            + " (" + repoErr.getStatusCode().value() + ").");
                }
            }

            if (!"FINE_GRAINED".equals(kind) && !hasRepoScope && "CLASSIC".equals(kind)) {
                status.put("warning", "Classic PAT sans scope 'repo'. Recréez-le avec repo coché.");
            }
        } catch (org.springframework.web.client.HttpClientErrorException httpErr) {
            status.put("valid", false);
            status.put("error", "Token rejeté par GitHub (" + httpErr.getStatusCode().value() + "). "
                    + "Supprimez-le et liez-en un nouveau.");
        } catch (Exception e) {
            status.put("valid", false);
            status.put("error", "Impossible de vérifier le token : " + e.getMessage());
        }
        return status;
    }

    public Map<String, Object> buildGitlabStatus(User user) {
        Map<String, Object> status = new LinkedHashMap<>();
        String token = userService.getAccessToken(user, AuthProvider.GITLAB);
        boolean linked = token != null && !token.isBlank();
        status.put("linked", linked);
        status.put("gitlabUrl", user.getGitlabUrl());
        if (!linked) {
            status.put("maskedToken", null);
            status.put("valid", false);
            status.put("warning", "Aucun token GitLab enregistré.");
            return status;
        }
        status.put("maskedToken", maskSecret(token));
        status.put("tokenKind", token.startsWith("glpat-") ? "PAT" : "UNKNOWN");
        try {
            Map<String, Object> glUser = gitLabService.validatePersonalAccessToken(user.getGitlabUrl(), token);
            status.put("valid", true);
            status.put("gitlabLogin", glUser.get("username") != null ? glUser.get("username") : glUser.get("name"));
        } catch (Exception e) {
            status.put("valid", false);
            status.put("error", "Token GitLab invalide : " + e.getMessage());
        }
        return status;
    }

    public static String detectGithubTokenKind(String token) {
        if (token == null) return "UNKNOWN";
        if (token.startsWith("github_pat_")) return "FINE_GRAINED";
        if (token.startsWith("ghp_")) return "CLASSIC";
        if (token.startsWith("gho_") || token.startsWith("ghu_")) return "OAUTH";
        return "UNKNOWN";
    }

    public static String maskSecret(String secret) {
        if (secret == null || secret.isBlank()) return null;
        if (secret.length() <= 12) return "••••••••";
        return secret.substring(0, 10) + "…" + secret.substring(secret.length() - 4);
    }

    private HttpHeaders githubHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        headers.set("User-Agent", "Vulnix-Medianet");
        return headers;
    }
}
