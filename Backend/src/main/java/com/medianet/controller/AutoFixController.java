package com.medianet.controller;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.service.AutoFixService;
import com.medianet.service.UserService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/autofix")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AutoFixController {

    private final AutoFixService autoFixService;
    private final UserService userService;

    public AutoFixController(AutoFixService autoFixService, UserService userService) {
        this.autoFixService = autoFixService;
        this.userService = userService;
    }

    /** Preview the AI-generated fix: returns original vs fixed lines + SHA */
    @PostMapping("/preview")
    public ResponseEntity<?> preview(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, String> body) {

        User currentUser = userService.getRequiredUser(authHeader);
        AuthProvider provider = resolveProvider(body.get("provider"));
        String accessToken = userService.getAccessToken(currentUser, provider);
        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", provider == AuthProvider.GITLAB
                            ? "GitLab token required. Link GitLab first."
                            : "GitHub token required. Link GitHub first."));
        }
        try {
            Map<String, Object> result = autoFixService.previewFix(
                    body.get("repoFullName"),
                    body.get("packageName"),
                    body.get("currentVersion"),
                    body.get("fixedVersion"),
                    body.get("cveId"),
                    body.get("filePath"),
                    body.get("source"),
                    provider.name(),
                    accessToken,
                    currentUser.getGitlabUrl());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            String detail = e.getMessage() != null ? e.getMessage() : "Auto-fix preview failed";
            // Include the HTTP status from RestTemplate exceptions
            if (e instanceof org.springframework.web.client.HttpClientErrorException httpErr) {
                detail = httpErr.getStatusCode() + " " + httpErr.getStatusText() + ": "
                        + httpErr.getResponseBodyAsString();
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", detail));
        }
    }

    /** Apply the fix: commits the fixed content to GitHub */
    @PostMapping("/apply")
    public ResponseEntity<?> apply(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, String> body) {

        User currentUser = userService.getRequiredUser(authHeader);
        AuthProvider provider = resolveProvider(body.get("provider"));
        String accessToken = userService.getAccessToken(currentUser, provider);
        if (accessToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", provider == AuthProvider.GITLAB
                            ? "GitLab token required. Link GitLab first."
                            : "GitHub token required. Link GitHub first."));
        }
        try {
            Map<String, Object> result = autoFixService.applyFix(
                    body.get("repoFullName"),
                    body.get("filePath"),
                    body.get("sha"),
                    body.get("fixedContent"),
                    body.get("commitMessage"),
                    provider.name(),
                    accessToken,
                    body.get("branch"),
                    body.get("lockFilePath"),
                    body.get("lockFileSha"),
                    body.get("lockFileContent"),
                    currentUser.getGitlabUrl());
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage() != null ? e.getMessage() : "Apply fix failed"));
        }
    }

    private AuthProvider resolveProvider(String rawProvider) {
        if (rawProvider == null || rawProvider.isBlank()) {
            return AuthProvider.GITHUB;
        }
        return AuthProvider.valueOf(rawProvider.toUpperCase());
    }
}
