package com.medianet.controller;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.FixKnowledge;
import com.medianet.entity.User;
import com.medianet.service.AutoFixService;
import com.medianet.service.CveJournalService;
import com.medianet.service.FixKnowledgeService;
import com.medianet.service.FixVersionValidationService;
import com.medianet.service.PolicyDeviationService;
import com.medianet.service.UserService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/autofix")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AutoFixController {

    private final AutoFixService autoFixService;
    private final UserService userService;
    private final FixKnowledgeService fixKnowledgeService;
    private final FixVersionValidationService fixVersionValidationService;
    private final CveJournalService cveJournalService;
    private final PolicyDeviationService policyDeviationService;

    public AutoFixController(AutoFixService autoFixService, UserService userService,
            FixKnowledgeService fixKnowledgeService,
            FixVersionValidationService fixVersionValidationService,
            CveJournalService cveJournalService,
            PolicyDeviationService policyDeviationService) {
        this.autoFixService = autoFixService;
        this.userService = userService;
        this.fixKnowledgeService = fixKnowledgeService;
        this.fixVersionValidationService = fixVersionValidationService;
        this.cveJournalService = cveJournalService;
        this.policyDeviationService = policyDeviationService;
    }

    /** Preview the AI-generated fix: returns original vs fixed lines + SHA + human memory + LLM advice */
    @PostMapping("/preview")
    public ResponseEntity<?> preview(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, String> body) {

        User currentUser = userService.getRequiredUser(authHeader);
        AuthProvider provider = resolveProvider(body.get("provider"));
        try {
            String accessToken = userService.getAccessToken(currentUser, provider);
            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", provider == AuthProvider.GITLAB
                                ? "GitLab token required. Link GitLab first."
                                : "GitHub token required. Link GitHub first."));
            }
            // Chef policy first: force official version when defined in Journal CVE
            Map<String, Object> policy = cveJournalService.getPolicy(
                    body.get("cveId"), body.get("packageName"));
            String chefVersion = policy.get("officialStableVersion") != null
                    ? String.valueOf(policy.get("officialStableVersion")).trim() : null;
            if (chefVersion != null && chefVersion.isBlank()) chefVersion = null;
            String targetFixed = chefVersion != null ? chefVersion : body.get("fixedVersion");

            Map<String, Object> result = autoFixService.previewFix(
                    body.get("repoFullName"),
                    body.get("packageName"),
                    body.get("currentVersion"),
                    targetFixed,
                    body.get("cveId"),
                    body.get("filePath"),
                    body.get("source"),
                    provider.name(),
                    accessToken,
                    currentUser.getGitlabUrl(),
                    body.get("branch"));

            // Assisted-fix agent: attach human knowledge + LLM recommendation
            fixKnowledgeService.enrichPreview(
                    result,
                    body.get("repoFullName"),
                    body.get("packageName"),
                    body.get("currentVersion"),
                    targetFixed,
                    body.get("cveId"),
                    currentUser);

            result.put("officialStableVersion", policy.get("officialStableVersion"));
            result.put("officialComment", policy.get("officialComment"));
            result.put("policySource", policy.get("policySource"));
            result.put("fixedVersionUsed", targetFixed);
            if (chefVersion != null) {
                result.put("policyPreferredVersion", chefVersion);
            }

            return ResponseEntity.ok(result);
        } catch (Exception e) {
            String detail = e.getMessage() != null ? e.getMessage() : "Auto-fix preview failed";
            if (e instanceof org.springframework.web.client.HttpClientErrorException httpErr) {
                detail = friendlyGitHubError(httpErr, false);
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", detail));
        }
    }

    /**
     * Apply the fix: commits to Git, and optionally stores a human-edited fix + reason
     * into the knowledge base for the assisted-fix agent.
     */
    @PostMapping("/apply")
    public ResponseEntity<?> apply(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, Object> body) {

        User currentUser = userService.getRequiredUser(authHeader);
        AuthProvider provider = resolveProvider(str(body.get("provider")));
        try {
            String accessToken = userService.getAccessToken(currentUser, provider);
            if (accessToken == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", provider == AuthProvider.GITLAB
                                ? "Token GitLab manquant. Liez d'abord votre compte GitLab."
                                : "Token GitHub manquant. Liez d'abord votre compte GitHub."));
            }

            boolean developerEdited = bool(body.get("developerEdited"));
            boolean memorize = bool(body.get("memorize"));
            String chosenSource = str(body.get("chosenSource"));
            if (chosenSource == null || chosenSource.isBlank()) {
                chosenSource = "AI";
            } else {
                chosenSource = chosenSource.trim().toUpperCase();
            }
            String reason = str(body.get("reason"));
            String aiContent = str(body.get("aiFixedContent"));
            String fixedContent = str(body.get("fixedContent"));

            Long knowledgeId = null;
            String knowledgeIdRaw = str(body.get("knowledgeId"));
            if (knowledgeIdRaw != null && !knowledgeIdRaw.isBlank() && !"null".equals(knowledgeIdRaw)) {
                try {
                    knowledgeId = Long.parseLong(knowledgeIdRaw);
                } catch (NumberFormatException ignored) {
                }
            }

            boolean isHumanReuse = "HUMAN".equals(chosenSource) && knowledgeId != null && !developerEdited;
            boolean contentChanged = !isHumanReuse
                    && aiContent != null && fixedContent != null
                    && !normalizeNewlines(aiContent).equals(normalizeNewlines(fixedContent));
            boolean shouldSaveMemory = !isHumanReuse && (developerEdited || contentChanged || memorize);

            if (shouldSaveMemory && (reason == null || reason.isBlank())) {
                return ResponseEntity.badRequest().body(Map.of(
                        "error",
                        "Indiquez pourquoi vous avez choisi/modifié ce correctif (motif obligatoire pour la mémoire agent)."));
            }

            // Écart politique chef → bloquer le commit, demander validation chef.
            // IMPORTANT: ne jamais committer ni écrire RISK_ACCEPTED ici — seul un chef
            // qui accepte la demande déclenche le commit + l’audit « Risque accepté ».
            String packageName = str(body.get("packageName"));
            String filePath = str(body.get("filePath"));
            Map<String, Object> policy = cveJournalService.getPolicy(
                    str(body.get("cveId")), packageName);
            String official = policy.get("officialStableVersion") != null
                    ? String.valueOf(policy.get("officialStableVersion")).trim() : null;
            if (official != null && official.isBlank()) {
                official = null;
            }

            String chosenFromBody = str(body.get("fixedVersion"));
            String chosenFromContent = null;
            if (fixedContent != null && !fixedContent.isBlank() && packageName != null) {
                chosenFromContent = fixVersionValidationService.extractVersionFromContent(
                        fixedContent, packageName, filePath);
            }
            // Prefer content (what will actually be committed) over the declared version
            String chosenVersion = firstNonBlank(chosenFromContent, chosenFromBody);

            boolean deviation = official != null
                    && chosenVersion != null && !chosenVersion.isBlank()
                    && !PolicyDeviationService.versionsEquivalent(official, chosenVersion);

            if (deviation) {
                if (reason == null || reason.isBlank()) {
                    return ResponseEntity.badRequest().body(Map.of(
                            "error",
                            "Motif obligatoire : indiquez pourquoi vous dérogez à la version chef ("
                                    + official + "). La demande sera envoyée aux chefs — "
                                    + "aucun commit tant qu’un chef n’a pas accepté.",
                            "status", "NEEDS_REASON",
                            "officialVersion", official,
                            "proposedVersion", chosenVersion));
                }
                Map<String, Object> pending = policyDeviationService.createPendingRequest(
                        currentUser,
                        str(body.get("cveId")),
                        packageName,
                        official,
                        chosenVersion,
                        str(body.get("currentVersion")),
                        reason,
                        str(body.get("repoFullName")),
                        filePath,
                        str(body.get("sha")),
                        fixedContent,
                        str(body.get("lockFilePath")),
                        str(body.get("lockFileSha")),
                        str(body.get("lockFileContent")),
                        str(body.get("branch")),
                        provider.name(),
                        str(body.get("commitMessage")),
                        str(body.get("source")));
                return ResponseEntity.ok(pending);
            }

            Map<String, Object> result = autoFixService.applyFix(
                    str(body.get("repoFullName")),
                    filePath,
                    str(body.get("sha")),
                    fixedContent,
                    str(body.get("commitMessage")),
                    provider.name(),
                    accessToken,
                    str(body.get("branch")),
                    str(body.get("lockFilePath")),
                    str(body.get("lockFileSha")),
                    str(body.get("lockFileContent")),
                    currentUser.getGitlabUrl());

            // Reuse of an existing human knowledge entry without new edits
            if (isHumanReuse) {
                fixKnowledgeService.markUsed(knowledgeId);
                result.put("knowledgeId", knowledgeId);
                result.put("knowledgeSaved", false);
            }

            // Persist memory for agent (human edit / content change / explicit memorize)
            if (shouldSaveMemory) {
                String ecosystem = inferEcosystem(filePath, str(body.get("source")));
                FixKnowledge saved = fixKnowledgeService.saveHumanFix(
                        currentUser,
                        str(body.get("repoFullName")),
                        packageName,
                        str(body.get("cveId")),
                        str(body.get("currentVersion")),
                        firstNonBlank(chosenVersion, str(body.get("fixedVersion"))),
                        filePath,
                        ecosystem,
                        aiContent,
                        fixedContent,
                        reason);
                fixKnowledgeService.markUsed(saved.getId());
                result.put("knowledgeId", saved.getId());
                result.put("knowledgeSaved", true);
            }

            // Audit trail for direct commits only (aligned with chef policy).
            // « Risque accepté » is recorded exclusively when a chef approves a deviation.
            try {
                cveJournalService.recordFixApplied(
                        currentUser,
                        str(body.get("cveId")),
                        packageName,
                        str(body.get("currentVersion")),
                        firstNonBlank(chosenVersion, str(body.get("fixedVersion"))),
                        str(body.get("repoFullName")),
                        reason,
                        false);
            } catch (Exception auditErr) {
                // never block commit on audit failure
            }

            Map<String, Object> response = new LinkedHashMap<>(result);
            response.put("chosenSource", chosenSource);
            response.put("status", "COMMITTED");
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            String detail = e.getMessage() != null ? e.getMessage() : "Apply fix failed";
            if (e instanceof org.springframework.web.client.HttpClientErrorException httpErr) {
                detail = friendlyGitHubError(httpErr, true);
            }
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", detail));
        }
    }

    private String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String firstNonBlank(String... values) {
        if (values == null) return null;
        for (String v : values) {
            if (v != null && !v.isBlank()) return v.trim();
        }
        return null;
    }

    private boolean bool(Object value) {
        if (value instanceof Boolean b) return b;
        if (value == null) return false;
        return "true".equalsIgnoreCase(String.valueOf(value));
    }

    private String normalizeNewlines(String value) {
        return value.replace("\r\n", "\n").replace('\r', '\n');
    }

    /** Debug / verify agent memory for a CVE or package. */
    @GetMapping("/knowledge")
    public ResponseEntity<?> listKnowledge(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam(value = "cveId", required = false) String cveId,
            @RequestParam(value = "packageName", required = false) String packageName) {
        userService.getRequiredUser(authHeader);
        FixKnowledge match = fixKnowledgeService.findBestMatch(packageName, cveId, null, null);
        if (match == null) {
            return ResponseEntity.ok(Map.of(
                    "found", false,
                    "cveId", cveId != null ? cveId : "",
                    "packageName", packageName != null ? packageName : ""));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("found", true);
        body.put("knowledge", fixKnowledgeService.toDto(match));
        return ResponseEntity.ok(body);
    }

    /**
     * Double-check a manually chosen dependency version before commit.
     * Warns if the version may still be vulnerable vs scanner recommendation.
     */
    @PostMapping("/validate-version")
    public ResponseEntity<?> validateVersion(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody Map<String, Object> body) {
        User currentUser = userService.getRequiredUser(authHeader);
        try {
            Map<String, Object> result = fixVersionValidationService.validate(
                    currentUser,
                    str(body.get("packageName")),
                    str(body.get("currentVersion")),
                    str(body.get("recommendedVersion")),
                    str(body.get("chosenVersion")),
                    str(body.get("cveId")),
                    str(body.get("ecosystem")),
                    str(body.get("filePath")),
                    str(body.get("fixedContent")));
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", e.getMessage() != null ? e.getMessage() : "Validation failed"));
        }
    }

    private String inferEcosystem(String filePath, String source) {
        if (filePath != null) {
            String f = filePath.toLowerCase();
            if (f.endsWith("package.json") || f.endsWith("package-lock.json")) return "npm";
            if (f.endsWith("pom.xml")) return "maven";
            if (f.endsWith("requirements.txt")) return "pip";
        }
        if (source != null) {
            String s = source.toLowerCase();
            if (s.contains("npm")) return "npm";
            if (s.contains("maven") || s.contains("dependency-check")) return "maven";
            if (s.contains("pip") || s.contains("python")) return "pip";
        }
        return null;
    }

    private String friendlyGitHubError(
            org.springframework.web.client.HttpClientErrorException httpErr,
            boolean isApply) {
        int status = httpErr.getStatusCode().value();
        String ghMessage = extractGithubMessage(httpErr.getResponseBodyAsString());
        return switch (status) {
            case 401 -> "Token GitHub invalide ou expiré. Reconnectez votre compte GitHub dans Profil "
                    + "(OAuth ou nouveau PAT).";
            case 403 -> build403Message(ghMessage, isApply);
            case 404 -> isApply
                    ? "Dépôt, branche ou fichier introuvable (404). Causes fréquentes : "
                    + "token Fine-grained sans accès à CE dépôt, ou scope 'repo' manquant. "
                    + "Détail GitHub : " + ghMessage
                    : "Dépôt ou fichier introuvable (404). " + ghMessage;
            case 409 -> "Conflit (409) : le fichier a été modifié depuis la prévisualisation. "
                    + "Fermez ce correctif et régénérez-le.";
            case 422 -> "Requête invalide (422) : " + ghMessage;
            default -> httpErr.getStatusCode() + " " + httpErr.getStatusText() + ": " + ghMessage;
        };
    }

    private String build403Message(String ghMessage, boolean isApply) {
        String lower = ghMessage != null ? ghMessage.toLowerCase() : "";
        if (lower.contains("resource not accessible by personal access token")
                || lower.contains("resource not accessible by integration")) {
            return "GitHub refuse l'écriture avec ce PAT (403). "
                    + "Même si le token a 'Read and write', un Fine-grained PAT doit "
                    + "explicitement inclure CE dépôt (Repository access) et Contents = Read and write. "
                    + "Solution la plus simple : créez un Classic PAT avec le scope 'repo', "
                    + "puis liez-le dans Profil → Se connecter manuellement. "
                    + "Détail GitHub : " + ghMessage;
        }
        if (lower.contains("protected branch") || lower.contains("cannot force-push")
                || lower.contains("not authorized to push")) {
            return "Branche protégée (403) : votre compte n'a pas le droit de pousser "
                    + "directement sur cette branche. Changez la branche du scan, "
                    + "ou assouplissez la protection sur GitHub. Détail : " + ghMessage;
        }
        if (lower.contains("sso") || lower.contains("saml")) {
            return "Organisation GitHub avec SSO (403) : allez sur GitHub → Settings → "
                    + "Applications → Authorized OAuth Apps / PATs → Authorize SSO pour l'organisation. "
                    + "Détail : " + ghMessage;
        }
        return (isApply
                ? "Accès refusé en écriture (403). Causes fréquentes : "
                + "1) Fine-grained PAT sans ce dépôt sélectionné, "
                + "2) pas collaborateur avec droit Write sur le repo, "
                + "3) branche protégée, "
                + "4) SSO org non autorisé. "
                + "Préférez un Classic PAT (scope repo) lié dans Profil. "
                : "Accès refusé (403). ")
                + "Détail GitHub : " + ghMessage;
    }

    private String extractGithubMessage(String body) {
        if (body == null || body.isBlank()) {
            return "(aucun détail)";
        }
        try {
            com.fasterxml.jackson.databind.JsonNode root =
                    new com.fasterxml.jackson.databind.ObjectMapper().readTree(body);
            if (root.has("message")) {
                String msg = root.path("message").asText();
                if (root.has("documentation_url")) {
                    return msg + " (" + root.path("documentation_url").asText() + ")";
                }
                return msg;
            }
        } catch (Exception ignored) {
        }
        return body.length() > 300 ? body.substring(0, 300) + "…" : body;
    }

    private AuthProvider resolveProvider(String rawProvider) {
        if (rawProvider == null || rawProvider.isBlank()) {
            return AuthProvider.GITHUB;
        }
        return AuthProvider.valueOf(rawProvider.toUpperCase());
    }
}
