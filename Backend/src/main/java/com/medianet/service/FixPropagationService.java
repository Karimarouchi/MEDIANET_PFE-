package com.medianet.service;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Applies the chef official version to every still-open repository for a CVE.
 */
@Service
public class FixPropagationService {

    private static final int MAX_TARGETS = 25;

    private final CveExposureService exposureService;
    private final CveJournalService cveJournalService;
    private final AutoFixService autoFixService;
    private final UserService userService;

    public FixPropagationService(
            CveExposureService exposureService,
            CveJournalService cveJournalService,
            AutoFixService autoFixService,
            UserService userService) {
        this.exposureService = exposureService;
        this.cveJournalService = cveJournalService;
        this.autoFixService = autoFixService;
        this.userService = userService;
    }

    public Map<String, Object> propagate(User user, String cveId, String packageName, List<Long> repositoryIds) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        if (cveId == null || cveId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "cveId is required");
        }

        Map<String, Object> policy = cveJournalService.getPolicy(cveId, packageName);
        String chefVersion = policy.get("officialStableVersion") != null
                ? String.valueOf(policy.get("officialStableVersion")).trim() : null;
        if (chefVersion == null || chefVersion.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Aucune version chef. Définissez d'abord la version officielle dans le journal.");
        }

        List<CveExposureService.RepoHit> targets = exposureService.openTargets(user, cveId, packageName);
        Set<Long> wanted = repositoryIds == null ? Set.of() : new HashSet<>(repositoryIds);
        if (!wanted.isEmpty()) {
            targets = targets.stream()
                    .filter(t -> t.repositoryId != null && wanted.contains(t.repositoryId))
                    .toList();
        }

        int truncated = 0;
        if (targets.size() > MAX_TARGETS) {
            truncated = targets.size() - MAX_TARGETS;
            targets = targets.subList(0, MAX_TARGETS);
        }

        List<Map<String, Object>> results = new ArrayList<>();
        int committed = 0;
        int skipped = 0;
        int failed = 0;

        for (CveExposureService.RepoHit target : targets) {
            Map<String, Object> row = applyOne(user, cveId, chefVersion, target);
            results.add(row);
            String status = String.valueOf(row.get("status"));
            if ("COMMITTED".equals(status)) {
                committed++;
            } else if ("FAILED".equals(status)) {
                failed++;
            } else {
                skipped++;
            }
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("cveId", cveId);
        out.put("packageName", packageName);
        out.put("officialStableVersion", chefVersion);
        out.put("attempted", results.size());
        out.put("committed", committed);
        out.put("skipped", skipped);
        out.put("failed", failed);
        out.put("truncated", truncated);
        out.put("results", results);
        return out;
    }

    private Map<String, Object> applyOne(
            User user, String cveId, String chefVersion, CveExposureService.RepoHit target) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("repositoryId", target.repositoryId);
        row.put("repoFullName", target.repoFullName);
        row.put("repoName", target.repoName);
        row.put("packageName", target.packageName);
        row.put("fromVersion", target.packageVersion);
        row.put("toVersion", chefVersion);

        if (target.repoFullName == null || target.repoFullName.isBlank()) {
            return skip(row, "NO_REPO", "URL de dépôt illisible.");
        }
        if (!CveExposureService.canPropagate(true, chefVersion, target.packageVersion)) {
            return skip(row, "ALREADY_AT_POLICY", "Ce dépôt est déjà à la version chef.");
        }

        AuthProvider provider;
        try {
            provider = AuthProvider.valueOf(
                    target.gitProvider != null ? target.gitProvider.trim().toUpperCase() : "GITHUB");
        } catch (Exception e) {
            provider = AuthProvider.GITHUB;
        }
        if (provider == AuthProvider.LOCAL) {
            return skip(row, "UNSUPPORTED_PROVIDER", "Correctif Git uniquement (GitHub / GitLab).");
        }

        String token = userService.getAccessToken(user, provider);
        if (token == null || token.isBlank()) {
            return skip(row, "NEED_TOKEN",
                    provider == AuthProvider.GITLAB
                            ? "Liez votre compte GitLab dans Profil."
                            : "Liez votre compte GitHub dans Profil.");
        }

        String pkg = target.packageName != null ? target.packageName : "";
        String filePath = target.filePath != null ? target.filePath : target.manifestFile;
        String reason = "Propagation de la version chef " + chefVersion
                + " vers " + target.repoFullName + ".";
        try {
            Map<String, Object> preview = autoFixService.previewFix(
                    target.repoFullName,
                    pkg,
                    target.packageVersion,
                    chefVersion,
                    cveId,
                    filePath,
                    target.source,
                    provider.name(),
                    token,
                    user.getGitlabUrl(),
                    target.branch);
            String fixedContent = String.valueOf(preview.get("fixedContent"));
            String sha = preview.get("sha") != null ? String.valueOf(preview.get("sha")) : "";
            String resolvedPath = preview.get("filePath") != null
                    ? String.valueOf(preview.get("filePath")) : filePath;
            String commitMessage = "fix: propagate chef policy " + cveId
                    + " — update " + pkg + " to " + chefVersion;

            Map<String, Object> applied = autoFixService.applyFix(
                    target.repoFullName,
                    resolvedPath,
                    sha,
                    fixedContent,
                    commitMessage,
                    provider.name(),
                    token,
                    target.branch,
                    str(preview.get("lockFilePath")),
                    str(preview.get("lockFileSha")),
                    str(preview.get("lockFileContent")),
                    user.getGitlabUrl());

            cveJournalService.recordFixApplied(
                    user, cveId, pkg, target.packageVersion, chefVersion,
                    target.repoFullName, reason, false);

            row.put("status", "COMMITTED");
            row.put("commitUrl", applied.get("commitUrl") != null ? applied.get("commitUrl") : applied.get("htmlUrl"));
            row.put("filePath", resolvedPath);
            return row;
        } catch (Exception e) {
            row.put("status", "FAILED");
            row.put("reason", e.getMessage() != null ? e.getMessage() : "Échec du correctif");
            return row;
        }
    }

    private static Map<String, Object> skip(Map<String, Object> row, String code, String message) {
        row.put("status", "SKIPPED");
        row.put("reasonCode", code);
        row.put("reason", message);
        return row;
    }

    private static String str(Object value) {
        return value == null || "null".equals(String.valueOf(value)) ? null : String.valueOf(value);
    }
}
