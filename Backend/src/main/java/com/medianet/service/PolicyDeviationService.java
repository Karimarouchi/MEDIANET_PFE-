package com.medianet.service;

import com.medianet.entity.*;
import com.medianet.repository.PolicyDeviationRequestRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.*;

@Service
public class PolicyDeviationService {

    private static final Logger log = LoggerFactory.getLogger(PolicyDeviationService.class);

    private final PolicyDeviationRequestRepo requestRepo;
    private final NotificationService notificationService;
    private final AutoFixService autoFixService;
    private final UserService userService;
    private final CveJournalService cveJournalService;
    private final AccessRoleService accessRoleService;
    private final JdbcTemplate jdbcTemplate;

    public PolicyDeviationService(
            PolicyDeviationRequestRepo requestRepo,
            NotificationService notificationService,
            AutoFixService autoFixService,
            UserService userService,
            CveJournalService cveJournalService,
            AccessRoleService accessRoleService,
            JdbcTemplate jdbcTemplate) {
        this.requestRepo = requestRepo;
        this.notificationService = notificationService;
        this.autoFixService = autoFixService;
        this.userService = userService;
        this.cveJournalService = cveJournalService;
        this.accessRoleService = accessRoleService;
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Hibernate ddl-auto=update does NOT widen existing varchar(512) → TEXT.
     * fixed_content / lock_file_content store full files and must be TEXT.
     */
    @Transactional(propagation = Propagation.NOT_SUPPORTED)
    public void ensureWideTextColumns() {
        String[] alters = {
                "ALTER TABLE policy_deviation_requests ALTER COLUMN fixed_content TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN lock_file_content TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN reason TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN review_comment TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN error_message TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN commit_message TYPE TEXT",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN file_path TYPE VARCHAR(1024)",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN lock_file_path TYPE VARCHAR(1024)",
                "ALTER TABLE policy_deviation_requests ALTER COLUMN commit_url TYPE VARCHAR(2048)",
        };
        for (String sql : alters) {
            try {
                jdbcTemplate.execute(sql);
            } catch (Exception e) {
                log.debug("[STARTUP] skip {}: {}", sql, e.getMessage());
            }
        }
        log.info("[STARTUP] policy_deviation_requests text columns ensured (fixed_content / lock_file_content)");
    }

    public static boolean versionsEquivalent(String a, String b) {
        if (a == null || b == null) return false;
        String na = a.replaceAll("^[^0-9]*", "").trim();
        String nb = b.replaceAll("^[^0-9]*", "").trim();
        return !na.isBlank() && na.equalsIgnoreCase(nb);
    }

    @Transactional
    public Map<String, Object> createPendingRequest(
            User developer,
            String cveId,
            String packageName,
            String officialVersion,
            String proposedVersion,
            String currentVersion,
            String reason,
            String repoFullName,
            String filePath,
            String fileSha,
            String fixedContent,
            String lockFilePath,
            String lockFileSha,
            String lockFileContent,
            String branch,
            String provider,
            String commitMessage,
            String source) {

        if (developer == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Le motif est obligatoire pour demander une dérogation à la politique chef.");
        }
        if (proposedVersion == null || proposedVersion.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Version proposée manquante.");
        }
        if (fixedContent == null || fixedContent.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Contenu du correctif manquant.");
        }

        String login = developer.getLogin() != null ? developer.getLogin() : developer.getEmail();

        // Commit message must attribute the change to the developer
        String msg = commitMessage;
        if (msg == null || msg.isBlank()) {
            msg = "fix: patch " + (cveId != null ? cveId : "")
                    + " — update " + packageName + " to " + proposedVersion
                    + " (par " + login + ", dérogation politique)";
        } else if (!msg.toLowerCase(Locale.ROOT).contains(login != null ? login.toLowerCase(Locale.ROOT) : "___")) {
            msg = msg + " — demandé par " + login;
        }

        PolicyDeviationRequest req = PolicyDeviationRequest.builder()
                .cveId(cveId)
                .packageName(packageName != null ? packageName : "")
                .officialVersion(officialVersion)
                .proposedVersion(proposedVersion.trim())
                .currentVersion(currentVersion)
                .reason(reason.trim())
                .status(PolicyDeviationStatus.PENDING)
                .requestedBy(developer)
                .requestedByLogin(login)
                .repoFullName(repoFullName)
                .filePath(filePath)
                .fileSha(fileSha)
                .fixedContent(fixedContent)
                .lockFilePath(lockFilePath)
                .lockFileSha(lockFileSha)
                .lockFileContent(lockFileContent)
                .branch(branch)
                .provider(provider)
                .commitMessage(msg)
                .source(source)
                .build();

        PolicyDeviationRequest saved;
        try {
            saved = requestRepo.save(req);
        } catch (DataIntegrityViolationException e) {
            String detail = e.getMostSpecificCause() != null ? e.getMostSpecificCause().getMessage() : e.getMessage();
            log.error("[POLICY] Failed to save deviation request: {}", detail);
            if (detail != null && detail.toLowerCase(Locale.ROOT).contains("value too long")) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Impossible d’enregistrer la dérogation : une colonne DB est trop petite (contenu du correctif). "
                                + "Redémarrez le backend (migration auto au démarrage), puis réessayez.",
                        e);
            }
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Impossible d’enregistrer la demande de dérogation. Réessayez ou contactez un admin.",
                    e);
        }

        String title = "Écart politique à valider — " + (cveId != null ? cveId : packageName);
        String message = login + " demande d’appliquer " + proposedVersion
                + " au lieu de la version chef " + officialVersion
                + " pour " + (packageName != null ? packageName : "ce package")
                + ". Motif : " + reason.trim();
        notificationService.notifyChefs(
                NotificationType.DEVIATION_REQUEST,
                title,
                message,
                "/cve-journal",
                saved.getId(),
                null);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("status", "PENDING_APPROVAL");
        out.put("requestId", saved.getId());
        out.put("message",
                "Demande envoyée aux chefs (Journal CVE). "
                        + "Le commit partira automatiquement au nom de " + login
                        + " si un chef accepte.");
        out.put("proposedVersion", saved.getProposedVersion());
        out.put("officialVersion", saved.getOfficialVersion());
        out.put("requestedByLogin", login);
        return out;
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> listPending(User chef) {
        requireChef(chef);
        return requestRepo.findAllPending().stream().map(this::toDto).toList();
    }

    @Transactional
    public Map<String, Object> approve(User chef, Long requestId, String reviewComment) {
        requireChef(chef);
        PolicyDeviationRequest req = requestRepo.findById(requestId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Demande introuvable."));

        if (req.getStatus() == PolicyDeviationStatus.APPROVED && req.getCommitUrl() != null) {
            notificationService.dismissRequestNotifications(req.getId());
            return toDto(req);
        }
        if (req.getStatus() == PolicyDeviationStatus.REJECTED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Cette demande a déjà été refusée.");
        }

        String chefLogin = chef.getLogin() != null ? chef.getLogin() : chef.getEmail();
        req.setReviewedBy(chef);
        req.setReviewedByLogin(chefLogin);
        req.setReviewComment(reviewComment != null ? reviewComment.trim() : null);
        req.setReviewedAt(LocalDateTime.now());

        User developer = req.getRequestedBy();
        AuthProvider provider = resolveProvider(req.getProvider());
        String accessToken;
        try {
            accessToken = userService.getAccessToken(developer, provider);
        } catch (Exception e) {
            accessToken = null;
        }
        if (accessToken == null || accessToken.isBlank()) {
            req.setStatus(PolicyDeviationStatus.COMMIT_FAILED);
            req.setErrorMessage("Token Git du développeur manquant ou expiré. "
                    + req.getRequestedByLogin() + " doit relier son compte Git.");
            requestRepo.save(req);
            notifyDevCommitFailed(req);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, req.getErrorMessage());
        }

        try {
            Map<String, Object> commitResult = autoFixService.applyFix(
                    req.getRepoFullName(),
                    req.getFilePath(),
                    req.getFileSha(),
                    req.getFixedContent(),
                    req.getCommitMessage(),
                    provider.name(),
                    accessToken,
                    req.getBranch(),
                    req.getLockFilePath(),
                    req.getLockFileSha(),
                    req.getLockFileContent(),
                    developer.getGitlabUrl());

            String commitUrl = commitResult.get("commitUrl") != null
                    ? String.valueOf(commitResult.get("commitUrl"))
                    : (commitResult.get("htmlUrl") != null ? String.valueOf(commitResult.get("htmlUrl")) : null);

            req.setStatus(PolicyDeviationStatus.APPROVED);
            req.setCommitUrl(commitUrl);
            req.setErrorMessage(null);
            requestRepo.save(req);

            notificationService.dismissRequestNotifications(req.getId());

            try {
                cveJournalService.recordFixApplied(
                        developer,
                        req.getCveId(),
                        req.getPackageName(),
                        req.getCurrentVersion(),
                        req.getProposedVersion(),
                        req.getRepoFullName(),
                        "Dérogation validée par " + chefLogin
                                + (req.getReason() != null ? " — " + req.getReason() : ""),
                        true);
            } catch (Exception auditErr) {
                log.warn("[PolicyDeviation] audit failed: {}", auditErr.getMessage());
            }

            notificationService.notifyUser(
                    developer,
                    NotificationType.DEVIATION_APPROVED,
                    "Dérogation acceptée — commit effectué",
                    "Votre demande pour " + req.getCveId() + " (" + req.getProposedVersion()
                            + " au lieu de " + req.getOfficialVersion() + ") a été acceptée par "
                            + chefLogin + ". Le commit a été poussé avec votre compte Git ("
                            + req.getRequestedByLogin() + ")."
                            + (commitUrl != null ? " " + commitUrl : ""),
                    commitUrl != null ? commitUrl : "/vulnerabilities",
                    req.getId());

            return toDto(req);
        } catch (Exception e) {
            log.error("[PolicyDeviation] auto-commit failed for request {}: {}", requestId, e.getMessage());
            req.setStatus(PolicyDeviationStatus.COMMIT_FAILED);
            req.setErrorMessage(e.getMessage());
            requestRepo.save(req);
            notificationService.dismissRequestNotifications(req.getId());
            notifyDevCommitFailed(req);
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Acceptation enregistrée mais le commit a échoué : " + e.getMessage());
        }
    }

    @Transactional
    public Map<String, Object> reject(User chef, Long requestId, String reviewComment) {
        requireChef(chef);
        PolicyDeviationRequest req = requestRepo.findById(requestId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Demande introuvable."));

        if (req.getStatus() == PolicyDeviationStatus.APPROVED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Demande déjà approuvée (commit effectué).");
        }
        if (req.getStatus() == PolicyDeviationStatus.REJECTED) {
            notificationService.dismissRequestNotifications(req.getId());
            return toDto(req);
        }

        String chefLogin = chef.getLogin() != null ? chef.getLogin() : chef.getEmail();
        req.setStatus(PolicyDeviationStatus.REJECTED);
        req.setReviewedBy(chef);
        req.setReviewedByLogin(chefLogin);
        req.setReviewComment(reviewComment != null ? reviewComment.trim() : null);
        req.setReviewedAt(LocalDateTime.now());
        requestRepo.save(req);

        notificationService.dismissRequestNotifications(req.getId());

        notificationService.notifyUser(
                req.getRequestedBy(),
                NotificationType.DEVIATION_REJECTED,
                "Dérogation refusée",
                "Votre demande pour " + req.getCveId() + " (version " + req.getProposedVersion()
                        + ") a été refusée par " + chefLogin + "."
                        + (req.getReviewComment() != null ? " Motif : " + req.getReviewComment() : "")
                        + " Aucun commit n’a été effectué. Utilisez la version chef "
                        + req.getOfficialVersion() + ".",
                "/vulnerabilities",
                req.getId());

        return toDto(req);
    }

    private void notifyDevCommitFailed(PolicyDeviationRequest req) {
        notificationService.notifyUser(
                req.getRequestedBy(),
                NotificationType.DEVIATION_COMMIT_FAILED,
                "Dérogation acceptée mais commit échoué",
                "Un chef a accepté votre écart pour " + req.getCveId()
                        + ", mais le commit au nom de " + req.getRequestedByLogin()
                        + " a échoué : " + (req.getErrorMessage() != null ? req.getErrorMessage() : "erreur")
                        + ". Vérifiez votre token Git et régénérez le correctif.",
                "/vulnerabilities",
                req.getId());
    }

    private void requireChef(User user) {
        if (user == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentification requise.");
        }
        Set<AccessPermission> perms = accessRoleService.getEffectivePermissions(user);
        boolean ok = perms.contains(AccessPermission.CVE_JOURNAL)
                || perms.contains(AccessPermission.PIPELINE)
                || user.getRole() == UserRole.ADMIN;
        if (!ok) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Permission Journal CVE requise pour valider les écarts.");
        }
    }

    private static AuthProvider resolveProvider(String provider) {
        if (provider == null || provider.isBlank()) return AuthProvider.GITHUB;
        try {
            return AuthProvider.valueOf(provider.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return AuthProvider.GITHUB;
        }
    }

    public Map<String, Object> toDto(PolicyDeviationRequest r) {
        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", r.getId());
        dto.put("cveId", r.getCveId());
        dto.put("packageName", r.getPackageName());
        dto.put("officialVersion", r.getOfficialVersion());
        dto.put("proposedVersion", r.getProposedVersion());
        dto.put("currentVersion", r.getCurrentVersion());
        dto.put("reason", r.getReason());
        dto.put("status", r.getStatus() != null ? r.getStatus().name() : null);
        dto.put("requestedByLogin", r.getRequestedByLogin());
        dto.put("reviewedByLogin", r.getReviewedByLogin());
        dto.put("reviewComment", r.getReviewComment());
        dto.put("repoFullName", r.getRepoFullName());
        dto.put("filePath", r.getFilePath());
        dto.put("branch", r.getBranch());
        dto.put("commitUrl", r.getCommitUrl());
        dto.put("commitMessage", r.getCommitMessage());
        dto.put("errorMessage", r.getErrorMessage());
        dto.put("createdAt", r.getCreatedAt() != null ? r.getCreatedAt().toString() : null);
        dto.put("reviewedAt", r.getReviewedAt() != null ? r.getReviewedAt().toString() : null);
        return dto;
    }
}
