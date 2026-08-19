package com.medianet.service;

import com.medianet.entity.*;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.PolicyDeviationRequestRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.UserRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    /** Dev outcome messages (approved / rejected / commit failed) stay visible 15 minutes. */
    public static final int DEV_OUTCOME_TTL_MINUTES = 15;

    private static final List<NotificationType> OUTCOME_TYPES = List.of(
            NotificationType.DEVIATION_APPROVED,
            NotificationType.DEVIATION_REJECTED,
            NotificationType.DEVIATION_COMMIT_FAILED);

    private final AppNotificationRepo notificationRepo;
    private final UserRepo userRepo;
    private final AccessRoleService accessRoleService;
    private final PolicyDeviationRequestRepo deviationRequestRepo;
    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final ClientRepositoryRepo clientRepositoryRepo;
    private final EmployeeClientRepo employeeClientRepo;

    public NotificationService(
            AppNotificationRepo notificationRepo,
            UserRepo userRepo,
            AccessRoleService accessRoleService,
            PolicyDeviationRequestRepo deviationRequestRepo,
            ScanResultRepo scanResultRepo,
            CveEntryRepo cveEntryRepo,
            ClientRepositoryRepo clientRepositoryRepo,
            EmployeeClientRepo employeeClientRepo) {
        this.notificationRepo = notificationRepo;
        this.userRepo = userRepo;
        this.accessRoleService = accessRoleService;
        this.deviationRequestRepo = deviationRequestRepo;
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.clientRepositoryRepo = clientRepositoryRepo;
        this.employeeClientRepo = employeeClientRepo;
    }

    @Transactional
    public AppNotification notifyUser(
            User recipient,
            NotificationType type,
            String title,
            String message,
            String link,
            Long relatedRequestId) {
        if (recipient == null) return null;
        AppNotification n = AppNotification.builder()
                .recipient(recipient)
                .type(type)
                .title(title)
                .message(message)
                .link(link)
                .relatedRequestId(relatedRequestId)
                .read(false)
                .build();
        return notificationRepo.save(n);
    }

    /**
     * Notify every collaborator of every project that owns this repository
     * when a scan (UI or git push) finishes.
     */
    @Transactional(propagation = org.springframework.transaction.annotation.Propagation.REQUIRES_NEW)
    public void notifyCiScanFinished(Long scanId) {
        if (scanId == null) {
            return;
        }
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId).orElse(null);
        if (scan == null) {
            return;
        }
        ScanResult.ScanStatus status = scan.getStatus();
        if (status != ScanResult.ScanStatus.COMPLETED && status != ScanResult.ScanStatus.FAILED) {
            return;
        }

        Repository repo = scan.getRepository();
        String repoLabel = repoLabel(repo);
        String projectLabel = projectLabel(repo);
        boolean gitPush = scan.getCommitSha() != null && !scan.getCommitSha().isBlank();
        String shortSha = shortSha(scan.getCommitSha());
        String gitHost = gitPushHost(repo);
        String link = scanReportLink(scan.getId(), repo != null ? repo.getId() : null);
        boolean failed = status == ScanResult.ScanStatus.FAILED;

        String title;
        String message;
        NotificationType type;
        if (failed) {
            type = NotificationType.SCAN_FAILED;
            if (gitPush) {
                title = "Scan automatique en échec — git push — " + repoLabel;
                message = "Projet " + projectLabel + ". Scan automatique (git push " + gitHost
                        + ") du commit " + shortSha + " : le scan n’a pas pu aboutir.";
            } else {
                title = "Scan en échec — " + repoLabel;
                message = "Projet " + projectLabel + ". Le scan du dépôt " + repoLabel + " a échoué.";
            }
        } else {
            List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
            int total = cves.size();
            long critical = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
            long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
            boolean gateFail = critical + high > 0;
            type = NotificationType.SCAN_COMPLETED;
            String counts = total + " CVE"
                    + (critical > 0 || high > 0
                    ? " dont " + critical + " CRITICAL et " + high + " HIGH."
                    : ".");
            if (gitPush) {
                title = (gateFail ? "Scan automatique FAIL — git push — " : "Scan automatique terminé — git push — ")
                        + repoLabel;
                message = "Projet " + projectLabel + ". Scan automatique déclenché par un git push ("
                        + gitHost + "), commit " + shortSha + ". " + counts;
            } else {
                title = (gateFail ? "Scan terminé (vulnérabilités) — " : "Scan terminé — ") + repoLabel;
                message = "Projet " + projectLabel + ". Le scan du dépôt " + repoLabel + " est terminé. " + counts;
            }
        }

        Set<User> recipients = projectCollaborators(repo);
        if (recipients.isEmpty()) {
            log.warn("Scan {} finished but no project collaborator to notify for repo {}",
                    scan.getId(), repo != null ? repo.getId() : null);
            return;
        }
        int sent = 0;
        for (User recipient : recipients) {
            if (notificationRepo.existsByRecipient_IdAndTypeAndRelatedRequestId(
                    recipient.getId(), type, scan.getId())) {
                continue;
            }
            notifyUser(recipient, type, title, message, link, scan.getId());
            sent++;
        }
        log.info("Scan {} notifications sent={} recipients={} repo={} gitPush={}",
                scan.getId(), sent, recipients.size(), repo != null ? repo.getId() : null, gitPush);
    }

    /** Employees assigned to any project that lists this repository. */
    private Set<User> projectCollaborators(Repository repo) {
        Map<Long, User> byId = new LinkedHashMap<>();
        Long repoId = repo != null ? repo.getId() : null;
        if (repoId != null) {
            for (User collaborator : employeeClientRepo.findCollaboratorsByRepositoryId(repoId)) {
                if (isActive(collaborator) && collaborator.getId() != null) {
                    byId.put(collaborator.getId(), collaborator);
                }
            }
            for (ClientRepository link : clientRepositoryRepo.findByRepository_Id(repoId)) {
                if (link.getClient() == null || link.getClient().getId() == null) {
                    continue;
                }
                for (EmployeeClient assignment : employeeClientRepo.findByClient_Id(link.getClient().getId())) {
                    User employee = assignment.getEmployee();
                    if (employee != null && isActive(employee) && employee.getId() != null) {
                        byId.put(employee.getId(), employee);
                    }
                }
            }
        }
        if (repo != null && repo.getOwnerUser() != null && isActive(repo.getOwnerUser())
                && repo.getOwnerUser().getId() != null) {
            byId.put(repo.getOwnerUser().getId(), repo.getOwnerUser());
        }
        return new LinkedHashSet<>(byId.values());
    }

    private String projectLabel(Repository repo) {
        Long repoId = repo != null ? repo.getId() : null;
        if (repoId == null) {
            return "projet";
        }
        List<String> names = new ArrayList<>();
        for (ClientRepository link : clientRepositoryRepo.findByRepository_Id(repoId)) {
            if (link.getClient() != null && link.getClient().getName() != null
                    && !link.getClient().getName().isBlank()) {
                names.add(link.getClient().getName());
            }
        }
        if (names.isEmpty()) {
            return "projet";
        }
        return String.join(", ", names);
    }

    static String gitPushHost(Repository repo) {
        String url = repo != null ? repo.getRepoUrl() : null;
        if (url != null && url.toLowerCase(Locale.ROOT).contains("gitlab")) {
            return "GitLab CI";
        }
        if (url != null && url.toLowerCase(Locale.ROOT).contains("github")) {
            return "GitHub Actions";
        }
        return "git";
    }

    private static boolean isActive(User user) {
        return user != null && !Boolean.TRUE.equals(user.getSuspended());
    }

    private static String repoLabel(Repository repo) {
        if (repo == null) {
            return "dépôt";
        }
        String slug = CiScanService.normalizeGithubSlug(repo.getRepoUrl());
        if (slug != null && !slug.isBlank()) {
            return slug;
        }
        return repo.getRepoUrl() != null && !repo.getRepoUrl().isBlank() ? repo.getRepoUrl() : "dépôt";
    }

    private static String shortSha(String sha) {
        if (sha == null || sha.isBlank()) {
            return "—";
        }
        String value = sha.trim();
        return value.length() <= 7 ? value : value.substring(0, 7);
    }

    private static String scanReportLink(Long scanId, Long repoId) {
        StringBuilder url = new StringBuilder("/vulnerabilities");
        if (scanId != null) {
            url.append("?scanId=").append(scanId);
            if (repoId != null) {
                url.append("&repoId=").append(repoId);
            }
        } else if (repoId != null) {
            url.append("?repoId=").append(repoId);
        }
        return url.toString();
    }

    /** Notify every account that has CVE_JOURNAL permission (chefs), plus ADMIN. */
    @Transactional
    public void notifyChefs(
            NotificationType type,
            String title,
            String message,
            String link,
            Long relatedRequestId,
            Long excludeUserId) {
        List<User> chefs = listChefUsers();
        boolean any = false;
        for (User u : chefs) {
            if (excludeUserId != null && excludeUserId.equals(u.getId()) && chefs.size() > 1) {
                continue;
            }
            notifyUser(u, type, title, message, link, relatedRequestId);
            any = true;
        }
        if (!any && excludeUserId != null) {
            for (User u : chefs) {
                if (excludeUserId.equals(u.getId())) {
                    notifyUser(u, type, title, message, link, relatedRequestId);
                    break;
                }
            }
        }
    }

    /**
     * After accept/refuse: remove pending-request notifications for all chefs
     * so a treated écart never stays in the inbox.
     */
    @Transactional
    public void dismissRequestNotifications(Long relatedRequestId) {
        if (relatedRequestId == null) return;
        notificationRepo.deleteByRelatedRequestIdAndType(
                relatedRequestId, NotificationType.DEVIATION_REQUEST);
    }

    public List<User> listChefUsers() {
        List<User> chefs = new ArrayList<>();
        for (User u : userRepo.findAll()) {
            if (Boolean.TRUE.equals(u.getSuspended())) continue;
            Set<AccessPermission> perms = accessRoleService.getEffectivePermissions(u);
            if ((perms != null && perms.contains(AccessPermission.CVE_JOURNAL))
                    || u.getRole() == UserRole.ADMIN) {
                chefs.add(u);
            }
        }
        return chefs;
    }

    @Transactional
    public List<Map<String, Object>> listForUser(User user) {
        purgeExpiredOutcomes(user.getId());
        Set<Long> pendingRequestIds = loadPendingRequestIds();
        LocalDateTime outcomeCutoff = LocalDateTime.now().minusMinutes(DEV_OUTCOME_TTL_MINUTES);

        return notificationRepo.findByRecipient_IdOrderByCreatedAtDesc(user.getId())
                .stream()
                .filter(n -> isVisible(n, pendingRequestIds, outcomeCutoff))
                .limit(50)
                .map(this::toDto)
                .toList();
    }

    @Transactional
    public long unreadCount(User user) {
        purgeExpiredOutcomes(user.getId());
        Set<Long> pendingRequestIds = loadPendingRequestIds();
        LocalDateTime outcomeCutoff = LocalDateTime.now().minusMinutes(DEV_OUTCOME_TTL_MINUTES);

        return notificationRepo.findByRecipient_IdOrderByCreatedAtDesc(user.getId())
                .stream()
                .filter(n -> !n.isRead())
                .filter(n -> isVisible(n, pendingRequestIds, outcomeCutoff))
                .count();
    }

    @Transactional
    public void markRead(User user, Long id) {
        AppNotification n = notificationRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Notification introuvable."));
        if (!n.getRecipient().getId().equals(user.getId())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Notification non autorisée.");
        }
        n.setRead(true);
        notificationRepo.save(n);
    }

    @Transactional
    public void markAllRead(User user) {
        notificationRepo.markAllReadForUser(user.getId());
    }

    @Transactional
    public void clearAll(User user) {
        notificationRepo.deleteAllForUser(user.getId());
    }

    private void purgeExpiredOutcomes(Long userId) {
        LocalDateTime before = LocalDateTime.now().minusMinutes(DEV_OUTCOME_TTL_MINUTES);
        notificationRepo.deleteExpiredOutcomesForUser(userId, OUTCOME_TYPES, before);
    }

    private Set<Long> loadPendingRequestIds() {
        return deviationRequestRepo.findAllPending().stream()
                .map(PolicyDeviationRequest::getId)
                .collect(Collectors.toSet());
    }

    private boolean isVisible(
            AppNotification n,
            Set<Long> pendingRequestIds,
            LocalDateTime outcomeCutoff) {
        NotificationType type = n.getType();
        if (type == null) return false;

        if (type == NotificationType.DEVIATION_REQUEST) {
            Long reqId = n.getRelatedRequestId();
            return reqId != null && pendingRequestIds.contains(reqId);
        }

        if (OUTCOME_TYPES.contains(type)) {
            LocalDateTime created = n.getCreatedAt();
            return created != null && !created.isBefore(outcomeCutoff);
        }

        return true;
    }

    public Map<String, Object> toDto(AppNotification n) {
        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", n.getId());
        dto.put("type", n.getType() != null ? n.getType().name() : null);
        dto.put("title", n.getTitle());
        dto.put("message", n.getMessage());
        dto.put("link", n.getLink());
        dto.put("relatedRequestId", n.getRelatedRequestId());
        dto.put("read", n.isRead());
        dto.put("createdAt", n.getCreatedAt() != null ? n.getCreatedAt().toString() : null);
        return dto;
    }
}
