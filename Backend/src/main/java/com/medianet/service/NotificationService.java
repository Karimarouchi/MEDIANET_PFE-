package com.medianet.service;

import com.medianet.entity.*;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.PolicyDeviationRequestRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.UserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class NotificationService {

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
     * Inbox alert when a GitHub Actions / CI scan finishes (commitSha present).
     * UI-triggered scans are skipped: the user already watches the live logs.
     */
    @Transactional
    public void notifyCiScanFinished(Long scanId) {
        if (scanId == null) {
            return;
        }
        ScanResult scan = scanResultRepo.findByIdWithRepository(scanId).orElse(null);
        if (scan == null || scan.getCommitSha() == null || scan.getCommitSha().isBlank()) {
            return;
        }
        ScanResult.ScanStatus status = scan.getStatus();
        if (status != ScanResult.ScanStatus.COMPLETED && status != ScanResult.ScanStatus.FAILED) {
            return;
        }

        Repository repo = scan.getRepository();
        String repoLabel = repoLabel(repo);
        String shortSha = shortSha(scan.getCommitSha());
        String link = scanReportLink(scan.getId(), repo != null ? repo.getId() : null);
        boolean failed = status == ScanResult.ScanStatus.FAILED;

        String title;
        String message;
        NotificationType type;
        if (failed) {
            type = NotificationType.SCAN_FAILED;
            title = "Scan CI en échec — " + repoLabel;
            message = "Le scan du commit " + shortSha + " n’a pas pu aboutir. Ouvrez le rapport pour voir les logs.";
        } else {
            List<CveEntry> cves = cveEntryRepo.findByScanResultId(scan.getId());
            int total = cves.size();
            long critical = cves.stream().filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
            long high = cves.stream().filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();
            boolean gateFail = critical + high > 0;
            type = NotificationType.SCAN_COMPLETED;
            title = (gateFail ? "Quality gate FAIL — " : "Scan CI terminé — ") + repoLabel;
            message = "Push scanné (" + shortSha + "). "
                    + total + " CVE"
                    + (critical > 0 || high > 0
                    ? " dont " + critical + " CRITICAL et " + high + " HIGH."
                    : ".")
                    + (gateFail
                    ? " La merge doit rester bloquée tant que ces vulnérabilités ne sont pas corrigées ou justifiées."
                    : " Aucune vulnérabilité CRITICAL/HIGH : quality gate vert.");
        }

        for (User recipient : ciScanRecipients(repo)) {
            notifyUser(recipient, type, title, message, link, scan.getId());
        }
    }

    private Set<User> ciScanRecipients(Repository repo) {
        Map<Long, User> byId = new LinkedHashMap<>();
        if (repo != null && repo.getOwnerUser() != null && isActive(repo.getOwnerUser())) {
            byId.put(repo.getOwnerUser().getId(), repo.getOwnerUser());
        }
        Long repoId = repo != null ? repo.getId() : null;
        if (repoId != null) {
            for (ClientRepository link : clientRepositoryRepo.findByRepository_Id(repoId)) {
                if (link.getClient() == null || link.getClient().getId() == null) {
                    continue;
                }
                for (EmployeeClient assignment : employeeClientRepo.findByClient_Id(link.getClient().getId())) {
                    User employee = assignment.getEmployee();
                    if (employee != null && isActive(employee)) {
                        byId.put(employee.getId(), employee);
                    }
                }
            }
        }
        for (User user : userRepo.findAll()) {
            if (user.getRole() == UserRole.ADMIN && isActive(user)) {
                byId.put(user.getId(), user);
            }
        }
        return new LinkedHashSet<>(byId.values());
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
            if (perms.contains(AccessPermission.CVE_JOURNAL)
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
