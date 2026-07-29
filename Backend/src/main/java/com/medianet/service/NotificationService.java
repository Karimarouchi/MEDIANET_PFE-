package com.medianet.service;

import com.medianet.entity.*;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.PolicyDeviationRequestRepo;
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

    public NotificationService(
            AppNotificationRepo notificationRepo,
            UserRepo userRepo,
            AccessRoleService accessRoleService,
            PolicyDeviationRequestRepo deviationRequestRepo) {
        this.notificationRepo = notificationRepo;
        this.userRepo = userRepo;
        this.accessRoleService = accessRoleService;
        this.deviationRequestRepo = deviationRequestRepo;
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
