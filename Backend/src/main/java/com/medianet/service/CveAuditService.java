package com.medianet.service;

import com.medianet.entity.*;
import com.medianet.repository.CveAuditEventRepo;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

@Service
public class CveAuditService {

    private final CveAuditEventRepo auditEventRepo;

    public CveAuditService(CveAuditEventRepo auditEventRepo) {
        this.auditEventRepo = auditEventRepo;
    }

    @Transactional
    public CveAuditEvent record(
            CveAuditEventType type,
            String cveId,
            String packageName,
            User actor,
            String fromVersion,
            String toVersion,
            String officialVersion,
            String repoFullName,
            String message) {

        String login = null;
        if (actor != null) {
            login = actor.getLogin() != null ? actor.getLogin() : actor.getEmail();
        }

        CveAuditEvent event = CveAuditEvent.builder()
                .eventType(type)
                .cveId(cveId != null ? cveId.trim() : null)
                .packageName(packageName != null ? packageName.trim() : "")
                .actor(actor)
                .actorLogin(login)
                .fromVersion(blankToNull(fromVersion))
                .toVersion(blankToNull(toVersion))
                .officialVersion(blankToNull(officialVersion))
                .repoFullName(blankToNull(repoFullName))
                .message(blankToNull(message))
                .build();
        return auditEventRepo.save(event);
    }

    public List<Map<String, Object>> listTimeline(String cveId, String packageName) {
        String pkg = packageName != null ? packageName.trim() : "";
        List<CveAuditEvent> events;
        if (cveId == null || cveId.isBlank()) {
            events = List.of();
        } else if (pkg.isBlank()) {
            events = auditEventRepo.findByCveIdIgnoreCaseOrderByCreatedAtDesc(cveId.trim());
        } else {
            events = auditEventRepo.findTimeline(cveId.trim(), pkg);
            if (events.isEmpty()) {
                // also include CVE-level events (empty package)
                events = new ArrayList<>(auditEventRepo.findTimeline(cveId.trim(), ""));
            }
        }
        return events.stream().map(this::toDto).toList();
    }

    public boolean hasRiskAccepted(String cveId, String packageName) {
        if (cveId == null || cveId.isBlank()) return false;
        String pkg = packageName != null ? packageName.trim() : "";
        return auditEventRepo.existsByCveIdIgnoreCaseAndPackageNameIgnoreCaseAndEventType(
                cveId.trim(), pkg, CveAuditEventType.RISK_ACCEPTED)
                || auditEventRepo.existsByCveIdIgnoreCaseAndPackageNameIgnoreCaseAndEventType(
                cveId.trim(), "", CveAuditEventType.RISK_ACCEPTED);
    }

    public Map<String, Object> toDto(CveAuditEvent e) {
        Map<String, Object> dto = new LinkedHashMap<>();
        dto.put("id", e.getId());
        dto.put("cveId", e.getCveId());
        dto.put("packageName", e.getPackageName());
        dto.put("eventType", e.getEventType() != null ? e.getEventType().name() : null);
        dto.put("actorLogin", e.getActorLogin());
        dto.put("fromVersion", e.getFromVersion());
        dto.put("toVersion", e.getToVersion());
        dto.put("officialVersion", e.getOfficialVersion());
        dto.put("repoFullName", e.getRepoFullName());
        dto.put("message", e.getMessage());
        dto.put("createdAt", e.getCreatedAt() != null ? e.getCreatedAt().toString() : null);
        return dto;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
