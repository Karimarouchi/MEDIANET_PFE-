package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "cve_audit_events", indexes = {
        @Index(name = "idx_cve_audit_cve_pkg", columnList = "cve_id, package_name"),
        @Index(name = "idx_cve_audit_created", columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveAuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", length = 64)
    private String cveId;

    @Column(name = "package_name", length = 255)
    @Builder.Default
    private String packageName = "";

    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false, length = 32)
    private CveAuditEventType eventType;

    @Column(name = "actor_login", length = 120)
    private String actorLogin;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_id")
    private User actor;

    @Column(name = "from_version", length = 128)
    private String fromVersion;

    @Column(name = "to_version", length = 128)
    private String toVersion;

    @Column(name = "official_version", length = 128)
    private String officialVersion;

    @Column(name = "repo_full_name", length = 255)
    private String repoFullName;

    @Column(name = "message", columnDefinition = "TEXT")
    private String message;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (packageName == null) packageName = "";
    }
}
