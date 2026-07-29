package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Memory of a human-edited CVE fix: content + reason why the developer chose it.
 * Used by the assisted-fix agent to propose AI vs known human corrections.
 */
@Entity
@Table(name = "fix_knowledge", indexes = {
        @Index(name = "idx_fix_knowledge_cve_pkg", columnList = "cve_id, package_name"),
        @Index(name = "idx_fix_knowledge_pkg_ver", columnList = "package_name, from_version")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FixKnowledge {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", length = 64)
    private String cveId;

    @Column(name = "package_name", nullable = false, length = 255)
    private String packageName;

    @Column(name = "ecosystem", length = 64)
    private String ecosystem;

    @Column(name = "from_version", length = 128)
    private String fromVersion;

    @Column(name = "to_version", length = 128)
    private String toVersion;

    @Column(name = "file_path", length = 512)
    private String filePath;

    @Column(name = "repo_full_name", length = 255)
    private String repoFullName;

    @Column(name = "ai_content", columnDefinition = "TEXT")
    private String aiContent;

    @Column(name = "developer_content", nullable = false, columnDefinition = "TEXT")
    private String developerContent;

    @Column(name = "reason", nullable = false, columnDefinition = "TEXT")
    private String reason;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "created_by_id")
    private User createdBy;

    @Column(name = "created_by_login", length = 120)
    private String createdByLogin;

    @Builder.Default
    @Column(name = "usage_count", nullable = false)
    private int usageCount = 0;

    @Builder.Default
    @Column(name = "success_count", nullable = false)
    private int successCount = 0;

    @Builder.Default
    @Column(name = "fail_count", nullable = false)
    private int failCount = 0;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    @Builder.Default
    private FixKnowledgeStatus status = FixKnowledgeStatus.ACTIVE;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "last_used_at")
    private LocalDateTime lastUsedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (status == null) {
            status = FixKnowledgeStatus.ACTIVE;
        }
    }
}
