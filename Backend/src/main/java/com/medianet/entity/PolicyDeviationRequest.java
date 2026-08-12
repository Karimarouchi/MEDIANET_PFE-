package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;

@Entity
@Table(name = "policy_deviation_requests", indexes = {
        @Index(name = "idx_policy_dev_status", columnList = "status"),
        @Index(name = "idx_policy_dev_cve", columnList = "cve_id, package_name")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PolicyDeviationRequest {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", length = 64)
    private String cveId;

    @Column(name = "package_name", length = 255)
    private String packageName;

    @Column(name = "official_version", length = 128)
    private String officialVersion;

    @Column(name = "proposed_version", nullable = false, length = 128)
    private String proposedVersion;

    @Column(name = "current_version", length = 128)
    private String currentVersion;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "reason", nullable = false, columnDefinition = "TEXT")
    private String reason;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 24)
    private PolicyDeviationStatus status;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "requested_by_id", nullable = false)
    private User requestedBy;

    @Column(name = "requested_by_login", length = 120)
    private String requestedByLogin;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "reviewed_by_id")
    private User reviewedBy;

    @Column(name = "reviewed_by_login", length = 120)
    private String reviewedByLogin;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "review_comment", columnDefinition = "TEXT")
    private String reviewComment;

    @Column(name = "repo_full_name", length = 255)
    private String repoFullName;

    @Column(name = "file_path", length = 1024)
    private String filePath;

    @Column(name = "file_sha", length = 128)
    private String fileSha;

    /** Full patched file (package.json, etc.) — must be TEXT, not varchar(512). */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "fixed_content", columnDefinition = "TEXT")
    private String fixedContent;

    @Column(name = "lock_file_path", length = 1024)
    private String lockFilePath;

    @Column(name = "lock_file_sha", length = 128)
    private String lockFileSha;

    /** Full lockfile content (package-lock.json…) — often >> 512 chars. */
    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "lock_file_content", columnDefinition = "TEXT")
    private String lockFileContent;

    @Column(name = "branch", length = 255)
    private String branch;

    @Column(name = "provider", length = 32)
    private String provider;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "commit_message", columnDefinition = "TEXT")
    private String commitMessage;

    @Column(name = "commit_url", length = 2048)
    private String commitUrl;

    @Column(name = "source", length = 64)
    private String source;

    @JdbcTypeCode(SqlTypes.LONGVARCHAR)
    @Column(name = "error_message", columnDefinition = "TEXT")
    private String errorMessage;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "reviewed_at")
    private LocalDateTime reviewedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (status == null) status = PolicyDeviationStatus.PENDING;
        if (packageName == null) packageName = "";
    }
}
