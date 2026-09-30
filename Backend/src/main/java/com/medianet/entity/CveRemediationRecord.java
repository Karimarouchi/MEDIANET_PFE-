package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * One derived "life of a vulnerability in a repository" record: when a
 * CVE/package pair was first seen, whether and when it disappeared from a
 * later scan (= fixed), and whether that took longer than its severity's SLA
 * threshold. Rebuilt from scratch from existing scan history — not a source
 * of truth itself, a materialized training label for the ML risk model.
 */
@Entity
@Table(name = "cve_remediation_records", indexes = {
        @Index(name = "idx_remediation_repo", columnList = "repository_id"),
        @Index(name = "idx_remediation_canonical", columnList = "canonical_id")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveRemediationRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "repository_id", nullable = false)
    private Long repositoryId;

    /** canonical_id + package_name identify "the same vulnerability instance" across scans. */
    @Column(name = "canonical_id", length = 180, nullable = false)
    private String canonicalId;

    @Column(name = "package_name")
    private String packageName;

    @Column(name = "cwe_id", length = 32)
    private String cweId;

    @Column(nullable = false)
    private String severity;

    private Double cvssScore;

    @Column(name = "kev_listed", nullable = false)
    private boolean kevListed;

    @Column(name = "exploit_available", nullable = false)
    private boolean exploitAvailable;

    @Column(name = "epss_score_at_detection")
    private Double epssScoreAtDetection;

    @Column(name = "ecosystem")
    private String ecosystem;

    @Column(name = "first_seen_scan_id", nullable = false)
    private Long firstSeenScanId;

    @Column(name = "first_seen_at", nullable = false)
    private LocalDateTime firstSeenAt;

    /** Null while still open. */
    @Column(name = "fixed_scan_id")
    private Long fixedScanId;

    @Column(name = "fixed_at")
    private LocalDateTime fixedAt;

    @Column(name = "still_open", nullable = false)
    private boolean stillOpen;

    /** Only set once fixed. */
    @Column(name = "days_to_fix")
    private Integer daysToFix;

    @Column(name = "sla_threshold_days", nullable = false)
    private int slaThresholdDays;

    /**
     * true = confirmed breach (fixed late, or still open past threshold).
     * false = confirmed on-time fix.
     * null = censored — still open but not yet past threshold, outcome unknown, must be
     * excluded from model training (including it as a negative would bias the model).
     */
    @Column(name = "sla_breached")
    private Boolean slaBreached;

    @Column(name = "computed_at", nullable = false)
    private LocalDateTime computedAt;
}
