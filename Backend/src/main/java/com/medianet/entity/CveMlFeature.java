package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * One training row: a {@link CveRemediationRecord} plus Medianet context
 * known at {@code first_seen} (repos, package history, dependency shape)
 * and external signals (EPSS ≤ first_seen, CISA KEV). Labels stay internal:
 * {@code sla_breached} = Experiment A (lab 15/30/60/90), {@code days_to_fix}
 * = future regression target, never a classifier feature. Rebuilt each run;
 * exported via {@code GET /api/ml/features/export.csv}.
 */
@Entity
@Table(name = "cve_ml_features", indexes = @Index(name = "idx_ml_feature_remediation", columnList = "remediation_record_id"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveMlFeature {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "remediation_record_id", nullable = false)
    private Long remediationRecordId;

    /** Carried through for a chronological train/test split in the Python pipeline — never random-split this data. */
    @Column(name = "first_seen_at", nullable = false)
    private LocalDateTime firstSeenAt;

    @Column(name = "canonical_id", nullable = false, length = 180)
    private String canonicalId;

    private String packageName;

    @Column(name = "cwe_id", length = 32)
    private String cweId;

    @Column(nullable = false)
    private String severity;

    private Double cvssScore;

    private String ecosystem;

    // ── External signal: CISA KEV ───────────────────────────────────────
    @Column(name = "kev_listed", nullable = false)
    private boolean kevListed;

    @Column(name = "kev_ransomware", nullable = false)
    private boolean kevRansomware;

    /** Days between our first detection and CISA KEV listing (may be negative if KEV-listed before we saw it). */
    @Column(name = "days_to_kev_listing")
    private Integer daysToKevListing;

    // ── External signal: EPSS (current + historical trajectory) ────────
    @Column(name = "exploit_available", nullable = false)
    private boolean exploitAvailable;

    @Column(name = "epss_score_at_detection")
    private Double epssScoreAtDetection;

    @Column(name = "epss_score_latest")
    private Double epssScoreLatest;

    /** epssScoreLatest - epssScoreAtDetection (or earliest observed) — rising vs falling exploitability. */
    @Column(name = "epss_score_trend")
    private Double epssScoreTrend;

    @Column(name = "epss_observation_count", nullable = false)
    private int epssObservationCount;

    // ── Internal Medianet context at first_seen (no future leakage) ────
    /** Repos already known to have this CVE+package at detection — not later scans. */
    @Column(name = "affected_repo_count")
    private Integer affectedRepoCount;

    @Column(name = "package_occurrence_count")
    private Integer packageOccurrenceCount;

    @Column(name = "hist_mean_days_cwe")
    private Double histMeanDaysCwe;

    @Column(name = "hist_mean_days_ecosystem")
    private Double histMeanDaysEcosystem;

    @Column(name = "hist_mean_days_repo")
    private Double histMeanDaysRepo;

    @Column(name = "hist_mean_days_package")
    private Double histMeanDaysPackage;

    @Column(name = "dependency_depth")
    private Integer dependencyDepth;

    /** True = DIRECT, false = TRANSITIVE, null = unknown / no first-seen entry. */
    @Column(name = "direct_dependency")
    private Boolean directDependency;

    @Column(name = "fix_available_at_detection")
    private Boolean fixAvailableAtDetection;

    // ── Labels (internal only — never use days_to_fix as a classifier feature)
    /** Future regression target. Null while still open. */
    @Column(name = "days_to_fix")
    private Integer daysToFix;

    @Column(name = "sla_threshold_days", nullable = false)
    private int slaThresholdDays;

    @Column(name = "sla_breached", nullable = false)
    private boolean slaBreached;

    @Column(name = "built_at", nullable = false)
    private LocalDateTime builtAt;
}
