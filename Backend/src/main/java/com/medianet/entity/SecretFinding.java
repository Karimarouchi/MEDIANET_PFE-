package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "secret_findings")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecretFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ruleId;
    private String description;
    private String file;
    private Integer startLine;
    private Integer endLine;

    @Column(columnDefinition = "TEXT")
    private String match;

    private String author;
    private String email;
    private String date;
    private String commit;

    /** Which detectors reported it: "gitleaks", "credsweeper" or "gitleaks,credsweeper". */
    @Column(name = "detectors", length = 60)
    private String detectors;

    // ── triage by the ML model (see SecretTriageService) ──
    /** LIKELY_REAL, REVIEW or LIKELY_FALSE_POSITIVE; null when the model has not run. */
    @Column(name = "ml_verdict", length = 30)
    private String mlVerdict;

    @Column(name = "ml_proba")
    private Double mlProba;

    /** PRODUCTION or TEST_OR_DOC (test, example, documentation file). */
    @Column(name = "ml_scope", length = 20)
    private String mlScope;

    /** 1 = look first … 4 = probable false positive. */
    @Column(name = "ml_priority")
    private Integer mlPriority;

    @Column(name = "ml_reasons", columnDefinition = "TEXT")
    private String mlReasons;

    @Column(name = "ml_model_version", length = 30)
    private String mlModelVersion;

    /** The analyst's call, which overrides the model: REAL or FALSE_POSITIVE; null = not reviewed. */
    @Column(name = "analyst_verdict", length = 20)
    private String analystVerdict;

    /** Raw secret and entropy from gitleaks.json: used for the triage only, never stored. */
    @Transient
    private String rawSecret;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;
}
