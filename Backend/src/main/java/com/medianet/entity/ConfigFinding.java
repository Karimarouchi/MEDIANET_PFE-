package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

/**
 * A misconfiguration reported by Trivy, Checkov or Hadolint on a Dockerfile, a Kubernetes manifest, a Terraform file…
 * It is not a vulnerability: it has no CVE, no package and no CVSS, so it lives in its own table and never enters the
 * CVE counters or the CI gate.
 */
@Entity
@Table(name = "config_findings")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConfigFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Rule id of the first tool that reported it (DS-0002, CKV_DOCKER_3, DL3008…). */
    @Column(name = "rule_id", length = 80)
    private String ruleId;

    /** Every equivalent rule id reported for this finding, comma separated (one per tool). */
    @Column(name = "rule_ids", length = 300)
    private String ruleIds;

    @Column(length = 500)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String resolution;

    /** CRITICAL, HIGH, MEDIUM, LOW, INFO, or UNKNOWN when the tool gives no severity (Checkov). */
    @Column(length = 20)
    private String severity;

    /** DOCKERFILE, KUBERNETES, TERRAFORM, CI_CD or OTHER. */
    @Column(length = 30)
    private String category;

    @Column(length = 500)
    private String file;

    private Integer startLine;
    private Integer endLine;

    /** Checkov/Trivy resource name, e.g. "Deployment.default.web". */
    @Column(length = 300)
    private String resource;

    /** Tools that reported it: "trivy", "checkov", "hadolint" or a comma separated mix. */
    @Column(length = 80)
    private String sources;

    @Column(name = "reference_url", length = 500)
    private String referenceUrl;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;
}
