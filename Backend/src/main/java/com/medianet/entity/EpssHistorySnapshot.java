package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

/**
 * One historical EPSS score observation for one CVE on one date, sourced
 * from FIRST.org's public daily archive (github.com/empiricalsec/epss_scores).
 * Only CVEs actually seen in our own scans are ingested — the daily files
 * cover every known CVE (hundreds of thousands), which we don't need.
 */
@Entity
@Table(name = "epss_history_snapshots",
        uniqueConstraints = @UniqueConstraint(columnNames = {"cve_id", "snapshot_date"}),
        indexes = @Index(name = "idx_epss_history_cve", columnList = "cve_id"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EpssHistorySnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false, length = 32)
    private String cveId;

    @Column(name = "snapshot_date", nullable = false)
    private LocalDate snapshotDate;

    @Column(name = "epss_score", nullable = false)
    private double epssScore;

    @Column(name = "percentile", nullable = false)
    private double percentile;
}
