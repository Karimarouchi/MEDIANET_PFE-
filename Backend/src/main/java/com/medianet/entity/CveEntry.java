package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "cve_entries")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String cveId;
    private String packageName;
    private String packageVersion;

    @Column(nullable = false)
    private String severity;

    private Double cvssScore;
    private String fixedVersion;

    @Column(columnDefinition = "TEXT")
    private String description;

    private String dataSource;
    private String source;

    private String filePath;
    private Integer lineNumber;

    /** True if at least one public exploit exists on Exploit-DB for this CVE. */
    @Column(name = "exploit_available", nullable = false)
    private boolean exploitAvailable = false;

    /** URL to the first matching exploit on exploit-db.com (may be null). */
    @Column(name = "exploit_url")
    private String exploitUrl;

    /**
     * True if this CVE is listed in the CISA KEV (Known Exploited Vulnerabilities)
     * catalogue.
     */
    @Column(name = "kev_listed", nullable = false)
    private boolean kevListed = false;

    /** ISO date when this CVE was added to the CISA KEV catalogue (may be null). */
    @Column(name = "kev_date_added")
    private String kevDateAdded;

    /**
     * True if this CVE is linked to a known ransomware campaign in the CISA KEV
     * catalogue.
     */
    @Column(name = "kev_ransomware", nullable = false)
    private boolean kevRansomware = false;

    /**
     * EPSS probability score (0.0–1.0): estimated chance of exploitation in the
     * next 30 days.
     */
    @Column(name = "epss_score")
    private Double epssScore;

    /**
     * EPSS percentile (0.0–1.0): fraction of all CVEs with a lower EPSS score than
     * this one.
     */
    @Column(name = "epss_percentile")
    private Double epssPercentile;

    /**
     * Number of distinct tools that independently detected this CVE (≥2 = higher
     * confidence).
     */
    @Column(name = "confirmed_by", nullable = false)
    private int confirmedBy = 1;

    /**
     * Comma-separated list of tool names that detected this CVE (e.g.
     * "trivy,grype").
     */
    @Column(name = "sources")
    private String sources;

    /**
     * OS platform affected by this CVE, extracted from NVD CPE data.
     * Values: "WINDOWS", "LINUX", "CROSS_PLATFORM"
     */
    @Column(name = "affected_os")
    private String affectedOs;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;
}
