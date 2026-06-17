package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CveDto {
    private Long id;
    private String cveId;
    private String packageName;
    private String packageVersion;
    private String severity;
    private Double cvssScore;
    private String fixedVersion;
    private String description;
    private String dataSource;
    private String source;
    private String filePath;
    private Integer lineNumber;
    /** True if at least one public exploit exists on Exploit-DB. */
    private boolean exploitAvailable;
    /** URL to the first exploit on exploit-db.com, or null. */
    private String exploitUrl;
    /** True if this CVE is listed in the CISA KEV catalogue. */
    private boolean kevListed;
    /** ISO date when this CVE was added to the CISA KEV catalogue, or null. */
    private String kevDateAdded;
    /** True if linked to a known ransomware campaign per CISA KEV. */
    private boolean kevRansomware;
    /** EPSS probability score (0.0–1.0): chance of exploitation in next 30 days. */
    private Double epssScore;
    /**
     * EPSS percentile (0.0–1.0): this CVE is more dangerous than
     * epssPercentile*100% of all CVEs.
     */
    private Double epssPercentile;

    /** Number of distinct tools that detected this CVE (≥2 = multi-confirmed). */
    private int confirmedBy;

    /** Comma-separated list of tool names that detected this CVE. */
    private String sources;

    /**
     * OS platform affected: "WINDOWS", "LINUX", "CROSS_PLATFORM".
     * Extracted from NVD CPE data during enrichment.
     */
    private String affectedOs;
}
