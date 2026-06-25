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

    // ─── SBOM enrichment fields ────────────────────────────────────────────────

    /** Exact name of the vulnerable component from the SBOM. */
    private String componentName;

    /** Exact version of the vulnerable component from the SBOM. */
    private String componentVersion;

    /** Component type (e.g. "library", "framework", "container"). */
    private String componentType;

    /** Package ecosystem (e.g. "npm", "maven", "pypi", "golang"). */
    private String ecosystem;

    /** Package manager (e.g. "npm", "mvn", "pip", "cargo"). */
    private String packageManager;

    /** Scope: "runtime", "dev", "test", "optional", "unknown". */
    private String dependencyScope;

    /** "DIRECT", "TRANSITIVE", or "UNKNOWN". */
    private String directOrTransitive;

    /** Depth from project root (1 = direct, >1 = transitive, null if unknown). */
    private Integer dependencyDepth;

    /** Human-readable path e.g. "frontend-rh -> axios -> follow-redirects". */
    private String dependencyPath;

    /** Package URL e.g. "pkg:npm/axios@0.21.1". */
    private String purl;

    /** BOM reference from the SBOM document. */
    private String bomRef;

    /** Manifest file path e.g. "frontend-rh/package-lock.json". */
    private String manifestFile;

    /** Module name derived from manifestFile (e.g. "frontend-rh", "Backend"). */
    private String moduleName;

    /**
     * Confidence of the direct/transitive classification: "HIGH", "MEDIUM", "LOW".
     */
    private String dependencyConfidence;
}
