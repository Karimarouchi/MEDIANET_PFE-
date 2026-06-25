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

    // ─── SBOM enrichment fields ────────────────────────────────────────────────

    /** Exact name of the vulnerable component as found in the SBOM. */
    @Column(name = "component_name")
    private String componentName;

    /** Exact version of the vulnerable component as found in the SBOM. */
    @Column(name = "component_version")
    private String componentVersion;

    /**
     * Component type from the SBOM (e.g. "library", "framework", "container",
     * "operating-system").
     */
    @Column(name = "component_type")
    private String componentType;

    /**
     * Package ecosystem (e.g. "npm", "maven", "pypi", "deb", "rpm", "golang",
     * "cargo"). Derived from PURL scheme or artifact.type.
     */
    @Column(name = "ecosystem")
    private String ecosystem;

    /**
     * Package manager that manages this dependency (e.g. "npm", "yarn", "mvn",
     * "pip", "cargo").
     */
    @Column(name = "package_manager")
    private String packageManager;

    /**
     * Scope in which this dependency is used: "runtime", "dev", "test",
     * "optional", "unknown".
     */
    @Column(name = "dependency_scope")
    private String dependencyScope;

    /**
     * Whether the dependency is direct or transitive.
     * Values: "DIRECT", "TRANSITIVE", "UNKNOWN".
     * Never set to DIRECT/TRANSITIVE unless evidence from the dependency graph
     * supports it.
     */
    @Column(name = "direct_or_transitive")
    private String directOrTransitive = "UNKNOWN";

    /**
     * Number of hops from the project root (or module root) to this component.
     * 1 = direct dependency, >1 = transitive. Null if graph is not available.
     */
    @Column(name = "dependency_depth")
    private Integer dependencyDepth;

    /**
     * Human-readable dependency path, e.g.
     * "frontend-rh -> axios -> follow-redirects". Null if not resolvable.
     */
    @Column(name = "dependency_path", columnDefinition = "TEXT")
    private String dependencyPath;

    /**
     * Package URL (PURL) of the vulnerable component.
     * e.g. "pkg:npm/axios@0.21.1".
     */
    @Column(name = "purl")
    private String purl;

    /**
     * BOM reference identifier from the SBOM (CycloneDX bomRef or Syft ID).
     * Used for precise cross-referencing inside the SBOM document.
     */
    @Column(name = "bom_ref")
    private String bomRef;

    /**
     * Path to the manifest file that declares or pins this dependency
     * (e.g. "frontend-rh/package-lock.json", "Backend/pom.xml").
     */
    @Column(name = "manifest_file")
    private String manifestFile;

    /**
     * Name of the project module that directly contains this dependency.
     * Derived from the first path segment of manifestFile
     * (e.g. "frontend-rh", "Backend").
     */
    @Column(name = "module_name")
    private String moduleName;

    /**
     * Confidence level of the DIRECT/TRANSITIVE/UNKNOWN classification.
     * Values: "HIGH" (PURL/bomRef + full graph), "MEDIUM" (name/version/eco
     * matching), "LOW" (fallback or missing SBOM).
     */
    @Column(name = "dependency_confidence")
    private String dependencyConfidence = "LOW";

    /**
     * PHASE 1: How the component was matched in the SBOM.
     * Values: "PURL_EXACT" (exact PURL match), "BOM_REF_EXACT" (exact bomRef match),
     * "NAME_VERSION_ECOSYSTEM" (name+version+eco match), "NONE" (no match).
     */
    @Column(name = "component_match_method")
    private String componentMatchMethod = "NONE";

    /**
     * PHASE 1: Confidence of the component matching method.
     * Values: "HIGH" (PURL or bomRef exact match), "MEDIUM" (name+version+eco match),
     * "LOW" (fallback or partial match).
     */
    @Column(name = "component_match_confidence")
    private String componentMatchConfidence = "LOW";

    /**
     * PHASE 1: Confidence level of the dependency graph resolution.
     * Values: "HIGH" (full path resolved via BFS), "MEDIUM" (partial path or ecosystem
     * constrained), "LOW" (heuristic-based), "NOT_AVAILABLE" (no SBOM or graph).
     */
    @Column(name = "dependency_graph_confidence")
    private String dependencyGraphConfidence = "NOT_AVAILABLE";

    /**
     * PHASE 1: Whether this CVE is eligible for SBOM analysis.
     * True if ecosystem is in {maven, npm, pypi, golang, cargo, composer, nuget}.
     * False otherwise (e.g., SAST, secrets, etc.).
     */
    @Column(name = "sbom_eligible")
    private Boolean sbomEligible = false;

    /**
     * PHASE 1: Reason why the CVE is or is not SBOM-eligible.
     * Values: "SUPPORTED_ECOSYSTEM", "UNSUPPORTED_ECOSYSTEM", "NO_PACKAGE_MANAGER",
     * "SAST_FINDING", "SECRETS_FINDING", "OTHER".
     */
    @Column(name = "sbom_eligibility_reason")
    private String sbomEligibilityReason;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;
}
