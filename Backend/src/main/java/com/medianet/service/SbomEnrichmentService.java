package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.service.DependencyGraphService.GraphResult;
import com.medianet.service.SbomParserService.SbomComponent;
import com.medianet.service.SbomParserService.SbomIndex;
import com.medianet.service.SbomParserService.DualSbomIndex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;

/**
 * Enriches a list of {@link CveEntry} objects with SBOM-derived dependency
 * information (all 14 new fields).
 *
 * <p>
 * Deduplication key used when filling fields (does NOT deduplicate — that
 * already happened in {@link ResultParserService}):
 * <ul>
 * <li>If PURL present: {@code cveId + purl + moduleName}</li>
 * <li>Else:
 * {@code cveId + packageName + installedVersion + ecosystem + moduleName + manifestFile}</li>
 * </ul>
 *
 * <p>
 * Called by {@link ScanService} immediately after
 * {@link ResultParserService#parseCves} and before NVD/ExploitDB/KEV/EPSS
 * enrichment.
 */
@Service
public class SbomEnrichmentService {

    private static final Logger log = LoggerFactory.getLogger(SbomEnrichmentService.class);

    private final SbomParserService sbomParserService;
    private final DependencyGraphService graphService;

    public SbomEnrichmentService(SbomParserService sbomParserService,
            DependencyGraphService graphService) {
        this.sbomParserService = sbomParserService;
        this.graphService = graphService;
    }

    /**
     * Enrich all CVE entries in-place with SBOM data.
     * Uses ecosystem-aware SBOM selection: Maven artifacts use maven-bom.cdx.json,
     * OS packages use sbom.syft.json.
     *
     * @param cves       list of parsed CVE entries (modified in-place)
     * @param resultsDir path to the scan results directory containing SBOM files
     */
    public void enrich(List<CveEntry> cves, String resultsDir) {
        if (cves == null || cves.isEmpty()) {
            log.info("[SBOM] No CVEs to enrich");
            return;
        }

        DualSbomIndex dualIdx = sbomParserService.parseMultiple(resultsDir);

        if (dualIdx.isEmpty()) {
            log.warn("[SBOM] ⚠️ No SBOM data available — all {} CVEs will get UNKNOWN/LOW confidence", cves.size());
            log.warn("[SBOM] Check: Does {} contain sbom.*.json or maven-bom.cdx.json?", resultsDir);
            for (CveEntry cve : cves) {
                applyUnknown(cve);
            }
            return;
        }

        int totalComponents = dualIdx.mavenSbomIndex.byBomRef.size() + dualIdx.syftSbomIndex.byBomRef.size();
        log.info("[SBOM] ✓ SBOMs parsed: Maven={} components, Syft={} components",
                dualIdx.mavenSbomIndex.byBomRef.size(), dualIdx.syftSbomIndex.byBomRef.size());

        int enriched = 0;
        int unresolved = 0;
        int failed = 0;

        for (CveEntry cve : cves) {
            try {
                enrichSingle(cve, dualIdx);
                if (!"UNKNOWN".equals(cve.getDirectOrTransitive())) {
                    enriched++;
                    log.debug("[SBOM] ✓ {} → {} (confidence={})",
                            cve.getCveId(), cve.getDirectOrTransitive(), cve.getDependencyConfidence());
                } else {
                    unresolved++;
                    log.trace("[SBOM] ✗ {} → UNKNOWN (no component match)", cve.getCveId());
                }
            } catch (Exception e) {
                log.warn("[SBOM] Failed to enrich CVE {}: {}", cve.getCveId(), e.getMessage());
                applyUnknown(cve);
                failed++;
            }
        }

        log.info("[SBOM] Enrichment summary: {}/{} resolved | {} UNKNOWN | {} errors",
                enriched, cves.size(), unresolved, failed);
        if (enriched > 0) {
            log.info("[SBOM] Success rate: {}%", (enriched * 100) / cves.size());
        }
    }

    // ─── Single CVE enrichment ────────────────────────────────────────────────

    /**
     * Enrich a single CVE with SBOM and dependency graph data.
     * Chooses the appropriate SBOM index based on ecosystem:
     * - Maven/Java artifacts: use Maven SBOM first, fallback to Syft
     * - OS packages (deb/rpm/apk): use Syft SBOM
     * - Unknown: try both
     */
    private void enrichSingle(CveEntry cve, DualSbomIndex dualIdx) {
        // Pre-step: infer ecosystem if missing, before eligibility check
        inferEcosystemIfMissing(cve);

        // PHASE 1: Determine SBOM eligibility first
        boolean sbomEligible = isEligibleEcosystem(cve.getEcosystem());
        cve.setSbomEligible(sbomEligible);
        if (!sbomEligible) {
            cve.setSbomEligibilityReason(sbomEligibilityReason(cve.getEcosystem(), cve.getSource()));
            cve.setComponentMatchMethod("NONE");
            cve.setComponentMatchConfidence("LOW");
            cve.setDependencyGraphConfidence("NOT_AVAILABLE");
            return;
        }
        cve.setSbomEligibilityReason("SUPPORTED_ECOSYSTEM");

        // Choose appropriate SBOM index based on CVE ecosystem
        SbomIndex primaryIdx = choosePrimaryIndex(cve.getEcosystem(), dualIdx);
        SbomIndex fallbackIdx = chooseFallbackIndex(primaryIdx, dualIdx);

        // 1. Lookup component in the SBOM index with match tracking
        String purl = cve.getPurl();
        String bomRef = cve.getBomRef();
        String name = cve.getPackageName();
        String version = cve.getPackageVersion();
        String eco = cve.getEcosystem();

        MatchResult matchResult = findBestComponentWithMethod(primaryIdx, fallbackIdx, purl, bomRef, name, version, eco);
        SbomComponent comp = matchResult.component;
        String matchMethod = matchResult.matchMethod;

        cve.setComponentMatchMethod(matchMethod);

        if (comp != null && !"NONE".equals(matchMethod)) {
            log.debug("[SBOM] {} | Found component via {}: {} | version={}",
                cve.getCveId(), matchMethod, comp.name, comp.version);

            // Fill component fields from the SBOM
            cve.setComponentName(comp.name);
            cve.setComponentVersion(comp.version);
            cve.setComponentType(comp.type);

            // Fill ecosystem fields
            if (comp.ecosystem != null && !"unknown".equals(comp.ecosystem)) {
                cve.setEcosystem(comp.ecosystem);
            }
            if (comp.packageManager != null && !"unknown".equals(comp.packageManager)) {
                cve.setPackageManager(comp.packageManager);
            }
            if (comp.scope != null && !"unknown".equals(comp.scope)) {
                cve.setDependencyScope(comp.scope);
            }

            // Fill PURL and bomRef
            if (comp.purl != null && !comp.purl.isBlank()) {
                cve.setPurl(comp.purl);
            }
            if (comp.bomRef != null && !comp.bomRef.isBlank()) {
                cve.setBomRef(comp.bomRef);
            }

            // Determine componentMatchConfidence based on match method
            String matchConfidence;
            if ("PURL_EXACT".equals(matchMethod) || "BOM_REF_EXACT".equals(matchMethod)) {
                matchConfidence = "HIGH";
            } else if ("NAME_VERSION_ECOSYSTEM".equals(matchMethod)) {
                matchConfidence = "MEDIUM";
            } else {
                matchConfidence = "LOW";
            }
            cve.setComponentMatchConfidence(matchConfidence);
        } else {
            log.debug("[SBOM] {} | No component found | attempted: purl={} bomRef={} name={} eco={}",
                    cve.getCveId(), purl, bomRef, name, eco);
            cve.setComponentMatchConfidence("LOW");
            // No SBOM component found — still fill what we know from the parser
            fillFromParserData(cve);
        }

        // 2. Resolve dependency graph (use combined/merged index for graph traversal)
        SbomIndex combinedIdx = primaryIdx != null ? primaryIdx : fallbackIdx;
        GraphResult result = graphService.resolve(
                combinedIdx,
                cve.getPurl(),
                cve.getBomRef(),
                cve.getPackageName(),
                cve.getPackageVersion(),
                cve.getEcosystem());

        cve.setDirectOrTransitive(result.directOrTransitive);
        cve.setDependencyDepth(result.depth > 0 ? result.depth : null);
        cve.setDependencyPath(result.path);
        cve.setDependencyConfidence(result.confidence);

        // PHASE 1: Set dependencyGraphConfidence based on resolution success
        if ("UNKNOWN".equals(result.directOrTransitive)) {
            cve.setDependencyGraphConfidence("NOT_AVAILABLE");
        } else if ("HIGH".equals(result.confidence)) {
            cve.setDependencyGraphConfidence("HIGH");
        } else if ("MEDIUM".equals(result.confidence)) {
            cve.setDependencyGraphConfidence("MEDIUM");
        } else {
            cve.setDependencyGraphConfidence("LOW");
        }

        // 3. Derive moduleName from manifestFile if not already set
        if (cve.getModuleName() == null && cve.getManifestFile() != null) {
            cve.setModuleName(deriveModuleName(cve.getManifestFile()));
        }

        log.debug("[SBOM] {} → {} | depth={} | matchMethod={} | matchConfidence={} | graphConfidence={} | path={} | module={}",
                cve.getCveId(), result.directOrTransitive,
                result.depth, matchMethod, cve.getComponentMatchConfidence(),
                cve.getDependencyGraphConfidence(), result.path, cve.getModuleName());
    }

    /**
     * Choose the primary SBOM index for a given ecosystem.
     * Maven/Java artifacts prefer Maven SBOM.
     * OS packages prefer Syft SBOM.
     */
    private SbomIndex choosePrimaryIndex(String ecosystem, DualSbomIndex dualIdx) {
        if (ecosystem == null) {
            return dualIdx.mavenSbomIndex.isEmpty() ? dualIdx.syftSbomIndex : dualIdx.mavenSbomIndex;
        }
        String eco = ecosystem.toLowerCase();
        if (eco.equals("maven") || eco.equals("pom") || eco.equals("java") || eco.equals("java-archive")) {
            return dualIdx.mavenSbomIndex;
        } else if (eco.equals("deb") || eco.equals("rpm") || eco.equals("apk") || eco.equals("docker")) {
            return dualIdx.syftSbomIndex;
        } else if (eco.equals("npm") || eco.equals("pypi") || eco.equals("golang") ||
                   eco.equals("cargo") || eco.equals("composer") || eco.equals("nuget")) {
            // These can be in either, prefer Maven for consistency
            return dualIdx.mavenSbomIndex.isEmpty() ? dualIdx.syftSbomIndex : dualIdx.mavenSbomIndex;
        }
        // Unknown ecosystem: try Maven first
        return dualIdx.mavenSbomIndex.isEmpty() ? dualIdx.syftSbomIndex : dualIdx.mavenSbomIndex;
    }

    /**
     * Choose the fallback SBOM index (the other one).
     */
    private SbomIndex chooseFallbackIndex(SbomIndex primary, DualSbomIndex dualIdx) {
        if (primary == dualIdx.mavenSbomIndex) {
            return dualIdx.syftSbomIndex;
        } else {
            return dualIdx.mavenSbomIndex;
        }
    }

    /**
     * Match result wrapper for tracking the matching method.
     */
    private static class MatchResult {
        SbomComponent component;
        String matchMethod;

        MatchResult(SbomComponent comp, String method) {
            this.component = comp;
            this.matchMethod = method;
        }
    }

    /**
     * Find the best matching component from the SBOM indexes with method tracking.
     * Priority: PURL → bomRef → name+version+eco → NONE.
     * Searches primary index first, then fallback.
     */
    private MatchResult findBestComponentWithMethod(SbomIndex primary, SbomIndex fallback,
            String purl, String bomRef, String name, String version, String eco) {
        // Try PURL exact match first (primary)
        if (purl != null && !purl.isBlank()) {
            SbomComponent c = primary.byPurl.get(SbomParserService.normalizePurl(purl));
            if (c != null)
                return new MatchResult(c, "PURL_EXACT");

            // Fallback to secondary index
            if (fallback != null) {
                c = fallback.byPurl.get(SbomParserService.normalizePurl(purl));
                if (c != null)
                    return new MatchResult(c, "PURL_EXACT");
            }
        }

        // Try bomRef exact match (primary)
        if (bomRef != null && !bomRef.isBlank()) {
            SbomComponent c = primary.byBomRef.get(bomRef);
            if (c != null)
                return new MatchResult(c, "BOM_REF_EXACT");

            // Fallback to secondary index
            if (fallback != null) {
                c = fallback.byBomRef.get(bomRef);
                if (c != null)
                    return new MatchResult(c, "BOM_REF_EXACT");
            }
        }

        // Try name+version+eco match (primary)
        if (name != null) {
            // Extract artifactId from groupId:artifactId Maven format (e.g. "ch.qos.logback:logback-core" → "logback-core")
            String artifactId = name.contains(":") ? name.substring(name.lastIndexOf(':') + 1) : name;
            String resolvedEco = eco != null ? eco : "unknown";
            String resolvedVersion = version != null ? version : "";

            // Try with full name first, then artifactId
            for (String n : artifactId.equals(name) ? new String[]{name} : new String[]{name, artifactId}) {
                String key = SbomParserService.nameVersionEcoKey(n, resolvedVersion, resolvedEco);
                SbomComponent c = primary.byNameVersionEco.get(key);
                if (c != null)
                    return new MatchResult(c, "NAME_VERSION_ECOSYSTEM");
                // Also try with "maven" ecosystem explicitly when resolvedEco is "pom"
                if ("pom".equals(resolvedEco)) {
                    key = SbomParserService.nameVersionEcoKey(n, resolvedVersion, "maven");
                    c = primary.byNameVersionEco.get(key);
                    if (c != null)
                        return new MatchResult(c, "NAME_VERSION_ECOSYSTEM");
                }
                if (fallback != null) {
                    key = SbomParserService.nameVersionEcoKey(n, resolvedVersion, resolvedEco);
                    c = fallback.byNameVersionEco.get(key);
                    if (c != null)
                        return new MatchResult(c, "NAME_VERSION_ECOSYSTEM");
                }
            }

            // Fallback: name + version without ecosystem (primary) — also try artifactId
            for (String n : artifactId.equals(name) ? new String[]{name} : new String[]{name, artifactId}) {
                for (SbomComponent comp : primary.byBomRef.values()) {
                    if (n.equalsIgnoreCase(comp.name)
                            && resolvedVersion.equals(comp.version != null ? comp.version : "")) {
                        return new MatchResult(comp, "NAME_VERSION_ECOSYSTEM");
                    }
                }
                if (fallback != null) {
                    for (SbomComponent comp : fallback.byBomRef.values()) {
                        if (n.equalsIgnoreCase(comp.name)
                                && resolvedVersion.equals(comp.version != null ? comp.version : "")) {
                            return new MatchResult(comp, "NAME_VERSION_ECOSYSTEM");
                        }
                    }
                }
            }
        }

        return new MatchResult(null, "NONE");
    }

    /**
     * PHASE 1: Check if a CVE's ecosystem is eligible for SBOM analysis.
     * Supported ecosystems: maven, pom, java, java-archive, npm, pypi, golang, cargo, composer, nuget.
     */
    private boolean isEligibleEcosystem(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank())
            return false;
        String eco = ecosystem.toLowerCase();
        return eco.equals("maven") || eco.equals("pom") || eco.equals("java") || eco.equals("java-archive")
                || eco.equals("npm") || eco.equals("pypi")
                || eco.equals("golang") || eco.equals("cargo") || eco.equals("composer")
                || eco.equals("nuget");
    }

    /**
     * Infer ecosystem from PURL or package name if it is missing or unknown.
     * Handles:
     *  - Grype/Trivy PURL like pkg:maven/... → ecosystem = "maven"
     *  - OSV-scanner groupId:artifactId format → ecosystem = "maven"
     */
    private void inferEcosystemIfMissing(CveEntry cve) {
        String eco = cve.getEcosystem();
        if (eco != null && !eco.isBlank() && !"unknown".equalsIgnoreCase(eco)) {
            return; // already set
        }
        // Try to infer from PURL
        String purl = cve.getPurl();
        if (purl != null && !purl.isBlank()) {
            String inferred = SbomParserService.ecosystemFromPurl(purl);
            if (inferred != null && !inferred.isBlank() && !"unknown".equals(inferred)) {
                log.debug("[SBOM] Inferred ecosystem='{}' from PURL for {}", inferred, cve.getCveId());
                cve.setEcosystem(inferred);
                return;
            }
        }
        // Try to infer from package name in groupId:artifactId format
        String name = cve.getPackageName();
        if (name != null && name.matches("^[\\w.\\-]+:[\\w.\\-]+$")) {
            log.debug("[SBOM] Inferred ecosystem='maven' from Maven name format '{}' for {}", name, cve.getCveId());
            cve.setEcosystem("maven");
        }
    }

    /**
     * PHASE 1: Determine why a CVE is not SBOM-eligible.
     */
    private String sbomEligibilityReason(String ecosystem, String source) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return "NO_PACKAGE_MANAGER";
        }
        String eco = ecosystem.toLowerCase();
        if (source != null) {
            if (source.contains("SAST") || source.contains("secrets")) {
                return "SAST_FINDING";
            }
        }
        return "UNSUPPORTED_ECOSYSTEM";
    }

    // ─── Helper methods ───────────────────────────────────────────────────────

    /**
     * When no SBOM component is found, derive basic fields from data already in
     * the CveEntry (populated by the parser).
     */
    private void fillFromParserData(CveEntry cve) {
        if (cve.getComponentName() == null) {
            cve.setComponentName(cve.getPackageName());
        }
        if (cve.getComponentVersion() == null) {
            cve.setComponentVersion(cve.getPackageVersion());
        }
        // Ecosystem may already be set by the parser
        if (cve.getPackageManager() == null && cve.getEcosystem() != null) {
            cve.setPackageManager(inferPackageManager(cve.getEcosystem()));
        }
    }

    private void applyUnknown(CveEntry cve) {
        cve.setDirectOrTransitive("UNKNOWN");
        cve.setDependencyConfidence("LOW");
        fillFromParserData(cve);
    }

    /**
     * Derive module name from manifest file path.
     * "frontend-rh/package-lock.json" → "frontend-rh"
     * "Backend/pom.xml" → "Backend"
     * "package.json" → (empty string → null)
     */
    static String deriveModuleName(String manifestFile) {
        if (manifestFile == null || manifestFile.isBlank())
            return null;
        String normalized = manifestFile.replace("\\", "/");
        int slash = normalized.indexOf('/');
        if (slash > 0) {
            return normalized.substring(0, slash);
        }
        return null; // file is at root, no module
    }

    private String inferPackageManager(String ecosystem) {
        if (ecosystem == null)
            return "unknown";
        return switch (ecosystem.toLowerCase(Locale.ROOT)) {
            case "npm" -> "npm";
            case "maven" -> "mvn";
            case "pypi" -> "pip";
            case "cargo" -> "cargo";
            case "golang" -> "go";
            case "gem" -> "gem";
            case "deb" -> "apt";
            case "rpm" -> "rpm";
            case "apk" -> "apk";
            default -> "unknown";
        };
    }
}
