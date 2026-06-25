package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;

/**
 * Parses SBOM files (CycloneDX or Syft JSON format) into separate in-memory indexes
 * used by {@link SbomEnrichmentService} to determine whether a CVE's component 
 * is a direct or transitive dependency.
 *
 * <p>
 * Strategy: Parse two SBOM sources separately to avoid mixing ecosystems:
 * <ol>
 * <li><b>Maven SBOM (CycloneDX)</b> - for Maven/Java artifacts</li>
 *   Priority: maven-bom.cdx.json → sbom.maven.cdx.json → sbom.cdx.json
 * <li><b>Syft SBOM</b> - for OS packages (deb, rpm, apk, docker)</li>
 *   Priority: sbom.syft.json → sbom.json
 * </ol>
 * 
 * <p>
 * Returns a {@link DualSbomIndex} containing both mavenSbomIndex and syftSbomIndex.
 * {@link SbomEnrichmentService} chooses the appropriate index based on CVE ecosystem.
 */
@Service
public class SbomParserService {

    private static final Logger log = LoggerFactory.getLogger(SbomParserService.class);
    
    // File search priority for Maven artifacts
    private static final String[] MAVEN_BOM_FILENAMES = { 
        "maven-bom.cdx.json", 
        "sbom.maven.cdx.json", 
        "sbom.cdx.json" 
    };
    
    // File search priority for OS packages
    private static final String[] SYFT_SBOM_FILENAMES = { 
        "sbom.syft.json", 
        "sbom.json" 
    };

    private final ObjectMapper mapper = new ObjectMapper();

    // ─── Public data classes ──────────────────────────────────────────────────

    /**
     * A single component entry from the SBOM.
     */
    public static class SbomComponent {
        public String bomRef;
        public String name;
        public String version;
        public String type; // "library", "framework", "container", etc.
        public String purl; // original PURL as written in the SBOM
        public String normalizedPurl;// lower-cased, qualifier-stripped version for matching
        public String ecosystem; // derived from purl scheme
        public String packageManager;
        public String scope; // "runtime", "dev", "test", "optional", "unknown"

        @Override
        public String toString() {
            return name + "@" + version + " [" + ecosystem + "] purl=" + purl;
        }
    }

    /**
     * Full SBOM index: lookup maps + dependency links + optional root component.
     */
    public static class SbomIndex {
        /** bomRef → component */
        public final Map<String, SbomComponent> byBomRef = new LinkedHashMap<>();
        /** normalizedPurl → component */
        public final Map<String, SbomComponent> byPurl = new LinkedHashMap<>();
        /** "name|version|ecosystem" → component */
        public final Map<String, SbomComponent> byNameVersionEco = new LinkedHashMap<>();

        /** ref → set of direct dependsOn refs (adjacency list of the dep graph). */
        public final Map<String, Set<String>> dependsOn = new LinkedHashMap<>();

        /**
         * Metadata root component (the project itself), if present in the SBOM.
         * null if absent (e.g. image scans or SBOMs without metadata.component).
         */
        public SbomComponent rootComponent;

        public boolean isEmpty() {
            return byBomRef.isEmpty() && byPurl.isEmpty();
        }
    }

    /**
     * Container for both Maven and Syft SBOM indexes.
     * Allows SbomEnrichmentService to choose the appropriate index based on CVE ecosystem.
     */
    public static class DualSbomIndex {
        /** SBOM index for Maven/Java artifacts (from maven-bom.cdx.json) */
        public final SbomIndex mavenSbomIndex;
        
        /** SBOM index for OS packages (from sbom.syft.json) */
        public final SbomIndex syftSbomIndex;
        
        public DualSbomIndex(SbomIndex maven, SbomIndex syft) {
            this.mavenSbomIndex = maven;
            this.syftSbomIndex = syft;
        }
        
        public boolean isEmpty() {
            return mavenSbomIndex.isEmpty() && syftSbomIndex.isEmpty();
        }
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Parse both Maven and Syft SBOMs from the results directory.
     * Returns a DualSbomIndex containing separate indexes for each ecosystem.
     *
     * @param resultsDir path to the scan results directory
     * @return {@link DualSbomIndex} with both mavenSbomIndex and syftSbomIndex
     */
    public DualSbomIndex parseMultiple(String resultsDir) {
        SbomIndex mavenIdx = parseMavenSbom(resultsDir);
        SbomIndex syftIdx = parseSyftSbom(resultsDir);
        return new DualSbomIndex(mavenIdx, syftIdx);
    }

    /**
     * Legacy method: Parse the first SBOM file found (for backward compatibility).
     * Priority: Maven SBOM → Syft SBOM
     *
     * @param resultsDir path to the scan results directory
     * @return populated {@link SbomIndex}, or an empty index if no SBOM found
     */
    public SbomIndex parse(String resultsDir) {
        // Try Maven SBOM first
        SbomIndex mavenIdx = parseMavenSbom(resultsDir);
        if (!mavenIdx.isEmpty()) {
            return mavenIdx;
        }
        // Fallback to Syft
        SbomIndex syftIdx = parseSyftSbom(resultsDir);
        if (!syftIdx.isEmpty()) {
            return syftIdx;
        }
        log.info("[SBOM] No SBOM file found in {}", resultsDir);
        return new SbomIndex();
    }

    /**
     * Parse Maven CycloneDX SBOM from the results directory.
     * Priority: maven-bom.cdx.json → sbom.maven.cdx.json → sbom.cdx.json
     *
     * @param resultsDir path to the scan results directory
     * @return populated {@link SbomIndex}, or an empty index if not found
     */
    private SbomIndex parseMavenSbom(String resultsDir) {
        File sbomFile = findMavenSbomFile(resultsDir);
        if (sbomFile == null) {
            log.debug("[SBOM] No Maven SBOM file found in {}", resultsDir);
            return new SbomIndex();
        }

        log.info("[SBOM] Parsing Maven SBOM: {} ({} bytes)", sbomFile.getName(), sbomFile.length());
        try {
            JsonNode root = mapper.readTree(sbomFile);
            SbomIndex idx = parseCycloneDx(root, sbomFile.getName());
            log.info("[SBOM] ✓ Maven SBOM loaded: {} components, {} dependencies",
                    idx.byBomRef.size(), idx.dependsOn.size());
            return idx;
        } catch (Exception e) {
            log.warn("[SBOM] Failed to parse Maven SBOM {}: {}", sbomFile.getName(), e.getMessage());
            return new SbomIndex();
        }
    }

    /**
     * Parse Syft SBOM from the results directory.
     * Priority: sbom.syft.json → sbom.json
     *
     * @param resultsDir path to the scan results directory
     * @return populated {@link SbomIndex}, or an empty index if not found
     */
    private SbomIndex parseSyftSbom(String resultsDir) {
        File sbomFile = findSyftSbomFile(resultsDir);
        if (sbomFile == null) {
            log.debug("[SBOM] No Syft SBOM file found in {}", resultsDir);
            return new SbomIndex();
        }

        log.info("[SBOM] Parsing Syft SBOM: {} ({} bytes)", sbomFile.getName(), sbomFile.length());
        try {
            JsonNode root = mapper.readTree(sbomFile);
            // Detect format
            if (root.has("artifacts") && !root.has("bomFormat")) {
                SbomIndex idx = parseSyft(root, sbomFile.getName());
                log.info("[SBOM] ✓ Syft SBOM loaded: {} components, {} dependencies",
                        idx.byBomRef.size(), idx.dependsOn.size());
                return idx;
            } else {
                // Fallback to CycloneDX parser
                SbomIndex idx = parseCycloneDx(root, sbomFile.getName());
                log.info("[SBOM] ✓ Generic SBOM loaded as CycloneDX: {} components, {} dependencies",
                        idx.byBomRef.size(), idx.dependsOn.size());
                return idx;
            }
        } catch (Exception e) {
            log.warn("[SBOM] Failed to parse Syft SBOM {}: {}", sbomFile.getName(), e.getMessage());
            return new SbomIndex();
        }
    }

    // ─── File detection ───────────────────────────────────────────────────────

    /**
     * Find Maven SBOM file (CycloneDX).
     * Priority: maven-bom.cdx.json → sbom.maven.cdx.json → sbom.cdx.json
     */
    private File findMavenSbomFile(String resultsDir) {
        for (String name : MAVEN_BOM_FILENAMES) {
            File f = new File(resultsDir, name);
            if (f.exists() && f.length() > 0) {
                log.debug("[SBOM] Found Maven SBOM: {}", name);
                return f;
            }
        }
        return null;
    }

    /**
     * Find Syft SBOM file.
     * Priority: sbom.syft.json → sbom.json
     */
    private File findSyftSbomFile(String resultsDir) {
        for (String name : SYFT_SBOM_FILENAMES) {
            File f = new File(resultsDir, name);
            if (f.exists() && f.length() > 0) {
                log.debug("[SBOM] Found Syft SBOM: {}", name);
                return f;
            }
        }
        return null;
    }

    // ─── CycloneDX parser ─────────────────────────────────────────────────────

    private SbomIndex parseCycloneDx(JsonNode root, String filename) {
        SbomIndex idx = new SbomIndex();

        // Root component from metadata.component
        JsonNode meta = root.path("metadata").path("component");
        if (!meta.isMissingNode() && !meta.isNull()) {
            idx.rootComponent = buildComponent(meta);
            if (idx.rootComponent != null) {
                registerComponent(idx, idx.rootComponent);
            }
        }

        // Components array
        JsonNode components = root.path("components");
        if (components.isArray()) {
            for (JsonNode node : components) {
                SbomComponent comp = buildComponent(node);
                if (comp != null) {
                    registerComponent(idx, comp);
                    // Recurse into nested components
                    parseNestedComponents(node.path("components"), idx);
                }
            }
        }

        // Dependencies section: ref → dependsOn[]
        JsonNode deps = root.path("dependencies");
        if (deps.isArray()) {
            for (JsonNode dep : deps) {
                String ref = text(dep, "ref");
                if (ref == null)
                    continue;
                JsonNode dependsOnArr = dep.path("dependsOn");
                Set<String> children = idx.dependsOn.computeIfAbsent(ref, k -> new LinkedHashSet<>());
                if (dependsOnArr.isArray()) {
                    for (JsonNode child : dependsOnArr) {
                        children.add(child.asText());
                    }
                }
            }
        }

        log.info("[SBOM] CycloneDX {} parsed: {} components, {} dependency links",
                filename, idx.byBomRef.size(), idx.dependsOn.size());
        return idx;
    }

    private void parseNestedComponents(JsonNode components, SbomIndex idx) {
        if (!components.isArray())
            return;
        for (JsonNode node : components) {
            SbomComponent comp = buildComponent(node);
            if (comp != null) {
                registerComponent(idx, comp);
                parseNestedComponents(node.path("components"), idx);
            }
        }
    }

    // ─── Syft parser ──────────────────────────────────────────────────────────

    private SbomIndex parseSyft(JsonNode root, String filename) {
        SbomIndex idx = new SbomIndex();

        // Syft root: "source" acts as the project root
        JsonNode source = root.path("source");
        if (!source.isMissingNode()) {
            SbomComponent root0 = new SbomComponent();
            root0.bomRef = "syft-root";
            root0.name = text(source, "target");
            root0.version = "";
            root0.type = text(source, "type");
            root0.ecosystem = "unknown";
            root0.normalizedPurl = "";
            root0.scope = "unknown";
            if (root0.name != null && !root0.name.isBlank()) {
                idx.rootComponent = root0;
            }
        }

        // Artifacts
        JsonNode artifacts = root.path("artifacts");
        if (artifacts.isArray()) {
            for (JsonNode node : artifacts) {
                SbomComponent comp = buildSyftComponent(node);
                if (comp != null) {
                    registerComponent(idx, comp);
                }
            }
        }

        // Syft relationships → build dependsOn graph
        JsonNode rels = root.path("artifactRelationships");
        if (!rels.isArray()) {
            rels = root.path("relationships"); // older Syft format
        }
        if (rels.isArray()) {
            for (JsonNode rel : rels) {
                String type = text(rel, "type");
                if ("dependency-of".equalsIgnoreCase(type)) {
                    // child dependency-of parent → parent dependsOn child
                    String child = text(rel, "artifact");
                    String parent = text(rel, "relatesTo");
                    if (child != null && parent != null) {
                        idx.dependsOn.computeIfAbsent(parent, k -> new LinkedHashSet<>()).add(child);
                    }
                } else if ("contains".equalsIgnoreCase(type)) {
                    String parent = text(rel, "artifact");
                    String child = text(rel, "relatesTo");
                    if (child != null && parent != null) {
                        idx.dependsOn.computeIfAbsent(parent, k -> new LinkedHashSet<>()).add(child);
                    }
                }
            }
        }

        log.info("[SBOM] Syft {} parsed: {} components, {} dependency links",
                filename, idx.byBomRef.size(), idx.dependsOn.size());
        return idx;
    }

    // ─── Component builders ───────────────────────────────────────────────────

    /** Build SbomComponent from a CycloneDX component node. */
    private SbomComponent buildComponent(JsonNode node) {
        if (node == null || node.isNull() || node.isMissingNode())
            return null;
        SbomComponent comp = new SbomComponent();
        comp.bomRef = text(node, "bom-ref");
        if (comp.bomRef == null)
            comp.bomRef = text(node, "bomRef");
        comp.name = text(node, "name");
        comp.version = text(node, "version");
        comp.type = text(node, "type");
        comp.purl = text(node, "purl");
        comp.normalizedPurl = normalizePurl(comp.purl);
        comp.ecosystem = ecosystemFromPurl(comp.purl);
        comp.packageManager = inferPackageManager(comp.ecosystem, comp.type);
        comp.scope = parseCdxScope(node);
        if (comp.bomRef == null && comp.name == null)
            return null;
        // Fallback bomRef from purl or name+version
        if (comp.bomRef == null) {
            comp.bomRef = comp.purl != null ? comp.purl : (comp.name + "@" + comp.version);
        }
        return comp;
    }

    /** Build SbomComponent from a Syft artifact node. */
    private SbomComponent buildSyftComponent(JsonNode node) {
        if (node == null || node.isNull())
            return null;
        SbomComponent comp = new SbomComponent();
        comp.bomRef = text(node, "id");
        comp.name = text(node, "name");
        comp.version = text(node, "version");
        comp.type = text(node, "type");
        // Syft stores PURLs in cpes or purl field
        comp.purl = text(node, "purl");
        comp.normalizedPurl = normalizePurl(comp.purl);
        comp.ecosystem = ecosystemFromPurl(comp.purl);
        if ("UNKNOWN".equals(comp.ecosystem)) {
            // Fallback: use Syft type field
            comp.ecosystem = syftTypeToEcosystem(comp.type);
        }
        comp.packageManager = inferPackageManager(comp.ecosystem, comp.type);
        comp.scope = "unknown";
        if (comp.bomRef == null && comp.name == null)
            return null;
        if (comp.bomRef == null)
            comp.bomRef = comp.name + "@" + comp.version;
        return comp;
    }

    // ─── Registration ─────────────────────────────────────────────────────────

    private void registerComponent(SbomIndex idx, SbomComponent comp) {
        if (comp.bomRef != null && !comp.bomRef.isBlank()) {
            idx.byBomRef.put(comp.bomRef, comp);
        }
        if (comp.normalizedPurl != null && !comp.normalizedPurl.isBlank()) {
            idx.byPurl.putIfAbsent(comp.normalizedPurl, comp);
        }
        if (comp.name != null && comp.version != null) {
            String key = nameVersionEcoKey(comp.name, comp.version, comp.ecosystem);
            idx.byNameVersionEco.putIfAbsent(key, comp);
        }
    }

    // ─── PURL utilities ───────────────────────────────────────────────────────

    /**
     * Normalize a PURL for comparison: trim, lowercase scheme+type+namespace+name,
     * preserve version, strip qualifiers and subpath.
     * Returns empty string if purl is null.
     */
    public static String normalizePurl(String purl) {
        if (purl == null || purl.isBlank())
            return "";
        // Strip qualifiers (?) and subpath (#)
        String normalized = purl.trim();
        int q = normalized.indexOf('?');
        if (q >= 0)
            normalized = normalized.substring(0, q);
        int h = normalized.indexOf('#');
        if (h >= 0)
            normalized = normalized.substring(0, h);
        return normalized.toLowerCase(java.util.Locale.ROOT);
    }

    /**
     * Extract the ecosystem name from a PURL.
     * "pkg:npm/axios@0.21.1" → "npm"
     */
    public static String ecosystemFromPurl(String purl) {
        if (purl == null || purl.isBlank())
            return "unknown";
        // pkg:<type>/...
        int colon = purl.indexOf(':');
        int slash = purl.indexOf('/', colon + 1);
        if (colon > 0 && slash > colon) {
            return purl.substring(colon + 1, slash).toLowerCase(java.util.Locale.ROOT);
        }
        return "unknown";
    }

    /** Build key for byNameVersionEco map. */
    public static String nameVersionEcoKey(String name, String version, String ecosystem) {
        return (name == null ? "" : name.toLowerCase(java.util.Locale.ROOT))
                + "|" + (version == null ? "" : version)
                + "|" + (ecosystem == null ? "unknown" : ecosystem.toLowerCase(java.util.Locale.ROOT));
    }

    private String parseCdxScope(JsonNode node) {
        JsonNode scope = node.path("scope");
        if (scope.isMissingNode() || scope.isNull())
            return "unknown";
        String s = scope.asText("").toLowerCase(java.util.Locale.ROOT);
        return switch (s) {
            case "required" -> "runtime";
            case "optional" -> "optional";
            case "excluded" -> "dev";
            default -> "unknown";
        };
    }

    private String syftTypeToEcosystem(String type) {
        if (type == null)
            return "unknown";
        return switch (type.toLowerCase(java.util.Locale.ROOT)) {
            case "npm" -> "npm";
            case "java-archive", "maven" -> "maven";
            case "python" -> "pypi";
            case "gem" -> "gem";
            case "go-module" -> "golang";
            case "rust-crate" -> "cargo";
            case "deb" -> "deb";
            case "rpm" -> "rpm";
            case "apk" -> "apk";
            default -> "unknown";
        };
    }

    private String inferPackageManager(String ecosystem, String type) {
        if (ecosystem == null)
            return "unknown";
        return switch (ecosystem.toLowerCase(java.util.Locale.ROOT)) {
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

    private static String text(JsonNode node, String field) {
        if (node == null)
            return null;
        JsonNode n = node.get(field);
        return (n != null && !n.isNull() && n.isTextual()) ? n.asText() : null;
    }
}
