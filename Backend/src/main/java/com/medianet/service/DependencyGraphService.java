package com.medianet.service;

import com.medianet.service.SbomParserService.SbomComponent;
import com.medianet.service.SbomParserService.SbomIndex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Builds a dependency graph from an {@link SbomIndex} and resolves, for a given
 * component, whether it is a DIRECT or TRANSITIVE dependency, its depth, and
 * its
 * full dependency path.
 *
 * <p>
 * Design rules (from validated plan):
 * <ul>
 * <li>BFS from one or more roots; uses a local {@code predecessorMap} built
 * during the BFS to reconstruct paths — no global mutable state.</li>
 * <li>Multi-root support: from {@code metadata.component} if present → else
 * nodes with no incoming edges → else treat every known bomRef as a root.</li>
 * <li>Never invent DIRECT/TRANSITIVE when evidence is unreliable: returns
 * UNKNOWN + LOW confidence instead.</li>
 * <li>Confidence levels: HIGH (matched by PURL or bomRef + graph present),
 * MEDIUM (matched by name/version/eco), LOW (no match or no graph).</li>
 * </ul>
 */
@Service
public class DependencyGraphService {

    private static final Logger log = LoggerFactory.getLogger(DependencyGraphService.class);

    // ─── Public result type ────────────────────────────────────────────────────

    public static class GraphResult {
        public final String directOrTransitive; // "DIRECT", "TRANSITIVE", "UNKNOWN"
        public final int depth; // 0 = unknown, 1 = direct, >1 = transitive
        public final String path; // e.g. "root -> axios -> follow-redirects"
        public final String confidence; // "HIGH", "MEDIUM", "LOW"

        GraphResult(String directOrTransitive, int depth, String path, String confidence) {
            this.directOrTransitive = directOrTransitive;
            this.depth = depth;
            this.path = path;
            this.confidence = confidence;
        }

        public static GraphResult unknown() {
            return new GraphResult("UNKNOWN", 0, null, "LOW");
        }
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /**
     * Resolve the graph position of a component identified by its PURL, bomRef,
     * or name/version/ecosystem.
     *
     * @param idx     the SBOM index produced by {@link SbomParserService}
     * @param purl    PURL of the component (may be null)
     * @param bomRef  bom reference of the component (may be null)
     * @param name    component name
     * @param version component version (may be null)
     * @param eco     ecosystem (may be null)
     * @return the resolved {@link GraphResult}
     */
    public GraphResult resolve(SbomIndex idx, String purl, String bomRef,
            String name, String version, String eco) {

        if (idx == null || idx.isEmpty()) {
            return GraphResult.unknown();
        }

        // 1. Find the component in the index
        MatchResult match = findComponent(idx, purl, bomRef, name, version, eco);
        if (match == null) {
            log.debug("[GRAPH] Component not found in SBOM: purl={} name={} version={}", purl, name, version);
            return GraphResult.unknown();
        }

        SbomComponent target = match.component;
        String matchConfidence = match.confidence;

        // 2. If no dependency graph, report UNKNOWN with the match confidence
        if (idx.dependsOn.isEmpty()) {
            log.debug("[GRAPH] No dependency graph in SBOM for component {}", target.name);
            return new GraphResult("UNKNOWN", 0, null,
                    "HIGH".equals(matchConfidence) ? "MEDIUM" : "LOW");
        }

        // 3. Determine roots
        List<String> roots = determineRoots(idx);
        if (roots.isEmpty()) {
            return new GraphResult("UNKNOWN", 0, null,
                    "HIGH".equals(matchConfidence) ? "MEDIUM" : "LOW");
        }

        // 4. BFS from roots to find the shortest path to target
        BfsResult bfs = bfsShortestPath(idx, roots, target);

        if (bfs == null) {
            // Component not reachable from roots in the graph
            log.debug("[GRAPH] Component {} not reachable from roots", target.name);
            return new GraphResult("UNKNOWN", 0, null,
                    "HIGH".equals(matchConfidence) ? "MEDIUM" : "LOW");
        }

        String directOrTransitive = bfs.depth == 1 ? "DIRECT" : "TRANSITIVE";
        // Confidence degradation: HIGH if purl/bomRef match + graph traversal
        // succeeded,
        // MEDIUM if name/version/eco match, LOW otherwise
        String finalConfidence = matchConfidence;

        String pathStr = buildPathString(idx, bfs.path);
        return new GraphResult(directOrTransitive, bfs.depth, pathStr, finalConfidence);
    }

    // ─── Component lookup ─────────────────────────────────────────────────────

    private static class MatchResult {
        final SbomComponent component;
        final String confidence; // "HIGH", "MEDIUM"

        MatchResult(SbomComponent c, String confidence) {
            this.component = c;
            this.confidence = confidence;
        }
    }

    private MatchResult findComponent(SbomIndex idx, String purl, String bomRef,
            String name, String version, String eco) {
        // Priority 1: exact PURL match
        if (purl != null && !purl.isBlank()) {
            String normalized = SbomParserService.normalizePurl(purl);
            SbomComponent c = idx.byPurl.get(normalized);
            if (c != null)
                return new MatchResult(c, "HIGH");
        }

        // Priority 2: bomRef match
        if (bomRef != null && !bomRef.isBlank()) {
            SbomComponent c = idx.byBomRef.get(bomRef);
            if (c != null)
                return new MatchResult(c, "HIGH");
        }

        // Priority 3: name + version + ecosystem
        if (name != null) {
            String resolvedEco = eco != null ? eco : "unknown";
            String resolvedVersion = version != null ? version : "";
            String key = SbomParserService.nameVersionEcoKey(name, resolvedVersion, resolvedEco);
            SbomComponent c = idx.byNameVersionEco.get(key);
            if (c != null)
                return new MatchResult(c, "MEDIUM");

            // Priority 4: name + version only (ignore ecosystem)
            for (SbomComponent comp : idx.byBomRef.values()) {
                if (name.equalsIgnoreCase(comp.name)
                        && resolvedVersion.equals(comp.version != null ? comp.version : "")) {
                    return new MatchResult(comp, "MEDIUM");
                }
            }

            // Priority 5: name only (weakest – only use as last resort)
            for (SbomComponent comp : idx.byBomRef.values()) {
                if (name.equalsIgnoreCase(comp.name)) {
                    return new MatchResult(comp, "MEDIUM");
                }
            }
        }

        return null;
    }

    // ─── Root detection ───────────────────────────────────────────────────────

    /**
     * Determine root nodes for BFS.
     * <ol>
     * <li>Use {@code idx.rootComponent.bomRef} if present.</li>
     * <li>Otherwise, find nodes that appear in dependsOn keys but NOT as a child
     * (i.e., nodes with no incoming edges).</li>
     * <li>Fallback: use all nodes in dependsOn keys as potential roots.</li>
     * </ol>
     */
    private List<String> determineRoots(SbomIndex idx) {
        // Case 1: explicit root from metadata.component
        if (idx.rootComponent != null && idx.rootComponent.bomRef != null) {
            return List.of(idx.rootComponent.bomRef);
        }

        // Case 2: topological root detection
        Set<String> allNodes = new LinkedHashSet<>(idx.dependsOn.keySet());
        Set<String> hasIncoming = new HashSet<>();
        for (Set<String> children : idx.dependsOn.values()) {
            hasIncoming.addAll(children);
        }
        List<String> roots = new ArrayList<>();
        for (String node : allNodes) {
            if (!hasIncoming.contains(node)) {
                roots.add(node);
            }
        }
        if (!roots.isEmpty())
            return roots;

        // Fallback: treat all keys as roots
        return new ArrayList<>(idx.dependsOn.keySet());
    }

    // ─── BFS ──────────────────────────────────────────────────────────────────

    private static class BfsResult {
        final int depth;
        final List<String> path; // list of bomRefs from root to target (inclusive)

        BfsResult(int depth, List<String> path) {
            this.depth = depth;
            this.path = path;
        }
    }

    /**
     * BFS from all roots simultaneously. Builds a local {@code predecessorMap}
     * to reconstruct the shortest path. Returns null if not reachable.
     */
    private BfsResult bfsShortestPath(SbomIndex idx, List<String> roots, SbomComponent target) {
        // Collect all bomRefs that might refer to the target component
        Set<String> targetRefs = collectTargetRefs(idx, target);

        // BFS
        Queue<String> queue = new ArrayDeque<>(roots);
        Map<String, String> predecessorMap = new LinkedHashMap<>(); // node → predecessor
        Map<String, Integer> depthMap = new LinkedHashMap<>();

        for (String root : roots) {
            predecessorMap.put(root, null);
            depthMap.put(root, 0);
        }

        while (!queue.isEmpty()) {
            String current = queue.poll();
            int currentDepth = depthMap.getOrDefault(current, 0);

            // Check if we reached the target
            if (targetRefs.contains(current)) {
                List<String> path = reconstructPath(predecessorMap, current);
                return new BfsResult(currentDepth, path);
            }

            Set<String> children = idx.dependsOn.getOrDefault(current, Collections.emptySet());
            for (String child : children) {
                if (!predecessorMap.containsKey(child)) {
                    predecessorMap.put(child, current);
                    depthMap.put(child, currentDepth + 1);
                    queue.add(child);

                    // Check immediately to short-circuit
                    if (targetRefs.contains(child)) {
                        List<String> path = reconstructPath(predecessorMap, child);
                        return new BfsResult(currentDepth + 1, path);
                    }
                }
            }
        }

        return null;
    }

    /**
     * Collect all bomRef values that could identify the target component
     * (direct bomRef, purl-as-ref, etc.)
     */
    private Set<String> collectTargetRefs(SbomIndex idx, SbomComponent target) {
        Set<String> refs = new LinkedHashSet<>();
        if (target.bomRef != null)
            refs.add(target.bomRef);
        if (target.purl != null)
            refs.add(target.purl);
        if (target.normalizedPurl != null && !target.normalizedPurl.isBlank()) {
            refs.add(target.normalizedPurl);
            // Also add the original purl of any component sharing the same normalizedPurl
            SbomComponent byPurl = idx.byPurl.get(target.normalizedPurl);
            if (byPurl != null && byPurl.bomRef != null)
                refs.add(byPurl.bomRef);
        }
        return refs;
    }

    private List<String> reconstructPath(Map<String, String> predecessorMap, String target) {
        LinkedList<String> path = new LinkedList<>();
        String cur = target;
        while (cur != null) {
            path.addFirst(cur);
            cur = predecessorMap.get(cur);
        }
        return path;
    }

    // ─── Path rendering ───────────────────────────────────────────────────────

    /**
     * Convert a list of bomRefs into a human-readable path string using component
     * display names when available.
     *
     * <p>
     * e.g. "frontend-rh → axios@0.21.1 → follow-redirects@1.14.0"
     */
    private String buildPathString(SbomIndex idx, List<String> bomRefs) {
        if (bomRefs == null || bomRefs.isEmpty())
            return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bomRefs.size(); i++) {
            if (i > 0)
                sb.append(" → ");
            String ref = bomRefs.get(i);
            SbomComponent comp = idx.byBomRef.get(ref);
            if (comp != null) {
                sb.append(comp.name);
                if (comp.version != null && !comp.version.isBlank()) {
                    sb.append("@").append(comp.version);
                }
            } else {
                sb.append(ref);
            }
        }
        return sb.toString();
    }
}
