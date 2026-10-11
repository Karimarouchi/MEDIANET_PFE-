package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CveEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Tells, for each vulnerable dependency, whether the project's own code imports it (read from package-usage.json,
 * written by the scanner from the import statements). It is a usage signal, not a call-graph reachability proof:
 * <ul>
 * <li>{@code YES}: imported by production code;</li>
 * <li>{@code TEST_ONLY}: imported only by tests;</li>
 * <li>{@code NOT_IMPORTED}: no import found (indirect dependency, unused, or imported under another name);</li>
 * <li>{@code UNKNOWN}: cannot tell (no usage file, unsupported ecosystem, transitive dependency).</li>
 * </ul>
 */
@Service
public class CodeUsageService {

    private static final Logger log = LoggerFactory.getLogger(CodeUsageService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** PyPI distribution name -> import name, when they differ. */
    private static final Map<String, String> PYPI_IMPORT_NAME = Map.ofEntries(
            Map.entry("pillow", "pil"), Map.entry("pyyaml", "yaml"), Map.entry("beautifulsoup4", "bs4"),
            Map.entry("scikit-learn", "sklearn"), Map.entry("opencv-python", "cv2"), Map.entry("python-dateutil", "dateutil"),
            Map.entry("pyjwt", "jwt"), Map.entry("protobuf", "google"), Map.entry("pymongo", "pymongo"),
            Map.entry("psycopg2-binary", "psycopg2"), Map.entry("attrs", "attr"), Map.entry("msgpack-python", "msgpack"));

    public record Usage(String status, List<String> files) {
    }

    public void apply(String resultsDir, List<CveEntry> cves) {
        if (cves == null || cves.isEmpty()) {
            return;
        }
        JsonNode usage = read(resultsDir);
        for (CveEntry c : cves) {
            Usage u = usageOf(usage, ecosystemOf(c), c.getPackageName(), c.getDirectOrTransitive());
            c.setCodeUsage(u.status());
            try {
                c.setUsageFiles(u.files().isEmpty() ? null : MAPPER.writeValueAsString(u.files()));
            } catch (Exception e) {
                c.setUsageFiles(null);
            }
        }
    }

    /**
     * Ecosystem of an entry. Advisories reported only by npm-audit / pip-audit carry no SBOM data (no ecosystem, no
     * manifest), but the tool that reported them tells it.
     */
    static String ecosystemOf(CveEntry c) {
        if (c.getEcosystem() != null && !c.getEcosystem().isBlank()) {
            return c.getEcosystem();
        }
        String purl = c.getPurl() == null ? "" : c.getPurl().toLowerCase(Locale.ROOT);
        if (purl.startsWith("pkg:npm/")) return "npm";
        if (purl.startsWith("pkg:pypi/")) return "pypi";
        if (purl.startsWith("pkg:maven/")) return "maven";
        if (purl.startsWith("pkg:golang/")) return "golang";
        String src = ((c.getSource() == null ? "" : c.getSource()) + "," + (c.getSources() == null ? "" : c.getSources()))
                .toLowerCase(Locale.ROOT);
        if (src.contains("npm-audit")) return "npm";
        if (src.contains("pip-audit")) return "pypi";
        String manifest = c.getManifestFile() == null ? "" : c.getManifestFile().toLowerCase(Locale.ROOT);
        if (manifest.endsWith("package-lock.json") || manifest.endsWith("package.json") || manifest.endsWith("yarn.lock")) return "npm";
        if (manifest.endsWith("pom.xml")) return "maven";
        if (manifest.endsWith("requirements.txt") || manifest.endsWith("poetry.lock")) return "pypi";
        if (manifest.endsWith("go.mod")) return "golang";
        return null;
    }

    JsonNode read(String resultsDir) {
        File f = new File(resultsDir, "package-usage.json");
        if (!f.isFile() || f.length() < 3) {
            return null;
        }
        try {
            JsonNode n = MAPPER.readTree(f);
            return n.has("filesScanned") ? n : null;
        } catch (Exception e) {
            log.warn("Cannot read package-usage.json: {}", e.getMessage());
            return null;
        }
    }

    static Usage usageOf(JsonNode usage, String ecosystem, String packageName, String directOrTransitive) {
        if (usage == null || packageName == null || packageName.isBlank() || ecosystem == null) {
            return new Usage("UNKNOWN", List.of());
        }
        String eco = ecosystem.toLowerCase(Locale.ROOT);
        String name = packageName.toLowerCase(Locale.ROOT);
        JsonNode hit = null;
        switch (eco) {
            case "npm" -> hit = usage.path("npm").get(name);
            case "pypi", "pip" -> {
                String norm = name.replace('-', '_');
                String alias = PYPI_IMPORT_NAME.get(name);
                JsonNode py = usage.path("pypi");
                hit = py.get(norm);
                if (hit == null && alias != null) {
                    hit = py.get(alias);
                }
                if (hit == null) {
                    hit = py.get(name);
                }
            }
            case "maven" -> {
                String group = name.contains(":") ? name.substring(0, name.indexOf(':')) : name;
                var it = usage.path("java").fields();
                while (it.hasNext() && hit == null) {
                    var e = it.next();
                    if (e.getKey().toLowerCase(Locale.ROOT).startsWith(group)) {
                        hit = e.getValue();
                    }
                }
            }
            case "golang", "go" -> {
                var it = usage.path("go").fields();
                while (it.hasNext() && hit == null) {
                    var e = it.next();
                    if (e.getKey().toLowerCase(Locale.ROOT).startsWith(name)) {
                        hit = e.getValue();
                    }
                }
            }
            default -> {
                return new Usage("UNKNOWN", List.of());
            }
        }
        if (hit != null) {
            List<String> files = new ArrayList<>();
            hit.path("files").forEach(x -> files.add(x.asText()));
            return new Usage(hit.path("prod").asBoolean(false) ? "YES" : "TEST_ONLY", files);
        }
        // not imported: a transitive dependency is never imported by the project itself, so nothing can be said
        if ("TRANSITIVE".equalsIgnoreCase(directOrTransitive)) {
            return new Usage("UNKNOWN", List.of());
        }
        return new Usage("NOT_IMPORTED", List.of());
    }
}
