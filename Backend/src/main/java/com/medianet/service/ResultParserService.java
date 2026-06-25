package com.medianet.service;

import com.medianet.dto.SastFindingDto;
import com.medianet.entity.CveEntry;
import com.medianet.entity.SecretFinding;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;
import java.util.Locale;

@Service
public class ResultParserService {

    private static final Logger log = LoggerFactory.getLogger(ResultParserService.class);
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Parse all tool output files and return deduplicated CVE list.
     * Each CveEntry gets confirmedBy = number of distinct tools that found it.
     */
    public List<CveEntry> parseCves(String resultsDir) {
        Map<String, CveEntry> deduped = new LinkedHashMap<>();
        Map<String, Set<String>> sourcesMap = new LinkedHashMap<>();

        parseGrype(new File(resultsDir, "grype.json"), deduped, sourcesMap);
        parseTrivy(new File(resultsDir, "trivy.json"), deduped, sourcesMap);
        parseOsvScanner(new File(resultsDir, "osv-scanner.json"), deduped, sourcesMap);
        parseSemgrep(new File(resultsDir, "semgrep.json"), deduped, sourcesMap);
        parseDependencyCheck(new File(resultsDir, "dependency-check-report.json"), deduped, sourcesMap);
        parseNpmAudit(new File(resultsDir, "npm-audit.json"), deduped, sourcesMap);
        parseZap(new File(resultsDir, "zap.json"), deduped, sourcesMap);

        // Merge confirmedBy counts into each CveEntry
        for (Map.Entry<String, CveEntry> e : deduped.entrySet()) {
            Set<String> srcs = sourcesMap.getOrDefault(e.getKey(), Collections.emptySet());
            if (!srcs.isEmpty()) {
                e.getValue().setConfirmedBy(srcs.size());
                e.getValue().setSources(String.join(",", srcs));
            }
        }

        return new ArrayList<>(deduped.values());
    }

    /**
     * Parse gitleaks.json for secret findings.
     */
    public List<SecretFinding> parseSecrets(String resultsDir) {
        List<SecretFinding> secrets = new ArrayList<>();
        File file = new File(resultsDir, "gitleaks.json");
        if (!file.exists() || file.length() == 0)
            return secrets;

        try {
            JsonNode root = mapper.readTree(file);
            if (root.isArray()) {
                for (JsonNode node : root) {
                    secrets.add(SecretFinding.builder()
                            .ruleId(text(node, "RuleID"))
                            .description(text(node, "Description"))
                            .file(text(node, "File"))
                            .startLine(intVal(node, "StartLine"))
                            .endLine(intVal(node, "EndLine"))
                            .match(text(node, "Match"))
                            .author(text(node, "Author"))
                            .email(text(node, "Email"))
                            .date(text(node, "Date"))
                            .commit(text(node, "Commit"))
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse gitleaks.json: {}", e.getMessage());
        }
        return secrets;
    }

    /**
     * Parse semgrep-owasp.json directly from disk for SAST findings.
     */
    public List<SastFindingDto> parseSastDirect(String resultsDir) {
        List<SastFindingDto> findings = new ArrayList<>();
        File file = new File(resultsDir, "semgrep-owasp.json");
        if (!file.exists() || file.length() == 0)
            return findings;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode results = root.get("results");
            if (results == null || !results.isArray())
                return findings;
            for (JsonNode r : results) {
                String checkId = text(r, "check_id");
                String path = r.has("path") ? r.get("path").asText() : "";
                int line = 0;
                JsonNode startNode = r.get("start");
                if (startNode != null && startNode.has("line"))
                    line = startNode.get("line").asInt();
                JsonNode extra = r.get("extra");
                String severity = extra != null ? text(extra, "severity") : "UNKNOWN";
                String message = extra != null ? text(extra, "message") : "";
                String owaspCategory = "Other";
                if (extra != null) {
                    JsonNode metadata = extra.get("metadata");
                    if (metadata != null) {
                        JsonNode owaspNode = metadata.get("owasp");
                        if (owaspNode != null && !owaspNode.isNull()) {
                            if (owaspNode.isArray() && owaspNode.size() > 0) {
                                owaspCategory = owaspNode.get(0).asText();
                            } else if (!owaspNode.isArray()) {
                                owaspCategory = owaspNode.asText();
                            }
                        }
                    }
                }
                final int finalLine = line;
                findings.add(SastFindingDto.builder()
                        .checkId(checkId)
                        .file(path)
                        .line(finalLine > 0 ? finalLine : null)
                        .message(message)
                        .severity(severity != null ? severity.toUpperCase() : "UNKNOWN")
                        .owaspCategory(owaspCategory)
                        .build());
            }
        } catch (Exception e) {
            log.warn("Failed to parse semgrep-owasp.json: {}", e.getMessage());
        }
        return findings;
    }

    /**
     * Read result.json to get ecosystems and tools executed.
     */
    public JsonNode parseResultJson(String resultsDir) {
        File file = new File(resultsDir, "result.json");
        if (!file.exists())
            return null;
        try {
            return mapper.readTree(file);
        } catch (Exception e) {
            log.warn("Failed to parse result.json: {}", e.getMessage());
            return null;
        }
    }

    // ===================== DEDUPLICATION KEY =====================
    /**
     * Build a deduplication key for a CVE entry.
     * If a PURL is available, use: cveId|purl|moduleName
     * Otherwise: cveId|packageName|version|ecosystem|moduleName|manifestFile
     */
    private String buildKey(String cveId, String purl, String packageName,
            String version, String ecosystem,
            String moduleName, String manifestFile) {
        if (purl != null && !purl.isBlank()) {
            return cveId + "|purl:" + purl + "|mod:" + nullToEmpty(moduleName);
        }
        return cveId + "|" + nullToEmpty(packageName)
                + "|" + nullToEmpty(version)
                + "|" + nullToEmpty(ecosystem)
                + "|mod:" + nullToEmpty(moduleName)
                + "|mf:" + nullToEmpty(manifestFile);
    }

    private static String nullToEmpty(String s) {
        return s != null ? s : "";
    }

    /** Derive the module name from the first path segment of a manifest file. */
    private static String moduleFromManifest(String manifestFile) {
        if (manifestFile == null || manifestFile.isBlank())
            return "";
        String normalized = manifestFile.replace("\\", "/");
        int slash = normalized.indexOf('/');
        return slash > 0 ? normalized.substring(0, slash) : "";
    }

    // ===================== GRYPE PARSER =====================
    private void parseGrype(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode matches = root.get("matches");
            if (matches == null || !matches.isArray())
                return;

            for (JsonNode match : matches) {
                JsonNode vuln = match.get("vulnerability");
                JsonNode artifact = match.get("artifact");
                if (vuln == null)
                    continue;

                String cveId = text(vuln, "id");
                String pkg = artifact != null ? text(artifact, "name") : "";
                String version = artifact != null ? text(artifact, "version") : "";

                // Extract SBOM-relevant fields from Grype artifact
                String purl = artifact != null ? text(artifact, "purl") : null;
                String bomRef = artifact != null ? text(artifact, "id") : null;
                String componentType = artifact != null ? text(artifact, "type") : null;

                // ecosystem from purl or artifact.type
                String ecosystem = null;
                if (purl != null && !purl.isBlank()) {
                    ecosystem = SbomParserService.ecosystemFromPurl(purl);
                    if ("unknown".equals(ecosystem))
                        ecosystem = null;
                }
                if (ecosystem == null && componentType != null) {
                    // Grype types: "java-archive", "npm", "python", "gem", "go-module", etc.
                    ecosystem = grypeTypeToEcosystem(componentType);
                }

                // manifestFile: use artifact.locations[0].path as evidence only
                String manifestFile = null;
                if (artifact != null) {
                    JsonNode locations = artifact.get("locations");
                    if (locations != null && locations.isArray() && !locations.isEmpty()) {
                        JsonNode loc = locations.get(0);
                        manifestFile = text(loc, "path");
                        if (manifestFile == null)
                            manifestFile = text(loc, "realPath");
                    }
                }
                String moduleName = moduleFromManifest(manifestFile);

                String key = buildKey(cveId, purl, pkg, version, ecosystem, moduleName, manifestFile);

                sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("grype");
                if (deduped.containsKey(key))
                    continue;

                String severity = text(vuln, "severity");
                Double cvss = null;
                JsonNode cvssArr = vuln.get("cvss");
                if (cvssArr != null && cvssArr.isArray() && !cvssArr.isEmpty()) {
                    JsonNode metrics = cvssArr.get(0).get("metrics");
                    if (metrics != null && metrics.has("baseScore")) {
                        cvss = metrics.get("baseScore").asDouble();
                    }
                }

                String fixedVer = null;
                JsonNode fix = vuln.get("fix");
                if (fix != null && fix.has("versions") && fix.get("versions").isArray()
                        && !fix.get("versions").isEmpty()) {
                    fixedVer = fix.get("versions").get(0).asText();
                }

                deduped.put(key, CveEntry.builder()
                        .cveId(cveId)
                        .packageName(pkg)
                        .packageVersion(version)
                        .severity(severity != null ? severity.toUpperCase() : "UNKNOWN")
                        .cvssScore(cvss)
                        .fixedVersion(fixedVer)
                        .description(text(vuln, "description"))
                        .dataSource(text(vuln, "dataSource"))
                        .source("grype")
                        .purl(purl)
                        .bomRef(bomRef)
                        .componentType(componentType)
                        .ecosystem(ecosystem)
                        .manifestFile(manifestFile)
                        .moduleName(moduleName.isEmpty() ? null : moduleName)
                        .build());
            }
        } catch (Exception e) {
            log.warn("Failed to parse grype.json: {}", e.getMessage());
        }
    }

    /** Convert Grype artifact type to ecosystem name. */
    private static String grypeTypeToEcosystem(String type) {
        if (type == null)
            return "unknown";
        return switch (type.toLowerCase(java.util.Locale.ROOT)) {
            case "java-archive" -> "maven";
            case "npm" -> "npm";
            case "python" -> "pypi";
            case "gem" -> "gem";
            case "go-module" -> "golang";
            case "rust-crate" -> "cargo";
            case "deb" -> "deb";
            case "rpm" -> "rpm";
            case "apk" -> "apk";
            default -> type.toLowerCase(java.util.Locale.ROOT);
        };
    }

    // ===================== TRIVY PARSER =====================
    private void parseTrivy(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode results = root.get("Results");
            if (results == null || !results.isArray())
                return;

            for (JsonNode result : results) {
                // Target is the manifest/image layer path (e.g. "package-lock.json", "pom.xml")
                String target = text(result, "Target");
                // Type is the ecosystem (e.g. "npm", "maven", "debian")
                String resultType = text(result, "Type");
                String trivyEcosystem = resultType != null ? resultType.toLowerCase(java.util.Locale.ROOT) : null;
                String moduleName = moduleFromManifest(target);

                JsonNode vulns = result.get("Vulnerabilities");
                if (vulns == null || !vulns.isArray())
                    continue;

                for (JsonNode v : vulns) {
                    String cveId = text(v, "VulnerabilityID");
                    String pkg = text(v, "PkgName");
                    String version = text(v, "InstalledVersion");

                    // Trivy may have PkgPath (path within the image layer)
                    String pkgPath = text(v, "PkgPath");
                    // Prefer PkgPath as manifestFile if available, else use Target
                    String manifestFile = pkgPath != null ? pkgPath : target;
                    String effectiveModule = moduleFromManifest(manifestFile);
                    if (effectiveModule.isEmpty())
                        effectiveModule = moduleName;

                    // Trivy may have PURL — only use it if present
                    String purl = null;
                    // Try newer Trivy format: PkgIdentifier.PURL
                    JsonNode pkgId = v.get("PkgIdentifier");
                    if (pkgId != null) {
                        purl = text(pkgId, "PURL");
                    }

                    String key = buildKey(cveId, purl, pkg, version, trivyEcosystem,
                            effectiveModule, manifestFile);

                    sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("trivy");
                    if (deduped.containsKey(key))
                        continue;

                    Double cvss = null;
                    JsonNode cvssNode = v.get("CVSS");
                    if (cvssNode != null) {
                        Iterator<JsonNode> sources = cvssNode.elements();
                        while (sources.hasNext()) {
                            JsonNode src = sources.next();
                            if (src.has("V3Score")) {
                                cvss = src.get("V3Score").asDouble();
                                break;
                            }
                        }
                    }

                    deduped.put(key, CveEntry.builder()
                            .cveId(cveId)
                            .packageName(pkg)
                            .packageVersion(version)
                            .severity(text(v, "Severity") != null ? text(v, "Severity").toUpperCase() : "UNKNOWN")
                            .cvssScore(cvss)
                            .fixedVersion(text(v, "FixedVersion"))
                            .description(text(v, "Description"))
                            .dataSource(text(v, "PrimaryURL"))
                            .source("trivy")
                            .purl(purl)
                            .ecosystem(trivyEcosystem)
                            .manifestFile(manifestFile)
                            .moduleName(effectiveModule.isEmpty() ? null : effectiveModule)
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse trivy.json: {}", e.getMessage());
        }
    }

    // ===================== OSV-SCANNER PARSER =====================
    private void parseOsvScanner(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode results = root.get("results");
            if (results == null || !results.isArray())
                return;

            for (JsonNode result : results) {
                JsonNode packages = result.get("packages");
                if (packages == null || !packages.isArray())
                    continue;

                for (JsonNode pkgNode : packages) {
                    JsonNode pkg = pkgNode.get("package");
                    String pkgName = pkg != null ? text(pkg, "name") : "";
                    String pkgVersion = pkg != null ? text(pkg, "version") : "";

                    JsonNode vulns = pkgNode.get("vulnerabilities");
                    if (vulns == null || !vulns.isArray())
                        continue;

                    for (JsonNode v : vulns) {
                        String osvId = text(v, "id");
                        JsonNode aliases = v.get("aliases");
                        String cveId = osvId;
                        if (aliases != null && aliases.isArray()) {
                            for (JsonNode alias : aliases) {
                                if (alias.asText().startsWith("CVE-")) {
                                    cveId = alias.asText();
                                    break;
                                }
                            }
                        }

                        String key = cveId + "|" + pkgName;
                        sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("osv-scanner");
                        if (deduped.containsKey(key))
                            continue;

                        String severity = "UNKNOWN";
                        Double cvss = null;
                        JsonNode sevArr = v.get("severity");
                        if (sevArr != null && sevArr.isArray()) {
                            for (JsonNode s : sevArr) {
                                if ("CVSS_V3".equals(text(s, "type"))) {
                                    String score = text(s, "score");
                                    if (score != null) {
                                        try {
                                            cvss = Double.parseDouble(score.split("/")[0]);
                                        } catch (Exception ignored) {
                                        }
                                    }
                                }
                            }
                        }
                        if (cvss != null) {
                            if (cvss >= 9.0)
                                severity = "CRITICAL";
                            else if (cvss >= 7.0)
                                severity = "HIGH";
                            else if (cvss >= 4.0)
                                severity = "MEDIUM";
                            else
                                severity = "LOW";
                        }

                        // Extract fixed version from affected[].ranges[].events[fixed]
                        String fixedVer = null;
                        JsonNode affectedArr = v.get("affected");
                        outer: if (affectedArr != null && affectedArr.isArray()) {
                            for (JsonNode affected : affectedArr) {
                                JsonNode ranges = affected.get("ranges");
                                if (ranges == null || !ranges.isArray())
                                    continue;
                                for (JsonNode range : ranges) {
                                    JsonNode events = range.get("events");
                                    if (events == null || !events.isArray())
                                        continue;
                                    for (JsonNode event : events) {
                                        JsonNode fixed = event.get("fixed");
                                        if (fixed != null && !fixed.isNull()) {
                                            fixedVer = fixed.asText();
                                            break outer;
                                        }
                                    }
                                }
                            }
                        }

                        deduped.put(key, CveEntry.builder()
                                .cveId(cveId)
                                .packageName(pkgName)
                                .packageVersion(pkgVersion)
                                .severity(severity)
                                .cvssScore(cvss)
                                .fixedVersion(fixedVer)
                                .description(text(v, "summary"))
                                .dataSource(text(v, "modified"))
                                .source("osv-scanner")
                                .build());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse osv-scanner.json: {}", e.getMessage());
        }
    }

    // ===================== SEMGREP PARSER =====================
    private void parseSemgrep(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode results = root.get("results");
            if (results == null || !results.isArray())
                return;

            for (JsonNode r : results) {
                String checkId = text(r, "check_id");
                JsonNode extra = r.get("extra");
                String severity = extra != null ? text(extra, "severity") : "UNKNOWN";
                String message = extra != null ? text(extra, "message") : "";

                JsonNode metadata = extra != null ? extra.get("metadata") : null;
                String cveId = null;
                String ruleUrl = null;
                String category = null;
                if (metadata != null) {
                    JsonNode cweArr = metadata.get("cwe");
                    if (cweArr != null && cweArr.isArray() && !cweArr.isEmpty()) {
                        String raw = cweArr.get(0).asText();
                        // "CWE-798: Use of Hard-coded Credentials" → "CWE-798"
                        cveId = raw.contains(":") ? raw.substring(0, raw.indexOf(':')).trim() : raw;
                    }
                    JsonNode ruleUrlNode = metadata.get("source-rule-url");
                    if (ruleUrlNode != null && !ruleUrlNode.isNull())
                        ruleUrl = ruleUrlNode.asText();
                    JsonNode catNode = metadata.get("category");
                    if (catNode != null && !catNode.isNull())
                        category = catNode.asText();
                }
                if (cveId == null)
                    cveId = checkId;

                String path = "";
                JsonNode pathNode = r.get("path");
                if (pathNode != null)
                    path = pathNode.asText();

                int line = 0;
                JsonNode startNode = r.get("start");
                if (startNode != null && startNode.has("line"))
                    line = startNode.get("line").asInt();

                // Dedup semgrep by rule + file + line — each location is a distinct finding
                String key = "semgrep|" + checkId + "|" + path + "|" + line;
                sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("semgrep");
                if (deduped.containsKey(key))
                    continue;

                deduped.put(key, CveEntry.builder()
                        .cveId(cveId)
                        .packageName(checkId)
                        .severity(severity != null ? severity.toUpperCase() : "UNKNOWN")
                        .description(message)
                        .dataSource(ruleUrl)
                        .source("semgrep")
                        .filePath(path)
                        .lineNumber(line > 0 ? line : null)
                        .build());
            }
        } catch (Exception e) {
            log.warn("Failed to parse semgrep.json: {}", e.getMessage());
        }
    }

    // ===================== DEPENDENCY-CHECK PARSER =====================
    private void parseDependencyCheck(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode deps = root.get("dependencies");
            if (deps == null || !deps.isArray())
                return; // handles {"warning":"..."} case gracefully

            for (JsonNode dep : deps) {
                JsonNode vulns = dep.get("vulnerabilities");
                if (vulns == null || !vulns.isArray())
                    continue;

                String fileName = text(dep, "fileName");
                if (fileName == null)
                    fileName = "";
                // Extract package name and version from filename e.g. "spring-core-6.1.4.jar"
                String pkgName = fileName.replaceAll("-[0-9].*", "").replaceAll("\\.[^.]+$", "");
                String pkgVersion = fileName.replaceAll("^.*?-([0-9][^-]*(?:-[^0-9][^-]*)*)\\.[^.]+$", "$1");
                if (pkgVersion.equals(fileName))
                    pkgVersion = null; // no version extracted

                for (JsonNode v : vulns) {
                    String cveId = text(v, "name");
                    if (cveId == null || cveId.isEmpty())
                        continue;
                    String key = cveId + "|" + pkgName;

                    sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("dependency-check");
                    if (deduped.containsKey(key))
                        continue;

                    String severity = text(v, "severity");
                    Double cvss = null;
                    JsonNode cvssv3 = v.get("cvssv3");
                    if (cvssv3 != null && cvssv3.has("baseScore")) {
                        cvss = cvssv3.get("baseScore").asDouble();
                    } else {
                        JsonNode cvssv2 = v.get("cvssv2");
                        if (cvssv2 != null && cvssv2.has("score")) {
                            cvss = cvssv2.get("score").asDouble();
                        }
                    }

                    deduped.put(key, CveEntry.builder()
                            .cveId(cveId)
                            .packageName(pkgName)
                            .packageVersion(pkgVersion)
                            .severity(severity != null ? severity.toUpperCase() : "UNKNOWN")
                            .cvssScore(cvss)
                            .description(text(v, "description"))
                            .dataSource("https://nvd.nist.gov/vuln/detail/" + cveId)
                            .source("dependency-check")
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse dependency-check-report.json: {}", e.getMessage());
        }
    }

    // ===================== NPM-AUDIT PARSER =====================
    private void parseNpmAudit(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode vulns = root.get("vulnerabilities");
            if (vulns == null || !vulns.isObject())
                return; // handles {"warning":"..."} case gracefully

            Iterator<Map.Entry<String, JsonNode>> fields = vulns.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String pkgName = entry.getKey();
                JsonNode v = entry.getValue();

                // Extract CVE/advisory ID, description, CVSS from via[]
                String cveId = null;
                String description = null;
                String dataSource = null;
                Double cvss = null;

                JsonNode via = v.get("via");
                if (via != null && via.isArray()) {
                    for (JsonNode viaEntry : via) {
                        if (viaEntry.isObject()) {
                            String url = text(viaEntry, "url");
                            if (url != null) {
                                String[] parts = url.split("/");
                                cveId = parts[parts.length - 1]; // e.g. GHSA-xxxx or CVE-xxxx
                                dataSource = url;
                            }
                            if (description == null)
                                description = text(viaEntry, "title");
                            JsonNode cvssNode = viaEntry.get("cvss");
                            if (cvssNode != null && cvssNode.has("score")) {
                                cvss = cvssNode.get("score").asDouble();
                            }
                            break;
                        }
                    }
                }
                if (cveId == null)
                    cveId = "npm|" + pkgName;

                String key = cveId + "|" + pkgName;
                sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("npm-audit");
                if (deduped.containsKey(key))
                    continue;

                String severity = text(v, "severity");
                String fixedVer = null;
                JsonNode fixAvail = v.get("fixAvailable");
                if (fixAvail != null && fixAvail.isObject()) {
                    fixedVer = text(fixAvail, "version");
                } else if (fixAvail != null && fixAvail.isBoolean() && fixAvail.asBoolean()) {
                    fixedVer = "available";
                }

                deduped.put(key, CveEntry.builder()
                        .cveId(cveId)
                        .packageName(pkgName)
                        .severity(severity != null ? severity.toUpperCase() : "UNKNOWN")
                        .cvssScore(cvss)
                        .fixedVersion(fixedVer)
                        .description(description)
                        .dataSource(dataSource)
                        .source("npm-audit")
                        .build());
            }
        } catch (Exception e) {
            log.warn("Failed to parse npm-audit.json: {}", e.getMessage());
        }
    }

    // ===================== ZAP DAST PARSER =====================
    // ZAP JSON format: { "site": [ { "alerts": [ { "pluginid", "alert", "riskdesc",
    // "desc", "solution", "reference", "instances": [{"uri"}] } ] } ] }
    private void parseZap(File file, Map<String, CveEntry> deduped, Map<String, Set<String>> sourcesMap) {
        if (!file.exists() || file.length() == 0)
            return;
        try {
            JsonNode root = mapper.readTree(file);
            JsonNode sites = root.get("site");
            if (sites == null || !sites.isArray())
                return;

            for (JsonNode site : sites) {
                JsonNode alerts = site.get("alerts");
                if (alerts == null || !alerts.isArray())
                    continue;

                for (JsonNode alert : alerts) {
                    String pluginId = text(alert, "pluginid");
                    String alertName = text(alert, "alert");
                    String riskDesc = text(alert, "riskdesc"); // e.g. "High (Medium)"
                    String desc = text(alert, "desc");
                    String solution = text(alert, "solution");
                    String reference = text(alert, "reference");

                    // Derive first affected URL from instances
                    String affectedUrl = null;
                    JsonNode instances = alert.get("instances");
                    if (instances != null && instances.isArray() && !instances.isEmpty()) {
                        affectedUrl = text(instances.get(0), "uri");
                    }

                    // Map riskdesc to severity (ZAP uses "High", "Medium", "Low", "Informational")
                    String severity = "UNKNOWN";
                    Double cvss = null;
                    if (riskDesc != null) {
                        String risk = riskDesc.split(" ")[0].toUpperCase();
                        switch (risk) {
                            case "HIGH" -> {
                                severity = "HIGH";
                                cvss = 7.5;
                            }
                            case "MEDIUM" -> {
                                severity = "MEDIUM";
                                cvss = 5.0;
                            }
                            case "LOW" -> {
                                severity = "LOW";
                                cvss = 3.0;
                            }
                            default -> severity = "LOW";
                        }
                    }

                    // Build a stable CVE-like ID: ZAP-<pluginId>
                    String cveId = "ZAP-" + (pluginId != null ? pluginId : alertName);
                    // Include affected URL in key so each URL-alert pair is distinct
                    String key = "zap|" + cveId + "|" + (affectedUrl != null ? affectedUrl : "unknown");

                    sourcesMap.computeIfAbsent(key, k -> new LinkedHashSet<>()).add("zaproxy");
                    if (deduped.containsKey(key))
                        continue;

                    // Compose description: ZAP desc + solution hint
                    String fullDesc = desc != null ? desc : "";
                    if (solution != null && !solution.isBlank()) {
                        fullDesc += "\n\nSolution: " + solution;
                    }

                    deduped.put(key, CveEntry.builder()
                            .cveId(cveId)
                            .packageName(alertName != null ? alertName : cveId)
                            .severity(severity)
                            .cvssScore(cvss)
                            .description(fullDesc.trim())
                            .dataSource(reference)
                            .filePath(affectedUrl)
                            .source("zaproxy")
                            .build());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse zap.json: {}", e.getMessage());
        }
    }

    // ===================== UTILS =====================
    private String text(JsonNode node, String field) {
        JsonNode f = node.get(field);
        return f != null && !f.isNull() ? f.asText() : null;
    }

    private Integer intVal(JsonNode node, String field) {
        JsonNode f = node.get(field);
        return f != null && !f.isNull() ? f.asInt() : null;
    }
}
