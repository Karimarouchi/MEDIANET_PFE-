package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.ConfigFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.util.*;

/**
 * Reads the misconfigurations found by Trivy, Checkov and Hadolint and merges the ones two tools report for the same
 * rule on the same file.
 *
 * <p>Trivy writes the same misconfigurations in trivy.json, trivy-iac.json and trivy-docker-misconfig.json, so only
 * trivy.json is read. A finding that Checkov or Hadolint did not rate keeps severity UNKNOWN: inventing MEDIUM would
 * make the tools look comparable when they are not.
 */
@Service
public class ConfigFindingParser {

    private static final Logger log = LoggerFactory.getLogger(ConfigFindingParser.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    static final String UNKNOWN = "UNKNOWN";
    private static final List<String> SEVERITY_ORDER = List.of(UNKNOWN, "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL");

    /**
     * Rules of two tools that state the same thing, checked on the titles of real scan results. Each line is one
     * group; two findings merge only when they belong to the same group, come from different tools and sit in the same
     * file. Anything not listed stays separate: a missed merge shows twice, a wrong merge hides a real finding.
     */
    private static final Map<String, String> EQUIVALENT_RULES = new HashMap<>();

    static {
        group("dockerfile-user", "DS-0002", "CKV_DOCKER_3");
        group("dockerfile-healthcheck", "DS-0026", "CKV_DOCKER_2");
        group("dockerfile-no-install-recommends", "DS-0029", "DL3015");
        group("k8s-privilege-escalation", "KSV-0001", "CKV_K8S_20");
        group("k8s-cpu-limit", "KSV-0011", "CKV_K8S_11");
        group("k8s-cpu-request", "KSV-0015", "CKV_K8S_10");
        group("k8s-memory-request", "KSV-0016", "CKV_K8S_12");
        group("k8s-memory-limit", "KSV-0018", "CKV_K8S_13");
        group("k8s-latest-tag", "KSV-0013", "CKV_K8S_14");
        group("k8s-readonly-rootfs", "KSV-0014", "CKV_K8S_22");
        group("k8s-privileged", "KSV-0017", "CKV_K8S_16");
        group("k8s-default-namespace", "KSV-0110", "CKV_K8S_21");
        group("k8s-seccomp", "KSV-0030", "CKV_K8S_31");
        group("k8s-high-uid", "KSV-0020", "CKV_K8S_40");
    }

    private static void group(String name, String... ruleIds) {
        for (String id : ruleIds) {
            EQUIVALENT_RULES.put(id, name);
        }
    }

    public List<ConfigFinding> parse(String resultsDir) {
        if (resultsDir == null) {
            return List.of();
        }
        File dir = new File(resultsDir);
        List<Raw> raws = new ArrayList<>();
        readTrivy(new File(dir, "trivy.json"), raws);
        readCheckov(new File(dir, "checkov.json"), raws);
        File[] hadolints = dir.listFiles((d, n) -> n.startsWith("hadolint") && n.endsWith(".json"));
        if (hadolints != null) {
            Arrays.sort(hadolints);
            for (File f : hadolints) {
                readHadolint(f, raws);
            }
        }
        return merge(raws);
    }

    // ------------------------------------------------------------------ readers

    private void readTrivy(File file, List<Raw> out) {
        JsonNode root = read(file);
        if (root == null || !root.has("Results")) {
            return;
        }
        for (JsonNode result : root.get("Results")) {
            JsonNode items = result.get("Misconfigurations");
            if (items == null || !items.isArray()) {
                continue;
            }
            String type = text(result, "Type");
            String target = text(result, "Target");
            for (JsonNode m : items) {
                String status = text(m, "Status");
                if (status != null && !"FAIL".equalsIgnoreCase(status)) {
                    continue;
                }
                JsonNode cause = m.get("CauseMetadata");
                Raw r = new Raw("trivy");
                r.ruleId = text(m, "ID");
                r.title = text(m, "Title");
                r.description = firstNonBlank(text(m, "Message"), text(m, "Description"));
                r.resolution = text(m, "Resolution");
                r.severity = normalizeSeverity(text(m, "Severity"));
                r.category = categoryOf(type);
                r.file = normalizePath(target);
                r.startLine = positive(cause, "StartLine");
                r.endLine = positive(cause, "EndLine");
                r.resource = cause != null ? text(cause, "Resource") : null;
                r.referenceUrl = text(m, "PrimaryURL");
                out.add(r);
            }
        }
    }

    private void readCheckov(File file, List<Raw> out) {
        JsonNode root = read(file);
        if (root == null) {
            return;
        }
        List<JsonNode> reports = new ArrayList<>();
        if (root.isArray()) {
            root.forEach(reports::add);
        } else {
            reports.add(root);
        }
        for (JsonNode report : reports) {
            String checkType = text(report, "check_type");
            // Checkov's "secrets" framework would duplicate the secret detectors, which have their own table.
            if (checkType != null && checkType.equalsIgnoreCase("secrets")) {
                continue;
            }
            JsonNode failed = report.path("results").path("failed_checks");
            if (!failed.isArray()) {
                continue;
            }
            for (JsonNode f : failed) {
                Raw r = new Raw("checkov");
                r.ruleId = text(f, "check_id");
                r.title = text(f, "check_name");
                r.severity = normalizeSeverity(text(f, "severity"));
                r.category = categoryOf(checkType);
                r.file = normalizePath(text(f, "file_path"));
                JsonNode range = f.get("file_line_range");
                if (range != null && range.isArray() && range.size() >= 2) {
                    r.startLine = range.get(0).asInt() > 0 ? range.get(0).asInt() : null;
                    r.endLine = range.get(1).asInt() > 0 ? range.get(1).asInt() : null;
                }
                r.resource = text(f, "resource");
                r.referenceUrl = text(f, "guideline");
                out.add(r);
            }
        }
    }

    private void readHadolint(File file, List<Raw> out) {
        JsonNode root = read(file);
        if (root == null || !root.isArray()) {
            return;
        }
        for (JsonNode h : root) {
            Raw r = new Raw("hadolint");
            r.ruleId = text(h, "code");
            r.title = text(h, "message");
            r.severity = hadolintSeverity(text(h, "level"));
            r.category = "DOCKERFILE";
            r.file = normalizePath(text(h, "file"));
            r.startLine = positive(h, "line");
            r.endLine = r.startLine;
            if (r.ruleId != null && r.ruleId.matches("DL\\d+")) {
                r.referenceUrl = "https://github.com/hadolint/hadolint/wiki/" + r.ruleId;
            }
            out.add(r);
        }
    }

    // ------------------------------------------------------------------ merge

    private List<ConfigFinding> merge(List<Raw> raws) {
        List<Group> groups = new ArrayList<>();
        for (Raw raw : raws) {
            Group target = null;
            for (Group g : groups) {
                if (g.accepts(raw)) {
                    target = g;
                    break;
                }
            }
            if (target == null) {
                groups.add(new Group(raw));
            } else {
                target.add(raw);
            }
        }
        List<ConfigFinding> findings = new ArrayList<>();
        for (Group g : groups) {
            findings.add(g.toFinding());
        }
        return findings;
    }

    private static final class Raw {
        final String tool;
        String ruleId;
        String title;
        String description;
        String resolution;
        String severity = UNKNOWN;
        String category = "OTHER";
        String file;
        Integer startLine;
        Integer endLine;
        String resource;
        String referenceUrl;

        Raw(String tool) {
            this.tool = tool;
        }

        String equivalenceGroup() {
            return ruleId == null ? null : EQUIVALENT_RULES.get(ruleId);
        }
    }

    private static final class Group {
        final List<Raw> members = new ArrayList<>();

        Group(Raw first) {
            members.add(first);
        }

        /** Same tool + same rule + same place is the same finding repeated; across tools it needs an equivalence. */
        boolean accepts(Raw raw) {
            Raw head = members.get(0);
            if (!Objects.equals(head.file, raw.file)) {
                return false;
            }
            boolean sameTool = members.stream().anyMatch(m -> m.tool.equals(raw.tool));
            if (sameTool) {
                return members.stream().anyMatch(m -> m.tool.equals(raw.tool)
                        && Objects.equals(m.ruleId, raw.ruleId)
                        && Objects.equals(m.startLine, raw.startLine)
                        && Objects.equals(m.resource, raw.resource));
            }
            String g = raw.equivalenceGroup();
            if (g == null || !g.equals(head.equivalenceGroup())) {
                return false;
            }
            return linesOverlap(head, raw);
        }

        /**
         * Checkov gives the line range of the whole resource and Trivy the lines of the offending block, so two
         * findings are the same place when their ranges overlap (a missing line matches any).
         */
        private static boolean linesOverlap(Raw a, Raw b) {
            if (a.startLine == null || b.startLine == null) {
                return true;
            }
            int aEnd = a.endLine != null ? a.endLine : a.startLine;
            int bEnd = b.endLine != null ? b.endLine : b.startLine;
            return a.startLine <= bEnd && b.startLine <= aEnd;
        }

        void add(Raw raw) {
            boolean sameTool = members.stream().anyMatch(m -> m.tool.equals(raw.tool));
            if (!sameTool) {
                members.add(raw);
            }
        }

        ConfigFinding toFinding() {
            Raw head = members.get(0);
            String severity = UNKNOWN;
            Integer line = null;
            Integer end = null;
            LinkedHashSet<String> tools = new LinkedHashSet<>();
            LinkedHashSet<String> rules = new LinkedHashSet<>();
            for (Raw m : members) {
                if (SEVERITY_ORDER.indexOf(m.severity) > SEVERITY_ORDER.indexOf(severity)) {
                    severity = m.severity;
                }
                if (line == null) {
                    line = m.startLine;
                    end = m.endLine;
                }
                tools.add(m.tool);
                if (m.ruleId != null) {
                    rules.add(m.ruleId);
                }
            }
            return ConfigFinding.builder()
                    .ruleId(head.ruleId)
                    .ruleIds(String.join(",", rules))
                    .title(truncate(head.title, 500))
                    .description(members.stream().map(m -> m.description).filter(Objects::nonNull).findFirst().orElse(null))
                    .resolution(members.stream().map(m -> m.resolution).filter(Objects::nonNull).findFirst().orElse(null))
                    .severity(severity)
                    .category(head.category)
                    .file(head.file)
                    .startLine(line)
                    .endLine(end)
                    .resource(members.stream().map(m -> m.resource).filter(Objects::nonNull).findFirst().orElse(null))
                    .sources(String.join(",", tools))
                    .referenceUrl(members.stream().map(m -> m.referenceUrl).filter(Objects::nonNull).findFirst().orElse(null))
                    .build();
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Hadolint: error and warning are the findings to read; info and style are kept but rated INFO. */
    static String hadolintSeverity(String level) {
        if (level == null) {
            return UNKNOWN;
        }
        return switch (level.toLowerCase(Locale.ROOT)) {
            case "error" -> "MEDIUM";
            case "warning" -> "LOW";
            case "info", "style" -> "INFO";
            default -> UNKNOWN;
        };
    }

    static String normalizeSeverity(String raw) {
        if (raw == null || raw.isBlank()) {
            return UNKNOWN;
        }
        String s = raw.trim().toUpperCase(Locale.ROOT);
        return SEVERITY_ORDER.contains(s) ? s : UNKNOWN;
    }

    static String categoryOf(String type) {
        if (type == null) {
            return "OTHER";
        }
        String t = type.toLowerCase(Locale.ROOT);
        if (t.contains("docker")) {
            return "DOCKERFILE";
        }
        if (t.contains("kubernetes") || t.contains("helm") || t.contains("kustomize")) {
            return "KUBERNETES";
        }
        if (t.contains("terraform")) {
            return "TERRAFORM";
        }
        if (t.contains("github") || t.contains("gitlab") || t.contains("circleci") || t.contains("azure_pipelines")
                || t.contains("bitbucket") || t.contains("argo")) {
            return "CI_CD";
        }
        return "OTHER";
    }

    static String normalizePath(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String p = raw.replace('\\', '/');
        int marker = p.indexOf("/workspace/repo/");
        if (marker >= 0) {
            p = p.substring(marker + "/workspace/repo/".length());
        }
        while (p.startsWith("./") || p.startsWith("/")) {
            p = p.startsWith("./") ? p.substring(2) : p.substring(1);
        }
        return p.isEmpty() ? null : p;
    }

    private static Integer positive(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode f = node.get(field);
        return f != null && f.isNumber() && f.asInt() > 0 ? f.asInt() : null;
    }

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode f = node.get(field);
        return f != null && !f.isNull() && !f.asText().isBlank() ? f.asText() : null;
    }

    private static String firstNonBlank(String a, String b) {
        return a != null ? a : b;
    }

    private static String truncate(String s, int max) {
        return s != null && s.length() > max ? s.substring(0, max) : s;
    }

    private JsonNode read(File file) {
        if (!file.exists() || file.length() == 0) {
            return null;
        }
        try {
            return MAPPER.readTree(file);
        } catch (Exception e) {
            log.warn("Failed to parse {}: {}", file.getName(), e.getMessage());
            return null;
        }
    }
}
