package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.AuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Pattern;

@Service
public class AutoFixService {

    private static final Logger log = LoggerFactory.getLogger(AutoFixService.class);

    @Value("${gemini.api.key}")
    private String geminiApiKey;

    @Value("${gemini.api.url}")
    private String geminiApiUrl;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final GitLabService gitLabService;

    public AutoFixService(GitLabService gitLabService) {
        this.gitLabService = gitLabService;
    }

    /**
     * Fetches the manifest file from GitHub, applies a deterministic dependency
     * update, and returns the original and fixed content as line arrays, plus the
     * file SHA.
     */
    public Map<String, Object> previewFix(
            String repoFullName,
            String packageName,
            String currentVersion,
            String fixedVersion,
            String cveId,
            String filePath,
            String source,
            String provider,
            String accessToken) throws Exception {

        AuthProvider gitProvider = resolveProvider(provider);

        String normalizedPackage = normalizePackageName(packageName);
        String artifactId = extractArtifactId(normalizedPackage);
        String groupId = extractGroupId(normalizedPackage);

        // Discover where the manifest file actually lives in the repo
        String resolvedPath = discoverManifestPath(repoFullName, normalizedPackage, filePath, source, gitProvider,
                accessToken);
        log.info("[AutoFix] repo={}, package={}, normalizedPackage={}, version={} → fixedVersion={}, resolved path={}",
                repoFullName, packageName, normalizedPackage, currentVersion, fixedVersion, resolvedPath);

        RemoteFile remoteFile = fetchRemoteFile(repoFullName, resolvedPath, gitProvider, accessToken);
        String originalContent = remoteFile.content();
        String sha = remoteFile.sha();
        List<String> originalLines = Arrays.asList(originalContent.split("\n", -1));

        // 3. Attempt deterministic fix first — preserves formatting exactly
        String fixedContent = tryProgrammaticFix(originalContent, resolvedPath, normalizedPackage, artifactId, groupId,
                currentVersion, fixedVersion);

        if (fixedContent != null) {
            log.info("[AutoFix] Programmatic fix applied for '{}'", normalizedPackage);
        } else {
            throw new IllegalStateException(buildUnsupportedFixMessage(normalizedPackage, resolvedPath));
        }

        List<String> fixedLines = Arrays.asList(fixedContent.split("\n", -1));

        Map<String, Object> result = new HashMap<>();
        result.put("originalLines", originalLines);
        result.put("fixedLines", fixedLines);
        result.put("fixedContent", fixedContent);
        result.put("filePath", resolvedPath);
        result.put("sha", sha != null ? sha : "");

        // If we fixed package.json, also patch the lock file so the next scan is clean
        if (resolvedPath.endsWith("package.json")) {
            String lockPath = resolvedPath.replace("package.json", "package-lock.json");
            try {
                RemoteFile lockFile = fetchRemoteFile(repoFullName, lockPath, gitProvider, accessToken);
                String lockOriginal = lockFile.content();
                String lockFixed = fixPackageLockJson(lockOriginal, normalizedPackage, currentVersion, fixedVersion);
                if (lockFixed != null) {
                    log.info("[AutoFix] Also patching lock file: {}", lockPath);
                    result.put("lockFilePath", lockPath);
                    result.put("lockFileSha", lockFile.sha());
                    result.put("lockFileContent", lockFixed);
                }
            } catch (Exception e) {
                log.warn("[AutoFix] Lock file not found/patchable at {}: {}", lockPath, e.getMessage());
            }
        }

        return result;
    }

    /**
     * Commits the fixed content back to GitHub.
     * Optionally also commits a patched lock file
     * (lockFilePath/lockFileSha/lockFileContent).
     */
    public Map<String, Object> applyFix(
            String repoFullName,
            String filePath,
            String sha,
            String fixedContent,
            String commitMessage,
            String provider,
            String accessToken,
            String branch,
            String lockFilePath,
            String lockFileSha,
            String lockFileContent) throws Exception {

        AuthProvider gitProvider = resolveProvider(provider);

        // Commit the main file (package.json / pom.xml / etc.)
        Map<String, Object> result = commitFile(repoFullName, filePath, sha, fixedContent, commitMessage,
                gitProvider, accessToken, branch);

        // Also commit the lock file if provided
        if (lockFilePath != null && lockFileSha != null && lockFileContent != null) {
            try {
                commitFile(repoFullName, lockFilePath, lockFileSha, lockFileContent,
                        "chore: update " + lockFilePath.substring(lockFilePath.lastIndexOf('/') + 1)
                                + " after dependency fix",
                        gitProvider, accessToken, branch);
                log.info("[AutoFix] Lock file committed: {}", lockFilePath);
            } catch (Exception e) {
                log.warn("[AutoFix] Failed to commit lock file {}: {}", lockFilePath, e.getMessage());
            }
        }

        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> commitFile(String repoFullName, String filePath, String sha,
            String content, String message, AuthProvider provider, String accessToken, String branch) throws Exception {

        if (provider == AuthProvider.GITLAB) {
            return gitLabService.updateFile(repoFullName, filePath, content, accessToken, branch,
                    message != null && !message.isBlank() ? message : "fix: auto-fix CVE via Vulnix Auto-Fix");
        }

        String url = "https://api.github.com/repos/" + repoFullName + "/contents/" + filePath;

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        headers.setContentType(MediaType.APPLICATION_JSON);

        String encodedContent = Base64.getEncoder()
                .encodeToString(content.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> body = new HashMap<>();
        body.put("message", message != null && !message.isBlank()
                ? message
                : "fix: auto-fix CVE via Vulnix Auto-Fix");
        body.put("content", encodedContent);
        body.put("sha", sha);

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(body, headers);
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.PUT, request, Map.class);

        Map<?, ?> responseBody = response.getBody();
        Map<String, Object> result = new HashMap<>();
        if (responseBody != null && responseBody.containsKey("commit")) {
            Map<?, ?> commit = (Map<?, ?>) responseBody.get("commit");
            result.put("commitUrl", commit.get("html_url") != null ? commit.get("html_url") : "");
            result.put("sha", commit.get("sha") != null ? commit.get("sha") : "");
        }
        return result;
    }

    /**
     * Patches a package-lock.json by updating the version for a specific package.
     * Handles both npm v1 (dependencies) and v2/v3 (packages / node_modules/*)
     * formats.
     * Returns the patched content, or null if the package was not found.
     */
    private String fixPackageLockJson(String content, String packageName,
            String currentVersion, String fixedVersion) {
        String[] lines = content.split("\n", -1);
        boolean inBlock = false;
        int braceDepth = 0;
        boolean modified = false;

        for (int i = 0; i < lines.length; i++) {
            String t = lines[i].trim();

            // Match package entry key (v1: "axios": { or v2: "node_modules/axios": {)
            if (!inBlock && (t.equals("\"" + packageName + "\": {")
                    || t.equals("\"node_modules/" + packageName + "\": {"))) {
                inBlock = true;
                braceDepth = 1;
                continue;
            }

            if (inBlock) {
                for (char c : t.toCharArray()) {
                    if (c == '{')
                        braceDepth++;
                    if (c == '}')
                        braceDepth--;
                }
                // "version" key at depth 1 → directly inside our package block
                if (braceDepth == 1 && t.startsWith("\"version\":")) {
                    String oldVal = "\"version\": \"" + currentVersion + "\"";
                    if (lines[i].contains(oldVal)) {
                        lines[i] = lines[i].replace(oldVal,
                                "\"version\": \"" + fixedVersion + "\"");
                        modified = true;
                        inBlock = false;
                    }
                }
                if (braceDepth <= 0)
                    inBlock = false;
            }
        }
        return modified ? String.join("\n", lines) : null;
    }

    // ── programmatic fix helpers ─────────────────────────────────────────────

    /**
     * Tries to fix the dependency version purely in code (no AI).
     * Returns the modified content, or null if the dependency is not explicitly
     * declared (transitive).
     */
    private String tryProgrammaticFix(String content, String filePath,
            String packageName, String artifactId, String groupId,
            String currentVersion, String fixedVersion) {
        String filename = filePath.contains("/")
                ? filePath.substring(filePath.lastIndexOf('/') + 1)
                : filePath;

        if ("pom.xml".equals(filename)) {
            // 1. Try to update an explicit dependency
            String result = fixMavenPom(content, artifactId, currentVersion, fixedVersion);
            if (result != null)
                return result;
            if (!looksLikeJavaDependency(packageName)) {
                log.warn("[AutoFix] Refusing to inject non-Java package '{}' into {}", packageName, filePath);
                return null;
            }
            // 2. Not found → add to <dependencyManagement> (override transitive version)
            String g = groupId != null ? groupId : artifactId;
            return addMavenDependencyManagement(content, g, artifactId, fixedVersion);
        }
        if ("package.json".equals(filename)) {
            return fixPackageJson(content, packageName, fixedVersion);
        }
        if (filename.endsWith("requirements.txt")) {
            return fixRequirements(content, packageName, fixedVersion);
        }
        return null;
    }

    /**
     * Locates an explicit &lt;dependency&gt; block containing the given artifactId
     * and
     * replaces the currentVersion with fixedVersion.
     * Returns the updated content, or null if not found.
     */
    private String fixMavenPom(String content, String artifactId,
            String currentVersion, String fixedVersion) {
        String[] lines = content.split("\n", -1);
        boolean inBlock = false;
        boolean foundArt = false;
        boolean modified = false;
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();

            if (trimmed.equals("<dependency>")) {
                inBlock = true;
                foundArt = false;
            }
            if (inBlock && trimmed.equals("<artifactId>" + artifactId + "</artifactId>")) {
                foundArt = true;
            }
            if (inBlock && foundArt
                    && trimmed.equals("<version>" + currentVersion + "</version>")) {
                line = line.replace(
                        "<version>" + currentVersion + "</version>",
                        "<version>" + fixedVersion + "</version>");
                modified = true;
                foundArt = false;
            }
            if (trimmed.equals("</dependency>")) {
                inBlock = false;
                foundArt = false;
            }
            sb.append(line);
            if (i < lines.length - 1)
                sb.append('\n');
        }
        return modified ? sb.toString() : null;
    }

    /**
     * Inserts a &lt;dependencyManagement&gt; override for a transitive dependency.
     * If a &lt;dependencyManagement&gt; block already exists the entry is added
     * inside it;
     * otherwise a new block is inserted just before &lt;dependencies&gt;.
     */
    private String addMavenDependencyManagement(String content, String groupId,
            String artifactId, String fixedVersion) {
        String entry = "        <dependency>\n" +
                "            <groupId>" + groupId + "</groupId>\n" +
                "            <artifactId>" + artifactId + "</artifactId>\n" +
                "            <version>" + fixedVersion + "</version>\n" +
                "        </dependency>";

        int dmStart = content.indexOf("<dependencyManagement>");
        if (dmStart >= 0) {
            // Block already exists — insert before the inner </dependencies>
            int dmEnd = content.indexOf("</dependencyManagement>", dmStart);
            int innerClose = content.lastIndexOf("</dependencies>", dmEnd);
            if (innerClose > dmStart) {
                return content.substring(0, innerClose)
                        + entry + "\n"
                        + content.substring(innerClose);
            }
        }

        // No dependencyManagement block — insert one before <dependencies>
        int depsIdx = content.indexOf("<dependencies>");
        if (depsIdx >= 0) {
            int lineStart = content.lastIndexOf('\n', depsIdx) + 1;
            String indent = content.substring(lineStart, depsIdx);
            String block = indent + "<dependencyManagement>\n" +
                    indent + "    <dependencies>\n" +
                    entry + "\n" +
                    indent + "    </dependencies>\n" +
                    indent + "</dependencyManagement>\n";
            return content.substring(0, lineStart) + block + content.substring(lineStart);
        }
        return content; // unchanged (shouldn't happen for valid pom.xml)
    }

    /**
     * Updates a dependency version in package.json, preserving the version prefix
     * (^, ~, etc.).
     * Returns the updated content, or null if not found.
     */
    private String fixPackageJson(String content, String packageName, String fixedVersion) {
        String[] sections = { "dependencies", "devDependencies", "peerDependencies", "optionalDependencies" };
        try {
            JsonNode root = objectMapper.readTree(content);
            for (String section : sections) {
                if (root.has(section) && root.path(section).has(packageName)) {
                    String cur = root.path(section).path(packageName).asText();
                    String prefix = cur.replaceAll("^([^0-9]*)[0-9].*", "$1"); // keep leading ^~>=
                    String newVal = prefix + fixedVersion;
                    return content.replace(
                            "\"" + packageName + "\": \"" + cur + "\"",
                            "\"" + packageName + "\": \"" + newVal + "\"");
                }
            }
        } catch (Exception e) {
            log.warn("[AutoFix] Failed to parse package.json: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Updates a dependency version in requirements.txt.
     * Returns the updated content, or null if not found.
     */
    private String fixRequirements(String content, String packageName, String fixedVersion) {
        String[] lines = content.split("\n", -1);
        boolean modified = false;
        for (int i = 0; i < lines.length; i++) {
            String lower = lines[i].toLowerCase();
            if (lower.startsWith(packageName.toLowerCase() + "==")
                    || lower.startsWith(packageName.toLowerCase() + ">=")
                    || lower.startsWith(packageName.toLowerCase() + "~=")) {
                lines[i] = lines[i].replaceAll(
                        "(?i)^" + Pattern.quote(packageName) + "[>=~!]{1,2}[^\\s#]+",
                        packageName + "==" + fixedVersion);
                modified = true;
            }
        }
        return modified ? String.join("\n", lines) : null;
    }

    // ── private helpers ──────────────────────────────────────────────────────

    /**
     * Determines the target manifest filename based on the package name ecosystem,
     * then uses the GitHub Tree API to find its actual path inside the repo.
     * Falls back to common known paths if the Tree API doesn't help.
     */
    private String discoverManifestPath(String repoFullName, String packageName,
            String hintFilePath, String source, AuthProvider provider, String accessToken) {
        if (provider == AuthProvider.GITLAB) {
            return discoverManifestPathGitLab(repoFullName, packageName, hintFilePath, source, accessToken);
        }
        return discoverManifestPathGithub(repoFullName, packageName, hintFilePath, source, accessToken);
    }

    private String discoverManifestPathGithub(String repoFullName, String packageName,
            String hintFilePath, String source, String ghToken) {

        // Determine what manifest file we're looking for
        String targetFilename = inferManifestFilename(packageName, hintFilePath, source);
        log.info("[AutoFix] discoverManifest: repo={}, package={}, hint={}, source={}, target={}",
                repoFullName, packageName, hintFilePath, source, targetFilename);

        // When we derived package.json from a lock file, remember the preferred
        // directory
        // e.g. hint=Frontend/package-lock.json → prefer Frontend/package.json
        String preferredDir = null;
        if ("package.json".equals(targetFilename) && hintFilePath != null) {
            String clean = hintFilePath.startsWith("/") ? hintFilePath.substring(1) : hintFilePath;
            if (clean.contains("/")) {
                preferredDir = clean.substring(0, clean.lastIndexOf('/'));
            }
        }

        // Try to find the file via GitHub Tree API (searches whole repo)
        try {
            // First get the default branch
            String defaultBranch = getDefaultBranch(repoFullName, ghToken);
            String treeUrl = "https://api.github.com/repos/" + repoFullName
                    + "/git/trees/" + defaultBranch + "?recursive=1";
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + ghToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("X-GitHub-Api-Version", "2022-11-28");
            HttpEntity<Void> req = new HttpEntity<>(headers);
            ResponseEntity<Map> resp = restTemplate.exchange(treeUrl, HttpMethod.GET, req, Map.class);
            if (resp.getBody() != null) {
                Object treeObj = resp.getBody().get("tree");
                if (treeObj instanceof List<?> tree) {
                    // Collect all matching manifest files, prefer root-level ones
                    List<String> candidates = new ArrayList<>();
                    for (Object item : tree) {
                        if (item instanceof Map<?, ?> node) {
                            String itemPath = String.valueOf(node.get("path"));
                            String itemType = String.valueOf(node.get("type"));
                            if ("blob".equals(itemType) && itemPath.endsWith(targetFilename)) {
                                candidates.add(itemPath);
                            }
                        }
                    }
                    log.info("[AutoFix] Tree API found {} candidates for '{}': {}", candidates.size(), targetFilename,
                            candidates);
                    if (!candidates.isEmpty()) {
                        // If we have a preferred directory (derived from lock file hint), use it
                        if (preferredDir != null) {
                            final String pd = preferredDir;
                            String exact = candidates.stream()
                                    .filter(c -> c.equals(pd + "/" + targetFilename))
                                    .findFirst().orElse(null);
                            if (exact != null) {
                                log.info("[AutoFix] Preferred dir match: {}", exact);
                                return exact;
                            }
                        }
                        // Otherwise prefer root-level / shortest path
                        candidates.sort(Comparator.comparingInt(String::length));
                        return candidates.get(0);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("[AutoFix] Tree API failed for {}: {}", repoFullName, e.getMessage());
        }

        // Heuristic fallback: try common paths
        List<String> fallbacks = List.of(
                targetFilename, // root
                "Backend/" + targetFilename,
                "backend/" + targetFilename,
                "Frontend/" + targetFilename,
                "frontend/" + targetFilename,
                "app/" + targetFilename,
                "src/" + targetFilename);

        for (String candidate : fallbacks) {
            try {
                fetchFileFromGitHub(repoFullName, candidate, ghToken);
                return candidate; // found it
            } catch (Exception ignored) {
                // try next
            }
        }

        // Last resort: just return the root-level filename
        return targetFilename;
    }

    private String discoverManifestPathGitLab(String repoFullName, String packageName,
            String hintFilePath, String source, String accessToken) {
        String targetFilename = inferManifestFilename(packageName, hintFilePath, source);
        String preferredDir = null;
        if ("package.json".equals(targetFilename) && hintFilePath != null) {
            String clean = hintFilePath.startsWith("/") ? hintFilePath.substring(1) : hintFilePath;
            if (clean.contains("/")) {
                preferredDir = clean.substring(0, clean.lastIndexOf('/'));
            }
        }

        java.util.LinkedHashSet<String> candidates = new java.util.LinkedHashSet<>();
        if (preferredDir != null) {
            candidates.add(preferredDir + "/" + targetFilename);
        }
        candidates.add(targetFilename);
        candidates.add("Backend/" + targetFilename);
        candidates.add("backend/" + targetFilename);
        candidates.add("Frontend/" + targetFilename);
        candidates.add("frontend/" + targetFilename);
        candidates.add("app/" + targetFilename);
        candidates.add("src/" + targetFilename);

        String branch = gitLabService.getProjectDefaultBranch(repoFullName, accessToken);
        for (String candidate : candidates) {
            try {
                gitLabService.getFileContent(repoFullName, candidate, accessToken, branch);
                return candidate;
            } catch (Exception ignored) {
            }
        }

        return preferredDir != null ? preferredDir + "/" + targetFilename : targetFilename;
    }

    private String inferManifestFilename(String packageName, String hintFilePath, String source) {
        String inferredFromPackage = inferManifestFromPackage(packageName);
        String inferredFromSource = inferManifestFromSource(source);
        String inferredManifest = inferredFromPackage != null ? inferredFromPackage : inferredFromSource;

        if (hintFilePath != null && !hintFilePath.isBlank()) {
            String clean = hintFilePath.startsWith("/") ? hintFilePath.substring(1) : hintFilePath;
            String hintFile = clean.contains("/") ? clean.substring(clean.lastIndexOf('/') + 1) : clean;

            // Lock files → their corresponding manifest (CRITICAL FIX)
            if ("package-lock.json".equals(hintFile) || "yarn.lock".equals(hintFile)
                    || "pnpm-lock.yaml".equals(hintFile)) {
                return "package.json";
            }
            // Direct manifest file in hint
            if (isKnownManifest(hintFile)) {
                if (inferredManifest != null && !inferredManifest.equals(hintFile)) {
                    log.warn("[AutoFix] Ignoring conflicting manifest hint '{}' for package '{}' (using '{}')",
                            hintFile, packageName, inferredManifest);
                    return inferredManifest;
                }
                return hintFile;
            }
        }

        if (inferredManifest != null) {
            return inferredManifest;
        }

        return "pom.xml";
    }

    private String inferManifestFromPackage(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return null;
        }
        if (looksLikeJavaDependency(packageName)) {
            return "pom.xml";
        }
        if (looksLikePythonDependency(packageName)) {
            return "requirements.txt";
        }
        return "package.json";
    }

    private String inferManifestFromSource(String source) {
        if (source == null || source.isBlank()) {
            return null;
        }
        String lc = source.toLowerCase(Locale.ROOT);
        if (lc.contains("npm")) {
            return "package.json";
        }
        if (lc.contains("dependency-check") || lc.contains("maven")) {
            return "pom.xml";
        }
        if (lc.contains("pip") || lc.contains("python")) {
            return "requirements.txt";
        }
        return null;
    }

    private boolean isKnownManifest(String filename) {
        return filename.equals("pom.xml") || filename.equals("package.json")
                || filename.equals("requirements.txt") || filename.equals("build.gradle")
                || filename.equals("go.mod") || filename.equals("Cargo.toml");
    }

    private boolean looksLikeJavaDependency(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return false;
        }
        String lc = packageName.toLowerCase(Locale.ROOT);
        return lc.contains(":")
                || lc.startsWith("org.")
                || lc.startsWith("com.")
                || lc.startsWith("io.")
                || lc.startsWith("net.")
                || lc.contains("logback")
                || lc.contains("spring")
                || lc.contains("log4j")
                || lc.contains("apache")
                || lc.contains("jackson")
                || lc.contains("hibernate")
                || lc.contains("tomcat")
                || lc.contains("netty")
                || lc.contains("jetty");
    }

    private boolean looksLikePythonDependency(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return false;
        }
        String lc = packageName.toLowerCase(Locale.ROOT);
        return lc.endsWith(".py")
                || lc.contains("django")
                || lc.contains("flask")
                || lc.contains("requests")
                || lc.contains("jinja")
                || lc.contains("sqlalchemy");
    }

    private String normalizePackageName(String packageName) {
        if (packageName == null) {
            return "";
        }
        String normalized = packageName.trim();
        if (!normalized.startsWith("pkg:")) {
            return normalized;
        }

        String withoutPrefix = normalized.substring(4);
        int firstSlash = withoutPrefix.indexOf('/');
        if (firstSlash < 0 || firstSlash == withoutPrefix.length() - 1) {
            return normalized;
        }

        String ecosystem = withoutPrefix.substring(0, firstSlash);
        String remainder = withoutPrefix.substring(firstSlash + 1);
        int versionSep = remainder.lastIndexOf('@');
        if (versionSep > 0) {
            remainder = remainder.substring(0, versionSep);
        }
        remainder = remainder.replace("%40", "@").replace("%2F", "/").replace("%2f", "/");

        if ("maven".equals(ecosystem) && remainder.contains("/")) {
            int sep = remainder.indexOf('/');
            return remainder.substring(0, sep) + ":" + remainder.substring(sep + 1);
        }
        return remainder;
    }

    private String extractArtifactId(String packageName) {
        if (packageName == null || packageName.isBlank()) {
            return "";
        }
        return packageName.contains(":") ? packageName.split(":", 2)[1] : packageName;
    }

    private String extractGroupId(String packageName) {
        if (packageName == null || packageName.isBlank() || !packageName.contains(":")) {
            return null;
        }
        return packageName.split(":", 2)[0];
    }

    private String buildUnsupportedFixMessage(String packageName, String resolvedPath) {
        if ("pom.xml".equals(resolvedPath.contains("/")
                ? resolvedPath.substring(resolvedPath.lastIndexOf('/') + 1)
                : resolvedPath) && !looksLikeJavaDependency(packageName)) {
            return "Le package '" + packageName
                    + "' ressemble a une dependance npm/Node.js. Vulnix refuse de la corriger dans "
                    + resolvedPath + ". Corrigez package.json et package-lock.json.";
        }
        return "Aucun correctif automatique sur n'a pu etre genere pour '" + packageName
                + "' dans " + resolvedPath + ".";
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> fetchFileFromGitHub(String repoFullName, String filePath,
            String ghToken) {
        String url = "https://api.github.com/repos/" + repoFullName + "/contents/" + filePath;
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + ghToken);
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        HttpEntity<Void> request = new HttpEntity<>(headers);
        ResponseEntity<Map> response = restTemplate.exchange(url, HttpMethod.GET, request, Map.class);
        return (Map<String, Object>) response.getBody();
    }

    @SuppressWarnings("unchecked")
    private String getDefaultBranch(String repoFullName, String ghToken) {
        try {
            String url = "https://api.github.com/repos/" + repoFullName;
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + ghToken);
            headers.set("Accept", "application/vnd.github+json");
            headers.set("X-GitHub-Api-Version", "2022-11-28");
            HttpEntity<Void> req = new HttpEntity<>(headers);
            ResponseEntity<Map> resp = restTemplate.exchange(url, HttpMethod.GET, req, Map.class);
            Map<String, Object> body = (Map<String, Object>) resp.getBody();
            if (body != null && body.containsKey("default_branch")) {
                return String.valueOf(body.get("default_branch"));
            }
        } catch (Exception e) {
            log.warn("[AutoFix] Failed to get default branch for {}: {}", repoFullName, e.getMessage());
        }
        return "main"; // fallback
    }

    private RemoteFile fetchRemoteFile(String repoFullName, String filePath, AuthProvider provider,
            String accessToken) throws Exception {
        if (provider == AuthProvider.GITLAB) {
            String content = gitLabService.getFileContent(repoFullName, filePath, accessToken,
                    gitLabService.getProjectDefaultBranch(repoFullName, accessToken));
            return new RemoteFile(content, "");
        }

        Map<String, Object> githubFile = fetchFileFromGitHub(repoFullName, filePath, accessToken);
        String base64Content = (String) githubFile.get("content");
        byte[] decoded = Base64.getMimeDecoder().decode(base64Content.replace("\n", ""));
        return new RemoteFile(new String(decoded, StandardCharsets.UTF_8),
                githubFile.get("sha") != null ? String.valueOf(githubFile.get("sha")) : "");
    }

    private AuthProvider resolveProvider(String provider) {
        if (provider == null || provider.isBlank()) {
            return AuthProvider.GITHUB;
        }
        return AuthProvider.valueOf(provider.toUpperCase(Locale.ROOT));
    }

    private record RemoteFile(String content, String sha) {
    }

    private static final int MAX_RETRIES = 3;

    private String callGemini(String filePath, String packageName, String currentVersion,
            String fixedVersion, String cveId, String fileContent) throws Exception {

        // For Maven packages like "ch.qos.logback:logback-core", provide both
        // coordinates
        String artifactId = packageName.contains(":") ? packageName.split(":")[1] : packageName;
        String groupId = packageName.contains(":") ? packageName.split(":")[0] : null;

        String mavenNote = (groupId != null)
                ? String.format("Maven groupId: %s, artifactId: %s", groupId, artifactId)
                : "";

        String prompt = String.format(
                """
                        You are a security expert fixing a vulnerable dependency in a Maven pom.xml or npm/pip project file.

                        File: %s
                        CVE: %s
                        Package: %s%s
                        Vulnerable version: %s
                        Required fixed version: %s

                        STRICT RULES — follow every rule or the fix will be rejected:

                        RULE 1 — SEARCH FIRST:
                        Carefully read the entire file content below and search for any occurrence of
                        artifactId '%s' (or the package name '%s').

                        RULE 2 — IF FOUND EXPLICITLY in <dependencies> or <dependencyManagement>:
                        Update ONLY the <version> tag of that dependency from '%s' to '%s'.
                        Do not touch any other element.

                        RULE 3 — IF NOT FOUND EXPLICITLY (transitive / managed dependency):
                        For pom.xml files: add a <dependencyManagement> section if one does not exist,
                        or add an entry inside the existing <dependencyManagement><dependencies> block:
                        <dependency>
                            <groupId>%s</groupId>
                            <artifactId>%s</artifactId>
                            <version>%s</version>
                        </dependency>
                        Place this entry INSIDE <dependencyManagement><dependencies>…</dependencies></dependencyManagement>.
                        NEVER insert a dependency tag inside <build>, <plugins>, or <plugin> blocks.

                        RULE 4 — PRESERVE STRUCTURE ABSOLUTELY:
                        Do NOT reorder any XML elements.
                        Do NOT move any tags.
                        Do NOT add or remove any other tags.
                        Keep ALL existing indentation, whitespace, and comments exactly as-is.

                        RULE 5 — OUTPUT:
                        Return ONLY the corrected file content.
                        No explanations. No markdown code fences. No comments about changes made.

                        File content:
                        %s
                        """,
                filePath, cveId, packageName,
                mavenNote.isBlank() ? "" : "\n" + mavenNote,
                currentVersion, fixedVersion,
                artifactId, packageName,
                currentVersion, fixedVersion,
                groupId != null ? groupId : packageName, artifactId, fixedVersion,
                fileContent);

        Map<String, Object> textPart = Map.of("text", prompt);
        Map<String, Object> content = Map.of("parts", List.of(textPart));
        Map<String, Object> requestBody = Map.of("contents", List.of(content));

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        String url = geminiApiUrl + "?key=" + geminiApiKey;

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, headers);

        // Retry loop with backoff for rate-limited (429) responses
        for (int attempt = 1; attempt <= MAX_RETRIES; attempt++) {
            try {
                ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, request, String.class);
                JsonNode root = objectMapper.readTree(response.getBody());
                return root.path("candidates").get(0)
                        .path("content").path("parts").get(0)
                        .path("text").asText();
            } catch (org.springframework.web.client.HttpClientErrorException.TooManyRequests e) {
                long waitSeconds = parseRetryDelay(e.getResponseBodyAsString());
                if (attempt == MAX_RETRIES) {
                    log.error("[AutoFix] Gemini API quota exhausted after {} retries", MAX_RETRIES);
                    throw new RuntimeException(
                            "Quota Gemini API épuisée. Veuillez réessayer dans " + waitSeconds
                                    + " secondes ou vérifier votre plan sur https://ai.google.dev/gemini-api/docs/rate-limits");
                }
                log.warn("[AutoFix] Gemini 429 — attempt {}/{}, waiting {}s before retry…",
                        attempt, MAX_RETRIES, waitSeconds);
                Thread.sleep(waitSeconds * 1000);
            }
        }
        throw new RuntimeException("Gemini API call failed after retries");
    }

    /**
     * Extracts the retry delay (in seconds) from a Gemini 429 error body.
     * Falls back to 60s if parsing fails.
     */
    private long parseRetryDelay(String errorBody) {
        try {
            JsonNode root = objectMapper.readTree(errorBody);
            JsonNode details = root.path("error").path("details");
            for (JsonNode detail : details) {
                if (detail.has("retryDelay")) {
                    String delay = detail.path("retryDelay").asText(); // e.g. "56s"
                    return Long.parseLong(delay.replaceAll("[^0-9]", ""));
                }
            }
        } catch (Exception ignored) {
        }
        return 60; // default fallback
    }

    private String stripMarkdownFences(String content) {
        // Remove ```xml, ```json, ``` etc. fences that Gemini may add despite
        // instructions
        content = content.trim();
        if (content.startsWith("```")) {
            int firstNewline = content.indexOf('\n');
            if (firstNewline != -1)
                content = content.substring(firstNewline + 1);
        }
        if (content.endsWith("```")) {
            content = content.substring(0, content.lastIndexOf("```")).trim();
        }
        return content;
    }
}
