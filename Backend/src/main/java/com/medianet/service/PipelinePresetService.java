package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.PipelinePresetDto;
import com.medianet.entity.AuthProvider;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

@Service
public class PipelinePresetService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final UserService userService;
    private final GitLabService gitLabService;

    public PipelinePresetService(UserService userService, GitLabService gitLabService) {
        this.userService = userService;
        this.gitLabService = gitLabService;
    }

    public PipelinePresetDto buildMonolithPreset(User currentUser, Repository repository) {
        String repoUrl = repository.getRepoUrl();
        AuthProvider provider = repository.getGitProvider() != null ? repository.getGitProvider() : detectProvider(repoUrl);
        String accessToken = userService.getAccessToken(currentUser, provider);
        String repoIdentifier = parseRepositoryIdentifier(repoUrl, provider);
        String branch = firstNonBlank(repository.getBranch(), resolveDefaultBranch(provider, repoIdentifier, accessToken), "main");
        RepoSnapshot snapshot = inspectRepository(provider, repoIdentifier, accessToken, branch);

        Component backend = detectBackend(snapshot);
        Component frontOffice = detectFrontOffice(snapshot);
        Component backOffice = detectBackOffice(snapshot);

        List<Component> components = new ArrayList<>();
        if (backend != null) components.add(backend);
        if (frontOffice != null) components.add(frontOffice);
        if (backOffice != null) components.add(backOffice);

        if (components.isEmpty()) {
            components.add(Component.node("Frontend", "frontoffice", PackageManager.NPM, true));
            components.add(Component.java("Backend", "backend", BuildTool.MAVEN, true));
        }

        String imagePrefix = resolveImagePrefix(snapshot, repoIdentifier, backend, frontOffice, backOffice);
        String dockerHubUsername = userService.getDockerHubUsername(currentUser);

        List<String> buildCommands = new ArrayList<>();
        List<String> testCommands = new ArrayList<>();
        List<String> dockerCommands = new ArrayList<>();
        List<String> containerScanCommands = new ArrayList<>();
        List<String> detectedComponents = new ArrayList<>();

        for (Component component : components.stream().sorted(Comparator.comparingInt(Component::order)).toList()) {
            buildCommands.add(component.buildCommand());
            testCommands.add(component.testCommand());
            String imageRef = qualifyImage(component.imageName(imagePrefix), dockerHubUsername);
            dockerCommands.add("docker build -t " + imageRef + " " + component.dockerContext());
            containerScanCommands.add("trivy image " + imageRef);
            detectedComponents.add(component.displayName());
        }

        String workspacePath = "/opt/apps/" + slugify(imagePrefix);
        String summary = "Preset monolithique e-commerce détecté: " + String.join(", ", detectedComponents)
                + ". Les commandes build/test/docker sont préremplies et prêtes à être affinées.";

        return new PipelinePresetDto(
                imagePrefix + "-monolith",
                "Pipeline DevSecOps monolithique conteneurisé pour " + imagePrefix + ".",
                repoUrl,
                branch,
                workspacePath,
                String.join("\n", buildCommands),
                String.join("\n", testCommands),
                String.join("\n", dockerCommands),
                String.join("\n", containerScanCommands),
                "docker compose pull\ndocker compose up -d",
                "docker run --rm ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com",
                "docker compose pull\ndocker compose up -d",
                true,
                true,
                true,
                true,
                imagePrefix,
                dockerHubUsername,
                detectedComponents,
                summary);
    }

    private RepoSnapshot inspectRepository(AuthProvider provider, String repoIdentifier, String accessToken, String branch) {
        try {
            List<RemoteEntry> rootEntries = listDirectory(provider, repoIdentifier, accessToken, branch, null);
            return new RepoSnapshot(provider, repoIdentifier, branch, rootEntries, accessToken);
        } catch (Exception ignored) {
            return new RepoSnapshot(provider, repoIdentifier, branch, List.of(), accessToken);
        }
    }

    private Component detectBackend(RepoSnapshot snapshot) {
        String rootDir = findDirectory(snapshot.rootEntries(), List.of("backend", "api", "server", "services"));
        List<RemoteEntry> entries = rootDir != null ? listSafe(snapshot, rootDir) : snapshot.rootEntries();
        if (containsFile(entries, "pom.xml") || containsFile(snapshot.rootEntries(), "pom.xml")) {
            boolean wrapper = containsFile(entries, "mvnw") || containsFile(snapshot.rootEntries(), "mvnw");
            return Component.java(rootDir, "backend", wrapper ? BuildTool.MAVEN_WRAPPER : BuildTool.MAVEN,
                    rootDir == null);
        }
        if (containsFile(entries, "build.gradle") || containsFile(entries, "build.gradle.kts")) {
            boolean wrapper = containsFile(entries, "gradlew") || containsFile(snapshot.rootEntries(), "gradlew");
            return Component.java(rootDir, "backend", wrapper ? BuildTool.GRADLE_WRAPPER : BuildTool.GRADLE,
                    rootDir == null);
        }
        return rootDir != null ? Component.java(rootDir, "backend", BuildTool.MAVEN, false) : null;
    }

    private Component detectFrontOffice(RepoSnapshot snapshot) {
        String dir = findDirectory(snapshot.rootEntries(), List.of("frontoffice", "front-office", "frontend", "front-end", "web", "client", "shop"));
        List<RemoteEntry> entries = dir != null ? listSafe(snapshot, dir) : snapshot.rootEntries();
        if (containsFile(entries, "package.json") || containsFile(snapshot.rootEntries(), "package.json")) {
            return Component.node(dir, dir != null && dir.toLowerCase(Locale.ROOT).contains("front") ? "frontoffice" : "frontend",
                    detectPackageManager(entries.isEmpty() ? snapshot.rootEntries() : entries), dir == null);
        }
        return dir != null ? Component.node(dir, "frontoffice", PackageManager.NPM, false) : null;
    }

    private Component detectBackOffice(RepoSnapshot snapshot) {
        String dir = findDirectory(snapshot.rootEntries(), List.of("backoffice", "back-office", "admin", "dashboard", "bo"));
        if (dir == null) {
            return null;
        }
        List<RemoteEntry> entries = listSafe(snapshot, dir);
        return Component.node(dir, "backoffice", detectPackageManager(entries), false);
    }

    private String resolveImagePrefix(RepoSnapshot snapshot, String repoIdentifier, Component backend, Component frontOffice,
            Component backOffice) {
        String fromBackend = backend != null ? resolveSpringApplicationName(snapshot, backend.path()) : null;
        if (fromBackend != null) {
            return slugify(fromBackend);
        }
        String fromFront = frontOffice != null ? resolvePackageName(snapshot, frontOffice.path()) : null;
        if (fromFront != null) {
            return slugify(fromFront);
        }
        String fromBackOffice = backOffice != null ? resolvePackageName(snapshot, backOffice.path()) : null;
        if (fromBackOffice != null) {
            return slugify(fromBackOffice);
        }
        return slugify(repoIdentifier.substring(repoIdentifier.lastIndexOf('/') + 1));
    }

    private String resolveSpringApplicationName(RepoSnapshot snapshot, String path) {
        String base = path == null || path.isBlank() ? "" : path + "/";
        String[] candidates = new String[] {
                base + "src/main/resources/application.properties",
                base + "src/main/resources/application.yml",
                base + "src/main/resources/application.yaml"
        };
        for (String candidate : candidates) {
            String content = fetchFileSafe(snapshot, candidate);
            if (content == null) {
                continue;
            }
            for (String line : content.split("\\R")) {
                String trimmed = line.trim();
                if (trimmed.startsWith("spring.application.name=")) {
                    return trimmed.substring("spring.application.name=".length()).trim();
                }
                if (trimmed.startsWith("name:")) {
                    return trimmed.substring("name:".length()).trim();
                }
            }
        }
        return null;
    }

    private String resolvePackageName(RepoSnapshot snapshot, String path) {
        String candidate = (path == null || path.isBlank() ? "" : path + "/") + "package.json";
        String content = fetchFileSafe(snapshot, candidate);
        if (content == null) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(content);
            String name = root.path("name").asText(null);
            return name != null && !name.isBlank() ? name : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String fetchFileSafe(RepoSnapshot snapshot, String filePath) {
        try {
            return fetchFile(snapshot.provider(), snapshot.repoIdentifier(), snapshot.accessToken(), snapshot.branch(), filePath);
        } catch (Exception ignored) {
            return null;
        }
    }

    private List<RemoteEntry> listSafe(RepoSnapshot snapshot, String path) {
        try {
            return listDirectory(snapshot.provider(), snapshot.repoIdentifier(), snapshot.accessToken(), snapshot.branch(), path);
        } catch (Exception ignored) {
            return List.of();
        }
    }

    private List<RemoteEntry> listDirectory(AuthProvider provider, String repoIdentifier, String accessToken, String branch, String path)
            throws Exception {
        if (provider == AuthProvider.GITLAB) {
            return gitLabService.listRepositoryTree(repoIdentifier, accessToken, path, branch).stream()
                    .map(entry -> new RemoteEntry(
                            String.valueOf(entry.getOrDefault("name", "")),
                            String.valueOf(entry.getOrDefault("path", "")),
                            String.valueOf(entry.getOrDefault("type", ""))))
                    .toList();
        }

        String url = "https://api.github.com/repos/" + repoIdentifier + "/contents";
        if (path != null && !path.isBlank()) {
            url += "/" + path;
        }
        url += "?ref=" + URLEncoder.encode(branch, StandardCharsets.UTF_8);
        HttpHeaders headers = githubHeaders(accessToken);
        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                });
        List<Map<String, Object>> body = response.getBody();
        if (body == null) {
            return List.of();
        }
        return body.stream()
                .map(entry -> new RemoteEntry(
                        String.valueOf(entry.getOrDefault("name", "")),
                        String.valueOf(entry.getOrDefault("path", "")),
                        String.valueOf(entry.getOrDefault("type", ""))))
                .toList();
    }

    private String fetchFile(AuthProvider provider, String repoIdentifier, String accessToken, String branch, String filePath)
            throws Exception {
        if (provider == AuthProvider.GITLAB) {
            return gitLabService.getFileContent(repoIdentifier, filePath, accessToken, branch);
        }
        String url = "https://api.github.com/repos/" + repoIdentifier + "/contents/" + filePath + "?ref="
                + URLEncoder.encode(branch, StandardCharsets.UTF_8);
        HttpHeaders headers = githubHeaders(accessToken);
        ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                new ParameterizedTypeReference<>() {
                });
        String encoded = String.valueOf(Objects.requireNonNullElse(response.getBody().get("content"), ""));
        return new String(java.util.Base64.getMimeDecoder().decode(encoded.replace("\n", "")), StandardCharsets.UTF_8);
    }

    private String resolveDefaultBranch(AuthProvider provider, String repoIdentifier, String accessToken) {
        if (provider == AuthProvider.GITLAB) {
            return gitLabService.getProjectDefaultBranch(repoIdentifier, accessToken);
        }
        try {
            String url = "https://api.github.com/repos/" + repoIdentifier;
            HttpHeaders headers = githubHeaders(accessToken);
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    new ParameterizedTypeReference<>() {
                    });
            Object branch = response.getBody() != null ? response.getBody().get("default_branch") : null;
            return branch != null ? String.valueOf(branch) : "main";
        } catch (Exception ignored) {
            return "main";
        }
    }

    private HttpHeaders githubHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        if (accessToken != null && !accessToken.isBlank()) {
            headers.setBearerAuth(accessToken);
        }
        headers.set("Accept", "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        return headers;
    }

    private String parseRepositoryIdentifier(String repoUrl, AuthProvider provider) {
        String normalized = repoUrl.replace(".git", "").replaceFirst("^https?://", "");
        int slashIndex = normalized.indexOf('/');
        String path = slashIndex >= 0 ? normalized.substring(slashIndex + 1) : normalized;
        if (provider == AuthProvider.GITHUB) {
            String[] parts = path.split("/");
            if (parts.length >= 2) {
                return parts[0] + "/" + parts[1];
            }
        }
        return path;
    }

    private AuthProvider detectProvider(String repoUrl) {
        return repoUrl != null && repoUrl.toLowerCase(Locale.ROOT).contains("gitlab")
                ? AuthProvider.GITLAB
                : AuthProvider.GITHUB;
    }

    private String findDirectory(List<RemoteEntry> entries, List<String> candidates) {
        Set<String> candidateSet = new HashSet<>(candidates);
        return entries.stream()
                .filter(entry -> "dir".equalsIgnoreCase(entry.type()) || "tree".equalsIgnoreCase(entry.type()))
                .map(RemoteEntry::path)
                .filter(Objects::nonNull)
                .filter(path -> candidateSet.contains(path.substring(path.lastIndexOf('/') + 1).toLowerCase(Locale.ROOT)))
                .findFirst()
                .orElse(null);
    }

    private boolean containsFile(List<RemoteEntry> entries, String fileName) {
        return entries.stream().anyMatch(entry -> fileName.equalsIgnoreCase(entry.name()));
    }

    private PackageManager detectPackageManager(List<RemoteEntry> entries) {
        if (containsFile(entries, "pnpm-lock.yaml")) {
            return PackageManager.PNPM;
        }
        if (containsFile(entries, "yarn.lock")) {
            return PackageManager.YARN;
        }
        return PackageManager.NPM;
    }

    private String qualifyImage(String imageName, String username) {
        if (username == null || username.isBlank()) {
            return imageName + ":latest";
        }
        return username.trim() + "/" + imageName + ":latest";
    }

    private String slugify(String value) {
        String normalized = Optional.ofNullable(value).orElse("app")
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
        return normalized.isBlank() ? "app" : normalized;
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private record RepoSnapshot(
            AuthProvider provider,
            String repoIdentifier,
            String branch,
            List<RemoteEntry> rootEntries,
            String accessToken) {
    }

    private record RemoteEntry(String name, String path, String type) {
    }

    private enum BuildTool {
        MAVEN,
        MAVEN_WRAPPER,
        GRADLE,
        GRADLE_WRAPPER
    }

    private enum PackageManager {
        NPM,
        YARN,
        PNPM
    }

    private record Component(String path, String componentSlug, String displayName, int order, String buildCommand,
            String testCommand, String dockerContext) {
        static Component java(String path, String componentSlug, BuildTool tool, boolean root) {
            String safePath = path == null ? "" : path;
            String prefix = root || safePath.isBlank() ? "" : "cd " + safePath + " && ";
            String build = switch (tool) {
                case MAVEN_WRAPPER -> prefix + "./mvnw clean package -DskipTests";
                case GRADLE -> prefix + "gradle build -x test";
                case GRADLE_WRAPPER -> prefix + "./gradlew build -x test";
                default -> prefix + "mvn clean package -DskipTests";
            };
            String test = switch (tool) {
                case MAVEN_WRAPPER -> prefix + "./mvnw test";
                case GRADLE -> prefix + "gradle test";
                case GRADLE_WRAPPER -> prefix + "./gradlew test";
                default -> prefix + "mvn test";
            };
            return new Component(safePath, componentSlug, "Backend", 1, build, test,
                    root || safePath.isBlank() ? "." : safePath);
        }

        static Component node(String path, String componentSlug, PackageManager manager, boolean root) {
            String safePath = path == null ? "" : path;
            String prefix = root || safePath.isBlank() ? "" : "cd " + safePath + " && ";
            String install = switch (manager) {
                case YARN -> "yarn install --frozen-lockfile";
                case PNPM -> "pnpm install --frozen-lockfile";
                default -> "npm install";
            };
            String build = switch (manager) {
                case YARN -> prefix + install + " && yarn build";
                case PNPM -> prefix + install + " && pnpm build";
                default -> prefix + install + " && npm run build";
            };
            String test = switch (manager) {
                case YARN -> prefix + "yarn test --watch=false";
                case PNPM -> prefix + "pnpm test -- --watch=false";
                default -> prefix + "npm test -- --watch=false";
            };
            String displayName = componentSlug.toLowerCase(Locale.ROOT).contains("back") ? "Back office"
                    : componentSlug.toLowerCase(Locale.ROOT).contains("front") ? "Front office"
                    : "Frontend";
            int order = componentSlug.toLowerCase(Locale.ROOT).contains("back") ? 3 : 2;
            return new Component(safePath, componentSlug, displayName, order, build, test,
                    root || safePath.isBlank() ? "." : safePath);
        }

        String imageName(String prefix) {
            return prefix + "-" + componentSlug;
        }
    }
}