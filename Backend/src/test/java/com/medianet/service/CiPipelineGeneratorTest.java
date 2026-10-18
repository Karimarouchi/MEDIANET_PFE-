package com.medianet.service;

import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CiPipelineGeneratorTest {

    private static final CiPipelineGenerator.VulnixTarget VULNIX =
            new CiPipelineGenerator.VulnixTarget("http://host.docker.internal:8080", 12);

    private static String res(String name) throws Exception {
        try (InputStream in = CiPipelineGeneratorTest.class.getResourceAsStream("/woodpecker/coussin/" + name)) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Map<String, Object>> steps(String yaml) {
        Map<String, Object> doc = new Yaml().load(yaml);
        Map<String, Map<String, Object>> byName = new HashMap<>();
        for (Map<String, Object> s : (List<Map<String, Object>>) doc.get("steps")) byName.put((String) s.get("name"), s);
        return byName;
    }

    /** Real tree of Karimarouchi/E-commerce-coussin: Spring Boot backend + npm workspace with two Vite apps. */
    @Test
    @SuppressWarnings("unchecked")
    void coussinGetsMavenNpmAndScanSteps() throws Exception {
        List<String> files = res("files.txt").lines().toList();
        Map<String, String> manifests = new HashMap<>();
        for (String m : CiPipelineGenerator.manifestsToRead(files)) manifests.put(m, res(m));
        assertThat(manifests).containsKeys("Backend/pom.xml", "Frontend/package.json");

        Map<String, Map<String, Object>> s = steps(CiPipelineGenerator.generate(files, manifests, VULNIX));

        assertThat(s).containsOnlyKeys("maven-backend", "npm-frontend", "vulnix-scan");
        assertThat(s.get("maven-backend")).containsEntry("image", "maven:3.9-eclipse-temurin-17")
                .containsEntry("directory", "Backend").containsEntry("commands", List.of("mvn -B -ntp verify"));
        // One npm step for the workspace root: members are built by its scripts, not twice.
        assertThat(s.get("npm-frontend")).containsEntry("directory", "Frontend");
        assertThat((List<String>) s.get("npm-frontend").get("commands")).containsExactly(
                "npm install --no-audit --no-fund", "npm run test --workspaces --if-present", "npm run lint", "npm run build");
        // Every step runs in parallel after the clone.
        s.values().forEach(step -> assertThat(step.get("depends_on")).isEqualTo(List.of()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void scanStepReadsTheTokenFromAWoodpeckerSecret() {
        Map<String, Object> scan = steps(CiPipelineGenerator.generate(List.of("README.md"), Map.of(), VULNIX)).get("vulnix-scan");
        Map<String, Object> env = (Map<String, Object>) scan.get("environment");
        assertThat(env.get("VULNIX_TOKEN")).isEqualTo(Map.of("from_secret", "vulnix_token"));
        assertThat(env).containsEntry("VULNIX_REPO_ID", "12").containsEntry("VULNIX_URL", "http://host.docker.internal:8080");
        assertThat(scan).doesNotContainKey("extra_hosts"); // refused by Woodpecker on untrusted repos
        String script = ((List<String>) scan.get("commands")).get(0);
        assertThat(script).contains("/api/ci/scans").contains("/api/ci/verdict").doesNotContain("$");
    }

    @Test
    void mavenModulesAndDependencyFoldersAreSkipped() {
        List<String> files = List.of("pom.xml", "core/pom.xml", "web/node_modules/x/package.json", "mvnw");
        Map<String, Map<String, Object>> s = steps(CiPipelineGenerator.generate(files,
                Map.of("pom.xml", "<properties><java.version>21</java.version></properties>"), VULNIX));
        assertThat(s).containsOnlyKeys("maven", "vulnix-scan");
        assertThat(s.get("maven")).containsEntry("image", "maven:3.9-eclipse-temurin-21")
                .containsEntry("commands", List.of("sh ./mvnw -B -ntp verify"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void lockfileMeansNpmCiAndOnlyExistingScriptsRun() {
        List<String> files = List.of("web/package.json", "web/package-lock.json");
        Map<String, Map<String, Object>> s = steps(CiPipelineGenerator.generate(files,
                Map.of("web/package.json", "{\"scripts\":{\"build\":\"vite build\"},\"engines\":{\"node\":\">=22\"}}"), VULNIX));
        assertThat(s.get("npm-web")).containsEntry("image", "node:22").containsEntry("environment", Map.of("CI", "true"));
        assertThat((List<String>) s.get("npm-web").get("commands")).containsExactly("npm ci --no-audit --no-fund", "npm run build");
    }

    @Test
    void dollarsAreEscapedForWoodpecker() {
        assertThat(CiPipelineGenerator.q("echo $HOME it's")).isEqualTo("'echo $$HOME it''s'");
    }

    @Test
    @SuppressWarnings("unchecked")
    void failingPipelineExplainsWhy() {
        Map<String, Object> step = steps(CiPipelineGenerator.failing("GitHub injoignable")).get("vulnix-config");
        assertThat((List<String>) step.get("commands")).containsExactly("echo \"Vulnix : GitHub injoignable\"", "exit 1");
    }
}
