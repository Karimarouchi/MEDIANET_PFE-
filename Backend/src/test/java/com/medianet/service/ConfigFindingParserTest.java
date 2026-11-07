package com.medianet.service;

import com.medianet.entity.ConfigFinding;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

/** Runs on the real outputs of Trivy, Checkov and Hadolint captured from the scanner image on a vulnerable repo. */
class ConfigFindingParserTest {

    private static final ConfigFindingParser PARSER = new ConfigFindingParser();
    private static List<ConfigFinding> findings;

    @BeforeAll
    static void parseRealOutputs() throws Exception {
        File dir = new File(ConfigFindingParserTest.class.getResource("/scanner-real").toURI());
        findings = PARSER.parse(dir.getPath());
    }

    private static ConfigFinding byRule(String ruleId) {
        List<ConfigFinding> hits = findings.stream()
                .filter(f -> f.getRuleIds() != null && List.of(f.getRuleIds().split(",")).contains(ruleId))
                .toList();
        assertEquals(1, hits.size(), "rule " + ruleId + " must appear exactly once");
        return hits.get(0);
    }

    @Test
    void everyFindingHasARuleACategoryAndASeverity() {
        assertFalse(findings.isEmpty());
        for (ConfigFinding f : findings) {
            assertNotNull(f.getRuleId());
            assertNotNull(f.getTitle());
            assertNotNull(f.getCategory());
            assertNotEquals("OTHER", f.getCategory(), f.getRuleId());
            assertNotNull(f.getSeverity());
            assertFalse(f.getSources().isBlank());
        }
    }

    @Test
    void rootUserReportedByTrivyAndCheckovIsOneFinding() {
        ConfigFinding f = byRule("DS-0002");
        assertEquals("DS-0002,CKV_DOCKER_3", f.getRuleIds());
        assertEquals("trivy,checkov", f.getSources());
        assertEquals("HIGH", f.getSeverity());
        assertEquals("DOCKERFILE", f.getCategory());
        assertEquals("Dockerfile", f.getFile());
    }

    @Test
    void healthcheckIsMergedToo() {
        ConfigFinding f = byRule("DS-0026");
        assertEquals("trivy,checkov", f.getSources());
        assertEquals("LOW", f.getSeverity());
    }

    @Test
    void noInstallRecommendsMergesTrivyAndHadolintOnTheSameLine() {
        ConfigFinding f = byRule("DS-0029");
        assertEquals("trivy,hadolint", f.getSources());
        assertEquals(2, f.getStartLine());
        assertEquals("DS-0029,DL3015", f.getRuleIds());
    }

    @Test
    void hadolintLevelsAreKeptWithTheirOwnSeverity() {
        assertEquals("LOW", byRule("DL3008").getSeverity());
        assertEquals("LOW", byRule("DL3042").getSeverity());
        assertEquals("INFO", byRule("DL3009").getSeverity());
    }

    @Test
    void checkovWithoutSeverityStaysUnknownNotMedium() {
        ConfigFinding f = byRule("CKV_K8S_38");
        assertEquals("checkov", f.getSources());
        assertEquals("UNKNOWN", f.getSeverity());
        assertEquals("KUBERNETES", f.getCategory());
        assertEquals("k8s/deployment.yaml", f.getFile());
    }

    @Test
    void kubernetesPrivilegedIsMergedAcrossTools() {
        ConfigFinding f = byRule("KSV-0017");
        assertEquals("trivy,checkov", f.getSources());
        assertTrue(f.getRuleIds().contains("CKV_K8S_16"));
        assertEquals("HIGH", f.getSeverity());
    }

    @Test
    void terraformFromBothToolsIsKept() {
        assertTrue(findings.stream().anyMatch(f -> "TERRAFORM".equals(f.getCategory()) && f.getSources().contains("checkov")));
        assertTrue(findings.stream().anyMatch(f -> "TERRAFORM".equals(f.getCategory()) && f.getSources().contains("trivy")));
    }

    @Test
    void noRuleIsListedTwiceForTheSameFileLineAndResource() {
        Set<String> seen = new HashSet<>();
        for (ConfigFinding f : findings) {
            String key = f.getRuleId() + "|" + f.getFile() + "|" + f.getStartLine() + "|" + f.getResource();
            assertTrue(seen.add(key), "duplicate " + key);
        }
    }

    @Test
    void theThreeDockerfilePairsAreMerged() {
        long merged = findings.stream().filter(f -> f.getSources().contains(",")).count();
        assertTrue(merged >= 3, "merged findings: " + merged);
    }

    @Test
    void onlyTrivyJsonIsReadSoTheOtherTrivyFilesDoNotDuplicate(@TempDir Path dir) throws Exception {
        Path real = Path.of(getClass().getResource("/scanner-real/trivy.json").toURI());
        Files.copy(real, dir.resolve("trivy.json"));
        List<ConfigFinding> once = PARSER.parse(dir.toString());
        Files.copy(real, dir.resolve("trivy-iac.json"));
        Files.copy(real, dir.resolve("trivy-docker-misconfig.json"));
        assertEquals(once.size(), PARSER.parse(dir.toString()).size());
    }

    @Test
    void missingOrBrokenFilesGiveNothing(@TempDir Path dir) throws Exception {
        assertTrue(PARSER.parse(dir.toString()).isEmpty());
        Files.writeString(dir.resolve("checkov.json"), "");
        Files.writeString(dir.resolve("hadolint-1.json"), "not json");
        assertTrue(PARSER.parse(dir.toString()).isEmpty());
        assertTrue(PARSER.parse(null).isEmpty());
    }

    @Test
    void checkovSecretsFrameworkIsIgnored(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("checkov.json"), """
                [{"check_type":"secrets","results":{"failed_checks":[
                  {"check_id":"CKV_SECRET_6","check_name":"Base64 High Entropy String","file_path":"/a.env","file_line_range":[1,1],"severity":null}
                ]}}]
                """);
        assertTrue(PARSER.parse(dir.toString()).isEmpty());
    }

    @Test
    void trivyPassedChecksAreNotFindings(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("trivy.json"), """
                {"Results":[{"Target":"Dockerfile","Type":"dockerfile","Misconfigurations":[
                  {"ID":"DS-0001","Title":"ok","Severity":"LOW","Status":"PASS"},
                  {"ID":"DS-0002","Title":"bad","Severity":"HIGH","Status":"FAIL"}]}]}
                """);
        List<ConfigFinding> list = PARSER.parse(dir.toString());
        assertEquals(1, list.size());
        assertEquals("DS-0002", list.get(0).getRuleId());
    }

    @Test
    void sameRuleOnDifferentFilesIsNotMerged(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("trivy.json"), """
                {"Results":[{"Target":"a/Dockerfile","Type":"dockerfile","Misconfigurations":[
                  {"ID":"DS-0002","Title":"root","Severity":"HIGH","Status":"FAIL"}]}]}
                """);
        Files.writeString(dir.resolve("checkov.json"), """
                [{"check_type":"dockerfile","results":{"failed_checks":[
                  {"check_id":"CKV_DOCKER_3","check_name":"user","file_path":"/b/Dockerfile","file_line_range":[1,3],"severity":null}]}}]
                """);
        assertEquals(2, PARSER.parse(dir.toString()).size());
    }

    @Test
    void checkovSeverityIsUsedWhenTheToolGivesOne(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("checkov.json"), """
                [{"check_type":"terraform","results":{"failed_checks":[
                  {"check_id":"CKV_AWS_1","check_name":"x","file_path":"/m.tf","file_line_range":[1,2],"severity":"HIGH"}]}}]
                """);
        assertEquals("HIGH", PARSER.parse(dir.toString()).get(0).getSeverity());
    }
}
