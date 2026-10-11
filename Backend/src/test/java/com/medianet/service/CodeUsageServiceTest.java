package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CveEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CodeUsageServiceTest {

    private static final String USAGE = """
            {"filesScanned": 40,
             "npm": {"axios": {"files": ["src/api.js"], "prod": true, "count": 3},
                     "jest": {"files": ["test/a.test.js"], "prod": false, "count": 1}},
             "pypi": {"yaml": {"files": ["app/cfg.py"], "prod": true, "count": 1}, "flask": {"files": ["app/__init__.py"], "prod": true, "count": 2}},
             "java": {"org.springframework.web.bind": {"files": ["src/C.java"], "prod": true, "count": 1}},
             "go": {"github.com/gin-gonic/gin": {"files": ["main.go"], "prod": true, "count": 1}}}
            """;

    private static com.fasterxml.jackson.databind.JsonNode usage() throws Exception {
        return new ObjectMapper().readTree(USAGE);
    }

    @Test
    void importedByProductionCodeTestsOnlyOrNotAtAll() throws Exception {
        assertThat(CodeUsageService.usageOf(usage(), "npm", "axios", "DIRECT").status()).isEqualTo("YES");
        assertThat(CodeUsageService.usageOf(usage(), "npm", "axios", "DIRECT").files()).containsExactly("src/api.js");
        assertThat(CodeUsageService.usageOf(usage(), "npm", "jest", "DIRECT").status()).isEqualTo("TEST_ONLY");
        assertThat(CodeUsageService.usageOf(usage(), "npm", "lodash", "DIRECT").status()).isEqualTo("NOT_IMPORTED");
        assertThat(CodeUsageService.usageOf(usage(), "npm", "lodash", "UNKNOWN").status()).isEqualTo("NOT_IMPORTED");
    }

    @Test
    void aTransitiveDependencyIsNeverReportedAsUnused() throws Exception {
        assertThat(CodeUsageService.usageOf(usage(), "npm", "follow-redirects", "TRANSITIVE").status()).isEqualTo("UNKNOWN");
        // but if the project does import it directly, that is stated
        assertThat(CodeUsageService.usageOf(usage(), "npm", "axios", "TRANSITIVE").status()).isEqualTo("YES");
    }

    @Test
    void pypiNamesAreNormalisedAndAliased() throws Exception {
        assertThat(CodeUsageService.usageOf(usage(), "pypi", "PyYAML", "DIRECT").status()).isEqualTo("YES");
        assertThat(CodeUsageService.usageOf(usage(), "pypi", "Flask", "DIRECT").status()).isEqualTo("YES");
        assertThat(CodeUsageService.usageOf(usage(), "pypi", "requests", "DIRECT").status()).isEqualTo("NOT_IMPORTED");
    }

    @Test
    void mavenMatchesTheGroupIdAgainstImports_goMatchesTheModulePath() throws Exception {
        assertThat(CodeUsageService.usageOf(usage(), "maven", "org.springframework:spring-webmvc", "DIRECT").status()).isEqualTo("YES");
        assertThat(CodeUsageService.usageOf(usage(), "maven", "com.fasterxml.jackson.core:jackson-databind", "DIRECT").status())
                .isEqualTo("NOT_IMPORTED");
        assertThat(CodeUsageService.usageOf(usage(), "golang", "github.com/gin-gonic/gin", "DIRECT").status()).isEqualTo("YES");
    }

    @Test
    void unknownWhenNothingCanBeSaid() throws Exception {
        assertThat(CodeUsageService.usageOf(null, "npm", "axios", "DIRECT").status()).isEqualTo("UNKNOWN");
        assertThat(CodeUsageService.usageOf(usage(), "deb", "libc6", "UNKNOWN").status()).isEqualTo("UNKNOWN");
        assertThat(CodeUsageService.usageOf(usage(), null, "axios", "DIRECT").status()).isEqualTo("UNKNOWN");
    }

    @Test
    void applySetsTheEntriesAndToleratesAMissingOrBrokenFile(@TempDir Path dir) throws Exception {
        CveEntry c = CveEntry.builder().packageName("axios").ecosystem("npm").directOrTransitive("DIRECT").build();
        new CodeUsageService().apply(dir.toString(), List.of(c));          // no file
        assertThat(c.getCodeUsage()).isEqualTo("UNKNOWN");

        Files.writeString(dir.resolve("package-usage.json"), "not json");
        new CodeUsageService().apply(dir.toString(), List.of(c));
        assertThat(c.getCodeUsage()).isEqualTo("UNKNOWN");

        Files.writeString(dir.resolve("package-usage.json"), USAGE);
        new CodeUsageService().apply(dir.toString(), List.of(c));
        assertThat(c.getCodeUsage()).isEqualTo("YES");
        assertThat(c.getUsageFiles()).isEqualTo("[\"src/api.js\"]");
    }

    @Test
    void ecosystemIsInferredWhenTheSbomGaveNone() {
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().source("npm-audit").build())).isEqualTo("npm");
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().sources("grype,npm-audit").build())).isEqualTo("npm");
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().purl("pkg:pypi/django@4.2").build())).isEqualTo("pypi");
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().manifestFile("backend/pom.xml").build())).isEqualTo("maven");
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().ecosystem("golang").source("npm-audit").build())).isEqualTo("golang");
        assertThat(CodeUsageService.ecosystemOf(CveEntry.builder().source("trivy").build())).isNull();
    }

    @Test
    void anNpmAuditOnlyAdvisoryGetsAUsageVerdict(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("package-usage.json"), USAGE);
        CveEntry c = CveEntry.builder().packageName("axios").source("npm-audit").build();   // no ecosystem, no manifest
        new CodeUsageService().apply(dir.toString(), List.of(c));
        assertThat(c.getCodeUsage()).isEqualTo("YES");
    }
}
