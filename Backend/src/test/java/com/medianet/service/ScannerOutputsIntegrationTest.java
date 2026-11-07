package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/** pip-audit and Nuclei, on real outputs, through the parser and the normalizer used by the scan import. */
class ScannerOutputsIntegrationTest {

    private static List<CveEntry> normalized;

    @BeforeAll
    static void parseRealOutputs() throws Exception {
        File dir = new File(ScannerOutputsIntegrationTest.class.getResource("/scanner-real").toURI());
        List<CveEntry> parsed = new ResultParserService().parseCves(dir.getPath());
        normalized = new VulnerabilityNormalizer(new AdvisoryAliasCache()).normalize(parsed);
    }

    private static List<CveEntry> bySource(String tool) {
        return normalized.stream()
                .filter(e -> e.getSources() != null && e.getSources().toUpperCase(Locale.ROOT).contains(tool))
                .toList();
    }

    @Test
    void pipAuditFindingsAreDependencies() {
        List<CveEntry> pip = bySource("PIP-AUDIT");
        assertFalse(pip.isEmpty());
        assertTrue(pip.stream().allMatch(e -> e.getFindingKind() == FindingKind.DEPENDENCY));
        assertTrue(pip.stream().allMatch(e -> "pypi".equals(e.getEcosystem())));
        assertTrue(pip.stream().allMatch(e -> e.getPurl() != null && e.getPurl().startsWith("pkg:pypi/")));
    }

    @Test
    void pipAuditAndGrypeConfirmTheSameFindingInsteadOfListingItTwice() {
        List<CveEntry> both = normalized.stream()
                .filter(e -> e.getSources() != null && e.getSources().contains("PIP-AUDIT") && e.getSources().contains("GRYPE"))
                .toList();
        assertFalse(both.isEmpty(), "at least one finding must be confirmed by both tools");
        assertTrue(both.stream().allMatch(e -> e.getConfirmedBy() >= 2));
        List<CveEntry> deps = normalized.stream().filter(e -> e.getFindingKind() == FindingKind.DEPENDENCY).toList();
        long distinct = deps.stream()
                .map(e -> e.getCveId() + "|" + e.getPackageName() + "|" + e.getPackageVersion())
                .distinct().count();
        assertEquals(distinct, deps.size(), "no duplicated dependency finding after normalization");
    }

    @Test
    void pipAuditAdvisoryIdBecomesAnAliasOfTheCve() {
        CveEntry jinja = normalized.stream()
                .filter(e -> "CVE-2020-28493".equals(e.getCveId()) && "jinja2".equalsIgnoreCase(e.getPackageName()))
                .findFirst().orElseThrow();
        assertTrue(jinja.getAliases().contains("PYSEC-2021-66"));
        assertEquals("2.11.3", jinja.getFixedVersion());
    }

    @Test
    void nucleiFindingsAreDastNeverDependencies() {
        List<CveEntry> nuclei = bySource("NUCLEI");
        assertEquals(4, nuclei.size());
        for (CveEntry e : nuclei) {
            assertEquals(FindingKind.DAST, e.getFindingKind(), e.getCveId());
            assertTrue(e.getCveId().startsWith("NUCLEI-") || e.getCveId().startsWith("CVE-"));
            assertTrue(e.getFilePath().startsWith("http"), "the matched URL is the location");
            assertNull(e.getPurl());
            assertNull(e.getPackageVersion());
        }
    }

    @Test
    void nucleiKeepsTemplateSeverityAndCwe() {
        CveEntry env = bySource("NUCLEI").stream()
                .filter(e -> "NUCLEI-codeigniter-env".equals(e.getCveId())).findFirst().orElseThrow();
        assertEquals("HIGH", env.getSeverity());
        assertEquals("CWE-552", env.getCweId());
        assertEquals("Codeigniter - .env File Discovery", env.getPackageName());
    }

    @Test
    void dastEntriesNeverMergeWithDependencyEntries() {
        assertTrue(normalized.stream().filter(e -> e.getFindingKind() == FindingKind.DAST)
                .noneMatch(e -> e.getSources().contains("GRYPE") || e.getSources().contains("TRIVY")));
    }

    @Test
    void nucleiLinesThatAreNotJsonAreSkipped(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("nuclei.jsonl"), """
                [INF] banner line
                {"template-id":"x-exposed","info":{"name":"X","severity":"medium"},"matched-at":"http://t/x"}

                {"broken":
                """);
        List<CveEntry> parsed = new ResultParserService().parseCves(dir.toString());
        assertEquals(1, parsed.size());
        assertEquals("MEDIUM", parsed.get(0).getSeverity());
    }

    @Test
    void pipAuditWithoutVulnerabilitiesGivesNothing(@TempDir Path dir) throws Exception {
        Files.writeString(dir.resolve("pip-audit.json"),
                "{\"dependencies\":[{\"name\":\"six\",\"version\":\"1.16.0\",\"vulns\":[]},{\"name\":\"local\",\"skip_reason\":\"not on PyPI\"}],\"fixes\":[]}");
        assertTrue(new ResultParserService().parseCves(dir.toString()).isEmpty());
    }
}
