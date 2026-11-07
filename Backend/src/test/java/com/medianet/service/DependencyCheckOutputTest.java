package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Real Dependency-Check output (run on the resolved Maven jars of a test project, with the NVD database stored outside
 * the image) next to the Grype and Trivy output of the same project.
 */
class DependencyCheckOutputTest {

    private static List<CveEntry> normalized;

    @BeforeAll
    static void load() throws Exception {
        String dir = new File(DependencyCheckOutputTest.class.getResource("/scanner-real-dc").toURI()).getPath();
        normalized = new VulnerabilityNormalizer(new AdvisoryAliasCache())
                .normalize(new ResultParserService().parseCves(dir));
    }

    private static boolean has(CveEntry e, String tool) {
        return e.getSources() != null && e.getSources().toUpperCase(Locale.ROOT).contains(tool);
    }

    @Test
    void log4shellIsReportedAndConfirmedByThreeTools() {
        CveEntry log4shell = normalized.stream()
                .filter(e -> "CVE-2021-44228".equals(e.getCveId()) && e.getPackageName() != null && e.getPackageName().endsWith("log4j-core"))
                .findFirst().orElseThrow();
        assertEquals(FindingKind.DEPENDENCY, log4shell.getFindingKind());
        assertTrue(has(log4shell, "DEPENDENCY-CHECK"));
        assertTrue(has(log4shell, "GRYPE"));
        assertTrue(has(log4shell, "TRIVY"));
        assertTrue(log4shell.getConfirmedBy() >= 3);
    }

    @Test
    void noDependencyFindingIsListedTwice() {
        List<CveEntry> deps = normalized.stream().filter(e -> e.getFindingKind() == FindingKind.DEPENDENCY).toList();
        long distinct = deps.stream().map(e -> e.getCveId() + "|" + e.getPackageName() + "|" + e.getPackageVersion())
                .distinct().count();
        assertEquals(distinct, deps.size());
    }

    @Test
    void dependencyCheckBringsFindingsOfItsOwn() {
        assertTrue(normalized.stream().anyMatch(e -> has(e, "DEPENDENCY-CHECK")));
        assertTrue(normalized.stream().filter(e -> has(e, "DEPENDENCY-CHECK")).count() >= 10);
    }
}
