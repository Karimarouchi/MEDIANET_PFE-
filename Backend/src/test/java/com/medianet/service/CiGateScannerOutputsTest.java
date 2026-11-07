package com.medianet.service;

import com.medianet.dto.CiVerdictDto;
import com.medianet.entity.ConfigFinding;
import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import com.medianet.repository.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

/**
 * The CI gate on real scanner outputs: dependency vulnerabilities, DAST alerts and misconfigurations are checked one by
 * one, to prove that misconfigurations never change a verdict and that the dependency rules are untouched.
 */
class CiGateScannerOutputsTest {

    private static List<CveEntry> all;
    private static List<ConfigFinding> configs;
    private static CiScanService gate;

    @BeforeAll
    static void load() throws Exception {
        String dir = new File(CiGateScannerOutputsTest.class.getResource("/scanner-real").toURI()).getPath();
        all = new VulnerabilityNormalizer(new AdvisoryAliasCache()).normalize(new ResultParserService().parseCves(dir));
        configs = new ConfigFindingParser().parse(dir);
        gate = new CiScanService(mock(ScanService.class), mock(ScanResultRepo.class), mock(RepositoryRepo.class),
                mock(ClientRepositoryRepo.class), mock(CveEntryRepo.class), mock(PolicyDeviationRequestRepo.class),
                mock(CveAuditService.class), mock(CiTokenService.class), mock(NotificationService.class), "https://x");
    }

    private static List<CveEntry> ofKind(FindingKind kind) {
        return all.stream().filter(e -> e.getFindingKind() == kind).toList();
    }

    private CiVerdictDto verdict(List<CveEntry> cves) {
        return gate.evaluate(null, 1L, "abc1234", cves);
    }

    @Test
    void dependencyVulnerabilitiesStillFailTheGate() {
        List<CveEntry> deps = ofKind(FindingKind.DEPENDENCY);
        assertTrue(deps.stream().anyMatch(e -> "HIGH".equals(e.getSeverity()) || "CRITICAL".equals(e.getSeverity())));
        CiVerdictDto v = verdict(deps);
        assertEquals("FAIL", v.verdict());
        assertEquals("BLOCKING_VULNS", v.reason());
        assertFalse(v.blocking().isEmpty());
    }

    @Test
    void aDastHighAlertBlocksExactlyLikeZapAlwaysDid() {
        List<CveEntry> dast = ofKind(FindingKind.DAST);
        assertEquals(4, dast.size());
        assertTrue(dast.stream().anyMatch(e -> "HIGH".equals(e.getSeverity())));
        CiVerdictDto v = verdict(dast);
        assertEquals("FAIL", v.verdict());
        assertTrue(v.blocking().stream().allMatch(f -> f.cveId().startsWith("NUCLEI-") || f.cveId().startsWith("CVE-")));
    }

    @Test
    void lowAndInfoDastAlertsDoNotBlock() {
        List<CveEntry> harmless = ofKind(FindingKind.DAST).stream()
                .filter(e -> !"HIGH".equals(e.getSeverity()) && !"CRITICAL".equals(e.getSeverity())).toList();
        assertFalse(harmless.isEmpty());
        assertEquals("PASS", verdict(harmless).verdict());
    }

    @Test
    void misconfigurationsAloneNeverFailTheGate() {
        assertFalse(configs.isEmpty());
        assertTrue(configs.stream().anyMatch(c -> "HIGH".equals(c.getSeverity())), "the repo has HIGH misconfigurations");
        // They are not CveEntry at all: the gate receives none of them.
        CiVerdictDto v = verdict(List.of());
        assertEquals("PASS", v.verdict());
        assertTrue(v.blocking().isEmpty());
    }

    @Test
    void theDefaultPolicyBlocksNoMisconfiguration() {
        assertTrue(new ConfigGatePolicy("", "").blocking(configs).isEmpty());
    }

    @Test
    void aConfiguredPolicyWouldBlockOnlyWhatItNames() {
        List<ConfigFinding> blocked = new ConfigGatePolicy("HIGH,CRITICAL", "KUBERNETES").blocking(configs);
        assertFalse(blocked.isEmpty());
        assertTrue(blocked.stream().allMatch(c -> "KUBERNETES".equals(c.getCategory())
                && ("HIGH".equals(c.getSeverity()) || "CRITICAL".equals(c.getSeverity()))));
    }

    @Test
    void theDependencyVerdictIsTheSameWithOrWithoutTheNewScanners() {
        // The dependency findings that block are those of Grype/Trivy/OSV/pip-audit; adding DAST entries to the list
        // must not remove or add a dependency to the blocking set.
        List<String> depsOnly = verdict(ofKind(FindingKind.DEPENDENCY)).blocking().stream().map(f -> f.cveId()).sorted().toList();
        List<String> everything = verdict(all).blocking().stream()
                .map(f -> f.cveId()).filter(id -> !id.startsWith("NUCLEI-")).sorted().toList();
        assertTrue(everything.containsAll(depsOnly));
    }
}
