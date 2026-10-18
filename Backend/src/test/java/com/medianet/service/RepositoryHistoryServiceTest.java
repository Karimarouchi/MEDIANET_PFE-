package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.FindingKind;
import com.medianet.entity.SecretFinding;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RepositoryHistoryServiceTest {

    private static CveEntry dep(String cve, String pkg, String severity) {
        CveEntry e = new CveEntry();
        e.setCveId(cve);
        e.setPackageName(pkg);
        e.setSeverity(severity);
        e.setFindingKind(FindingKind.DEPENDENCY);
        return e;
    }

    @Test
    @SuppressWarnings("unchecked")
    void sameCveSeenByTwoToolsCountsOnceAndCodeAlertsAreApart() {
        CveEntry code = dep("java.lang.security.audit.x", "", "ERROR");
        code.setFindingKind(FindingKind.CODE_WEAKNESS);
        Map<String, Object> m = RepositoryHistoryService.countFindings(List.of(
                dep("CVE-2026-1", "postcss", "MEDIUM"),       // Grype
                dep("CVE-2026-1", "postcss:7.0", "HIGH"),     // Dependency-Check, same CVE, worst severity kept
                dep("CVE-2026-2", "org.springframework:spring-webmvc", "CRITICAL"),
                dep("CVE-2026-3", "svgo", "MODERATE"),
                code));
        assertThat(m.get("vulnerabilities")).isEqualTo(3);
        assertThat(m.get("codeAlerts")).isEqualTo(1);
        assertThat(m.get("rawRows")).isEqualTo(5);
        Map<String, Integer> sev = (Map<String, Integer>) m.get("bySeverity");
        assertThat(sev).containsEntry("CRITICAL", 1).containsEntry("HIGH", 1).containsEntry("MEDIUM", 1);
    }

    @Test
    void repoCardCountsAreUniqueAndKevOncePerVulnerability() {
        CveEntry grype = dep("CVE-2026-9", "lodash", "HIGH");
        grype.setKevListed(true);
        CveEntry trivy = dep("CVE-2026-9", "lodash", "CRITICAL"); // same vuln, other tool, worse label
        trivy.setKevListed(true);
        CveEntry code = dep("rule.x", "", "ERROR");
        code.setFindingKind(FindingKind.CODE_WEAKNESS);
        long[] c = RepositoryHistoryService.severeCounts(List.of(
                grype, trivy, dep("CVE-2026-8", "axios", "HIGH"), dep("CVE-2026-7", "qs", "LOW"), code));
        assertThat(c).containsExactly(1L, 1L, 1L);
    }

    private static SecretFinding secret(String ml, String scope, String analyst) {
        SecretFinding s = new SecretFinding();
        s.setMlVerdict(ml);
        s.setMlScope(scope);
        s.setAnalystVerdict(analyst);
        return s;
    }

    @Test
    void secretsUseTheSameGroupsAsTheCodeSecurityTab() {
        Map<String, Integer> m = RepositoryHistoryService.countSecrets(List.of(
                secret("LIKELY_REAL", "PRODUCTION", null),
                secret("LIKELY_REAL", "TEST_OR_DOC", null),
                secret("LIKELY_REAL", "PRODUCTION", "FALSE_POSITIVE"),
                secret("LIKELY_FALSE_POSITIVE", "PRODUCTION", "REAL"),
                secret("REVIEW", "PRODUCTION", null),
                secret("LIKELY_FALSE_POSITIVE", "PRODUCTION", null)));
        assertThat(m).containsEntry("total", 6).containsEntry("toHandle", 2).containsEntry("confirmed", 1)
                .containsEntry("testAndDocs", 1).containsEntry("toCheck", 1).containsEntry("falsePositives", 2);
    }
}
