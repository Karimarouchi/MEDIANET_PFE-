package com.medianet.service;

import com.medianet.entity.CveEntry;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.Comparator;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ReleaseReadinessServiceTest {

    @Test
    void noDeadlineMeansNoVerdict() {
        assertThat(ReleaseReadinessService.delayRisk(null, 5, 1)).isNull();
    }

    @Test
    void aPassedDeadlineIsAlwaysHighRisk() {
        assertThat(ReleaseReadinessService.delayRisk(-1, 0, 0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.delayRisk(-30, 9, 2)).isEqualTo("ELEVE");
    }

    @Test
    void noBlockerMeansLowRisk() {
        assertThat(ReleaseReadinessService.delayRisk(3, 0, 0)).isEqualTo("FAIBLE");
        assertThat(ReleaseReadinessService.delayRisk(90, 0, 0)).isEqualTo("FAIBLE");
    }

    @Test
    void openBlockersNeverLeaveALowRisk() {
        assertThat(ReleaseReadinessService.delayRisk(31, 87, 0)).isEqualTo("MOYEN");
        assertThat(ReleaseReadinessService.delayRisk(8, 1, 0)).isEqualTo("MOYEN");
        assertThat(ReleaseReadinessService.delayRisk(7, 1, 0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.delayRisk(14, 3, 1)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.delayRisk(15, 3, 1)).isEqualTo("MOYEN");
    }

    @Test
    void daysRemainingCountsCalendarDays() {
        assertThat(ReleaseReadinessService.daysRemaining(LocalDate.now().plusDays(10))).isEqualTo(10);
        assertThat(ReleaseReadinessService.daysRemaining(LocalDate.now().minusDays(2))).isEqualTo(-2);
        assertThat(ReleaseReadinessService.daysRemaining(null)).isNull();
    }

    @Test
    void thereIsNoDayEstimateAnywhereInTheAnswer() throws Exception {
        // the removed model's fields must not come back by accident
        var fields = List.of(ReleaseReadinessService.FindingAgg.class.getDeclaredFields()).stream().map(f -> f.getName()).toList();
        assertThat(fields).noneMatch(n -> n.toLowerCase().contains("estimated") || n.toLowerCase().contains("remaining")
                || n.toLowerCase().contains("band") || n.toLowerCase().contains("sla"));
    }

    private static CveEntry entry(String id, String pkg, String severity, boolean kev, Double cvss) {
        return CveEntry.builder().cveId(id).packageName(pkg).severity(severity).kevListed(kev).cvssScore(cvss).build();
    }

    @Test
    void priorityOrderIsExploitedThenSeverityThenCvss() {
        var a = new ReleaseReadinessService.FindingAgg(entry("CVE-1", "a", "CRITICAL", false, 9.8));
        var b = new ReleaseReadinessService.FindingAgg(entry("CVE-2", "b", "HIGH", true, 7.0));
        var c = new ReleaseReadinessService.FindingAgg(entry("CVE-3", "c", "CRITICAL", false, 9.1));
        var d = new ReleaseReadinessService.FindingAgg(entry("CVE-4", "d", "HIGH", false, 8.0));
        Comparator<ReleaseReadinessService.FindingAgg> order = ReleaseReadinessService.priorityOrder();
        List<String> sorted = List.of(d, c, b, a).stream().sorted(order).map(x -> x.cveId).toList();
        assertThat(sorted).containsExactly("CVE-2", "CVE-1", "CVE-3", "CVE-4");
    }

    @Test
    void sameCveOnTwoPackagesIsTwoFindings() {
        assertThat(ReleaseReadinessService.findingKey(entry("CVE-1", "Lodash", "HIGH", false, null)))
                .isNotEqualTo(ReleaseReadinessService.findingKey(entry("CVE-1", "axios", "HIGH", false, null)));
        assertThat(ReleaseReadinessService.findingKey(entry("cve-1", " LODASH ", "HIGH", false, null)))
                .isEqualTo(ReleaseReadinessService.findingKey(entry("CVE-1", "lodash", "HIGH", false, null)));
    }
}
