package com.medianet.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("ReleaseReadinessService — deadline client vs max(estimatedDays)")
class ReleaseReadinessServiceTest {

    @Test
    @DisplayName("chemin critique = max des estimations, jamais la somme")
    void criticalPath_isMaxNotSum() {
        assertThat(ReleaseReadinessService.criticalPathDays(List.of(2.0, 8.0, 3.0))).isEqualTo(8.0);
        assertThat(ReleaseReadinessService.criticalPathDays(List.of(2.0, 3.0))).isNotEqualTo(5.0);
        assertThat(ReleaseReadinessService.criticalPathDays(List.of())).isNull();
        assertThat(ReleaseReadinessService.criticalPathDays(java.util.Arrays.asList(4.0, null, 1.0))).isEqualTo(4.0);
    }

    @Test
    @DisplayName("risque de retard calé sur l'intervalle MAE")
    void delayRisk_usesMaeInterval() {
        assertThat(ReleaseReadinessService.delayRisk(10, 4.0, 2.0)).isEqualTo("FAIBLE");
        assertThat(ReleaseReadinessService.delayRisk(5, 4.0, 2.0)).isEqualTo("MOYEN");
        assertThat(ReleaseReadinessService.delayRisk(3, 4.0, 2.0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.delayRisk(-1, 0.0, 2.0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.delayRisk(null, 4.0, 2.0)).isNull();
        assertThat(ReleaseReadinessService.delayRisk(10, null, 2.0)).isNull();
        assertThat(ReleaseReadinessService.delayRisk(10, 4.0, null)).isEqualTo("FAIBLE");
        assertThat(ReleaseReadinessService.delayRisk(5, 4.0, null)).isEqualTo("MOYEN");
    }

    @Test
    @DisplayName("jours restants = deadline locale − aujourd'hui")
    void daysRemaining_isCalendarDelta() {
        LocalDate today = LocalDate.now();
        assertThat(ReleaseReadinessService.daysRemaining(null)).isNull();
        assertThat(ReleaseReadinessService.daysRemaining(today)).isZero();
        assertThat(ReleaseReadinessService.daysRemaining(today.plusDays(7))).isEqualTo(7);
        assertThat(ReleaseReadinessService.daysRemaining(today.minusDays(2))).isEqualTo(-2);
    }

    @Test
    @DisplayName("priorités : KEV puis bande puis estimatedDays puis repos")
    void priorityOrder_kevThenBandThenDays() {
        ReleaseReadinessService.FindingAgg kevLow = agg("CVE-1", true, "FAIBLE", 1.0, 1);
        ReleaseReadinessService.FindingAgg highLong = agg("CVE-2", false, "ELEVE", 9.0, 3);
        ReleaseReadinessService.FindingAgg highShort = agg("CVE-3", false, "ELEVE", 2.0, 1);
        List<ReleaseReadinessService.FindingAgg> rows = new ArrayList<>(List.of(highShort, highLong, kevLow));
        rows.sort(ReleaseReadinessService.priorityOrder());
        assertThat(rows).extracting(a -> a.cveId).containsExactly("CVE-1", "CVE-2", "CVE-3");
    }

    @Test
    @DisplayName("jours restants = estimation − ancienneté, jamais négatif")
    void remainingDays_subtractsAge() {
        assertThat(ReleaseReadinessService.remainingDays(12.0, 10)).isEqualTo(2.0);
        assertThat(ReleaseReadinessService.remainingDays(3.0, 10)).isZero();
        assertThat(ReleaseReadinessService.remainingDays(null, 4)).isNull();
        assertThat(ReleaseReadinessService.remainingDays(5.0, 0)).isEqualTo(5.0);
    }

    @Test
    @DisplayName("une CVE déjà ouverte longtemps réduit le risque de retard")
    void ageLowersDelayRisk() {
        Double total = 12.0;
        assertThat(ReleaseReadinessService.delayRisk(5, total, 2.0)).isEqualTo("ELEVE");
        Double remaining = ReleaseReadinessService.remainingDays(total, 10);
        assertThat(ReleaseReadinessService.delayRisk(5, remaining, 2.0)).isEqualTo("FAIBLE");
    }

    @Test
    @DisplayName("exemple du jury : J-5, ~4 j, MAE 2,7 → MOYEN (borne haute 6,7 > 5)")
    void juryExample() {
        assertThat(ReleaseReadinessService.delayRisk(5, 4.0, 2.7)).isEqualTo("MOYEN");
    }

    private static ReleaseReadinessService.FindingAgg agg(String cveId, boolean kev, String band,
            double days, int repoCount) {
        CveStub first = new CveStub(cveId, kev);
        ReleaseReadinessService.FindingAgg agg = new ReleaseReadinessService.FindingAgg(first);
        agg.kevListed = kev;
        agg.blocking = true;
        agg.remediationBand = band;
        agg.estimatedDays = days;
        agg.remainingDays = days;
        agg.repositories.clear();
        for (int i = 0; i < repoCount; i++) {
            agg.repositories.add("repo-" + i);
        }
        return agg;
    }

    /** Minimal CveEntry stand-in so FindingAgg can be constructed in unit tests. */
    private static final class CveStub extends com.medianet.entity.CveEntry {
        CveStub(String cveId, boolean kev) {
            setCveId(cveId);
            setCanonicalId(cveId);
            setPackageName("pkg");
            setSeverity(kev ? "MEDIUM" : "HIGH");
            setKevListed(kev);
        }
    }

    @Test
    void rulesDelayRisk_neverSaysLowWithOpenBlockers() {
        assertThat(ReleaseReadinessService.rulesDelayRisk(null, 5, 0)).isNull();
        assertThat(ReleaseReadinessService.rulesDelayRisk(-2, 1, 0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.rulesDelayRisk(7, 3, 0)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.rulesDelayRisk(14, 3, 1)).isEqualTo("ELEVE");
        assertThat(ReleaseReadinessService.rulesDelayRisk(31, 87, 0)).isEqualTo("MOYEN");
        assertThat(ReleaseReadinessService.rulesDelayRisk(31, 0, 0)).isEqualTo("FAIBLE");
    }
}
