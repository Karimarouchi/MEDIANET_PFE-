package com.medianet.service;

import com.medianet.entity.CveRemediationStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CveJournalSla — MTTR / SLA KEV 24 h")
class CveJournalSlaTest {

    private static final LocalDateTime NOW = LocalDateTime.of(2026, 9, 8, 16, 0);

    @Test
    @DisplayName("délai moyen d'ouverture sur les CVE encore ouvertes")
    void meanDaysOpen_averagesOpenItems() {
        Map<String, Object> sla = CveJournalSla.compute(List.of(
                sample(false, CveRemediationStatus.OPEN, NOW.minusHours(48), null),
                sample(false, CveRemediationStatus.IN_PROGRESS, NOW.minusHours(24), null),
                sample(false, CveRemediationStatus.FIXED, NOW.minusHours(72), NOW.minusHours(60))
        ), NOW);

        assertThat(sla.get("meanDaysOpen")).isEqualTo(1.5);
        assertThat(sla.get("openWithAgeCount")).isEqualTo(2);
    }

    @Test
    @DisplayName("% de KEV corrigées en 24 h")
    void kevFixedWithin24h_percent() {
        Map<String, Object> sla = CveJournalSla.compute(List.of(
                sample(true, CveRemediationStatus.FIXED, NOW.minusHours(30), NOW.minusHours(20)),
                sample(true, CveRemediationStatus.FIXED, NOW.minusHours(80), NOW.minusHours(20)),
                sample(false, CveRemediationStatus.FIXED, NOW.minusHours(10), NOW.minusHours(2))
        ), NOW);

        assertThat(sla.get("kevFixedWithin24hCount")).isEqualTo(1);
        assertThat(sla.get("kevClosedWithTimingCount")).isEqualTo(2);
        assertThat(sla.get("kevFixedWithin24hPercent")).isEqualTo(50L);
    }

    @Test
    @DisplayName("KEV encore ouverte après 24 h = en retard")
    void kevOverdue_afterSlaWindow() {
        Map<String, Object> sla = CveJournalSla.compute(List.of(
                sample(true, CveRemediationStatus.OPEN, NOW.minusHours(25), null),
                sample(true, CveRemediationStatus.IN_PROGRESS, NOW.minusHours(6), null),
                sample(false, CveRemediationStatus.OPEN, NOW.minusHours(72), null)
        ), NOW);

        assertThat(sla.get("kevTotal")).isEqualTo(2);
        assertThat(sla.get("kevOpenCount")).isEqualTo(2);
        assertThat(sla.get("kevOverdueCount")).isEqualTo(1);
        assertThat(CveJournalSla.isKevOverdue(true, CveRemediationStatus.OPEN, NOW.minusHours(24), NOW)).isTrue();
        assertThat(CveJournalSla.isKevOverdue(true, CveRemediationStatus.OPEN, NOW.minusHours(23), NOW)).isFalse();
    }

    @Test
    @DisplayName("sans historique : pas de pourcentage inventé")
    void missingTimestamps_doNotInventPercent() {
        Map<String, Object> sla = CveJournalSla.compute(List.of(
                sample(true, CveRemediationStatus.OPEN, null, null)
        ), NOW);

        assertThat(sla.get("meanDaysOpen")).isNull();
        assertThat(sla.get("kevFixedWithin24hPercent")).isNull();
        assertThat(sla.get("kevOverdueCount")).isEqualTo(0);
    }

    private static CveJournalSla.Sample sample(
            boolean kev, CveRemediationStatus status, LocalDateTime firstSeen, LocalDateTime closedAt) {
        return new CveJournalSla.Sample(kev, status, firstSeen, closedAt);
    }
}
