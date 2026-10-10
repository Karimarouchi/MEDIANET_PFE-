package com.medianet.service;

import com.medianet.entity.CveMlFeature;
import com.medianet.entity.CveRemediationRecord;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("FeatureStoreBuilderService — features internes sans leakage")
class FeatureStoreBuilderServiceTest {

    private static final LocalDateTime DAY_1 = LocalDateTime.of(2026, 4, 1, 10, 0);
    private static final LocalDateTime DAY_10 = LocalDateTime.of(2026, 4, 10, 10, 0);
    private static final LocalDateTime DAY_20 = LocalDateTime.of(2026, 4, 20, 10, 0);

    @Test
    @DisplayName("affected_repo_count ignore un dépôt découvert après first_seen")
    void affectedRepoCount_doesNotCountReposDiscoveredLater() {
        CveRemediationRecord repoA = record(1L, 10L, "CVE-1", "log4j", DAY_1, 4);
        CveRemediationRecord repoB = record(2L, 20L, "CVE-1", "log4j", DAY_10, null);
        CveRemediationRecord repoCLater = record(3L, 30L, "CVE-1", "log4j", DAY_20, null);
        List<CveRemediationRecord> history = List.of(repoA, repoB, repoCLater);

        assertThat(FeatureStoreBuilderService.countAffectedReposAtDetection(repoA, history)).isEqualTo(1);
        assertThat(FeatureStoreBuilderService.countAffectedReposAtDetection(repoB, history)).isEqualTo(2);
        assertThat(FeatureStoreBuilderService.countAffectedReposAtDetection(repoCLater, history)).isEqualTo(3);
    }

    @Test
    @DisplayName("affected_repo_count ne mélange pas une autre CVE ou un autre package")
    void affectedRepoCount_requiresSameCveAndPackage() {
        CveRemediationRecord current = record(1L, 10L, "CVE-1", "log4j", DAY_10, null);
        CveRemediationRecord otherCve = record(2L, 20L, "CVE-2", "log4j", DAY_1, 2);
        CveRemediationRecord otherPkg = record(3L, 30L, "CVE-1", "gson", DAY_1, 2);
        List<CveRemediationRecord> history = List.of(current, otherCve, otherPkg);

        assertThat(FeatureStoreBuilderService.countAffectedReposAtDetection(current, history)).isEqualTo(1);
    }

    @Test
    @DisplayName("hist_mean_days_* n'utilise que les corrections strictement antérieures à first_seen")
    void histMeanDays_usesOnlyPastResolvedRows() {
        CveRemediationRecord pastSameCwe = record(1L, 10L, "CVE-OLD", "a", DAY_1, 6);
        pastSameCwe.setCweId("CWE-79");
        CveRemediationRecord current = record(2L, 20L, "CVE-NEW", "b", DAY_10, null);
        current.setCweId("CWE-79");
        CveRemediationRecord sameDay = record(3L, 30L, "CVE-SAME-DAY", "c", DAY_10, 99);
        sameDay.setCweId("CWE-79");
        CveRemediationRecord future = record(4L, 40L, "CVE-FUT", "d", DAY_20, 2);
        future.setCweId("CWE-79");
        CveRemediationRecord otherCwe = record(5L, 50L, "CVE-OTH", "e", DAY_1, 40);
        otherCwe.setCweId("CWE-89");
        CveRemediationRecord unresolvedPast = record(6L, 60L, "CVE-OPEN", "f", DAY_1, null);
        unresolvedPast.setCweId("CWE-79");

        Double mean = FeatureStoreBuilderService.meanDaysBefore(
                List.of(pastSameCwe, current, sameDay, future, otherCwe, unresolvedPast),
                current.getFirstSeenAt(),
                other -> "CWE-79".equals(other.getCweId()));

        assertThat(mean).isEqualTo(6.0);
    }

    @Test
    @DisplayName("hist_mean_days exclut une correction survenue après first_seen de la ligne")
    void histMeanDays_excludesFixesNotYetKnown() {
        // seen day 1, fixed only on day 21: unknown on day 10 when the current row is detected
        CveRemediationRecord fixedLater = record(1L, 10L, "CVE-OLD", "a", DAY_1, 20);
        // seen day 1, fixed day 4: known on day 10
        CveRemediationRecord fixedBefore = record(2L, 20L, "CVE-OLD2", "b", DAY_1, 3);
        CveRemediationRecord current = record(3L, 30L, "CVE-NEW", "c", DAY_10, null);

        Double mean = FeatureStoreBuilderService.meanDaysBefore(
                List.of(fixedLater, fixedBefore, current), current.getFirstSeenAt(), other -> true);

        assertThat(mean).isEqualTo(3.0);
    }

    @Test
    @DisplayName("KEV à la détection : une inscription KEV postérieure n'est pas visible à l'entraînement")
    void kevKnownAt_hidesFutureListing() {
        CveRemediationRecord kev = record(1L, 10L, "CVE-1", "a", DAY_1, null);
        kev.setKevListed(true);
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, -3, true)).isTrue();
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, 0, true)).isTrue();
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, 12, true)).isFalse();
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, null, true)).isFalse();
        // live inference uses today's KEV status
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, 12, false)).isTrue();
        kev.setKevListed(false);
        assertThat(FeatureStoreBuilderService.kevKnownAt(kev, -3, false)).isFalse();
    }

    @Test
    @DisplayName("hist_mean_days sans passé retourne null plutôt que 0")
    void histMeanDays_nullWhenNoPast() {
        CveRemediationRecord current = record(1L, 10L, "CVE-1", "log4j", DAY_1, null);
        current.setCweId("CWE-79");

        assertThat(FeatureStoreBuilderService.meanDaysBefore(
                List.of(current), current.getFirstSeenAt(), other -> true)).isNull();
    }

    @Test
    @DisplayName("package_occurrence_count ignore les occurrences apparues après first_seen")
    void packageOccurrence_ignoresFuture() {
        CveRemediationRecord past = record(1L, 10L, "CVE-A", "log4j", DAY_1, 3);
        CveRemediationRecord current = record(2L, 20L, "CVE-B", "log4j", DAY_10, null);
        CveRemediationRecord future = record(3L, 30L, "CVE-C", "log4j", DAY_20, 1);
        CveRemediationRecord otherPkg = record(4L, 40L, "CVE-D", "gson", DAY_1, 1);

        assertThat(FeatureStoreBuilderService.countPackageOccurrencesAtDetection(
                current, List.of(past, current, future, otherPkg))).isEqualTo(2);
    }

    @Test
    @DisplayName("toInferenceMap n'expose jamais days_to_fix ni sla_breached")
    void inferenceMap_excludesLabels() {
        CveMlFeature feature = CveMlFeature.builder()
                .remediationRecordId(1L)
                .firstSeenAt(DAY_1)
                .canonicalId("CVE-1")
                .severity("HIGH")
                .cvssScore(8.1)
                .daysToFix(12)
                .slaThresholdDays(30)
                .slaBreached(true)
                .builtAt(DAY_1)
                .build();

        Map<String, Object> row = FeatureStoreBuilderService.toInferenceMap(feature);
        assertThat(row).doesNotContainKeys("days_to_fix", "sla_breached", "sla_threshold_days");
        assertThat(row.get("cvss_score")).isEqualTo(8.1);
    }

    @Test
    @DisplayName("direct_dependency mappe DIRECT / TRANSITIVE / UNKNOWN")
    void directDependency_mapping() {
        assertThat(FeatureStoreBuilderService.toDirectDependency("DIRECT")).isTrue();
        assertThat(FeatureStoreBuilderService.toDirectDependency("transitive")).isFalse();
        assertThat(FeatureStoreBuilderService.toDirectDependency("UNKNOWN")).isNull();
        assertThat(FeatureStoreBuilderService.toDirectDependency(null)).isNull();
    }

    private static CveRemediationRecord record(Long id, Long repoId, String cve, String pkg,
            LocalDateTime firstSeen, Integer daysToFix) {
        CveRemediationRecord r = CveRemediationRecord.builder()
                .repositoryId(repoId)
                .canonicalId(cve)
                .packageName(pkg)
                .severity("HIGH")
                .firstSeenScanId(id)
                .firstSeenAt(firstSeen)
                .stillOpen(daysToFix == null)
                .daysToFix(daysToFix)
                .fixedAt(daysToFix == null ? null : firstSeen.plusDays(daysToFix))
                .slaThresholdDays(30)
                .computedAt(firstSeen)
                .build();
        r.setId(id);
        return r;
    }
}
