package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.CveRemediationRecord;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.CveRemediationRecordRepo;
import com.medianet.repository.ScanResultRepo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@DisplayName("RemediationLabelService — labels de l'expérience A")
class RemediationLabelServiceTest {

    private static final LocalDateTime T0 = LocalDateTime.of(2026, 1, 1, 10, 0);

    private final ScanResultRepo scanRepo = mock(ScanResultRepo.class);
    private final CveEntryRepo entryRepo = mock(CveEntryRepo.class);
    private final CveRemediationRecordRepo recordRepo = mock(CveRemediationRecordRepo.class);
    private final RemediationLabelService service = new RemediationLabelService(scanRepo, entryRepo, recordRepo);

    @Test
    @DisplayName("ouvert : l'horizon est le dernier scan du dépôt, pas la date du jour")
    void openFinding_usesLastScanAsHorizon() {
        // HIGH threshold = 30 days. Seen on day 0, still open on the last scan at day 10.
        // Today is months later, but that must NOT make it "breached".
        List<CveRemediationRecord> saved = run(
                scan(1L, T0, entry("CVE-1", "HIGH")),
                scan(2L, T0.plusDays(10), entry("CVE-1", "HIGH")));

        assertThat(saved).hasSize(1);
        assertThat(saved.get(0).getSlaBreached()).isNull(); // censored
        assertThat(saved.get(0).isStillOpen()).isTrue();
    }

    @Test
    @DisplayName("ouvert au-delà du seuil au dernier scan : breached")
    void openFinding_pastThresholdAtLastScan_isBreached() {
        List<CveRemediationRecord> saved = run(
                scan(1L, T0, entry("CVE-1", "HIGH")),
                scan(2L, T0.plusDays(45), entry("CVE-1", "HIGH")));

        assertThat(saved.get(0).getSlaBreached()).isTrue();
    }

    @Test
    @DisplayName("corrigé : days_to_fix = écart entre scans, breached seulement au-delà du seuil")
    void fixedFinding_daysToFixAndBreach() {
        List<CveRemediationRecord> saved = run(
                scan(1L, T0, entry("CVE-1", "CRITICAL")),
                scan(2L, T0.plusDays(5)),
                scan(3L, T0.plusDays(20)));

        assertThat(saved).hasSize(1);
        assertThat(saved.get(0).getDaysToFix()).isEqualTo(5);
        assertThat(saved.get(0).getFixedAt()).isEqualTo(T0.plusDays(5));
        assertThat(saved.get(0).getSlaBreached()).isFalse();
    }

    @SuppressWarnings("unchecked")
    private List<CveRemediationRecord> run(ScanFixture... scans) {
        Repository repo = new Repository();
        repo.setId(7L);
        List<ScanResult> results = new java.util.ArrayList<>();
        for (ScanFixture f : scans) {
            f.scan.setRepository(repo);
            results.add(f.scan);
            when(entryRepo.findByScanResultId(f.scan.getId())).thenReturn(f.entries);
        }
        when(scanRepo.findByStatusOrderByRepository_IdAscStartedAtAsc(ScanResult.ScanStatus.COMPLETED))
                .thenReturn(results);
        service.deriveAll();
        ArgumentCaptor<List<CveRemediationRecord>> captor = ArgumentCaptor.forClass(List.class);
        verify(recordRepo).saveAll(captor.capture());
        return captor.getValue();
    }

    private static ScanFixture scan(Long id, LocalDateTime at, CveEntry... entries) {
        ScanResult s = new ScanResult();
        s.setId(id);
        s.setStartedAt(at);
        s.setStatus(ScanResult.ScanStatus.COMPLETED);
        return new ScanFixture(s, List.of(entries));
    }

    private static CveEntry entry(String cve, String severity) {
        CveEntry e = new CveEntry();
        e.setCveId(cve);
        e.setCanonicalId(cve);
        e.setPackageName("pkg");
        e.setSeverity(severity);
        return e;
    }

    private record ScanFixture(ScanResult scan, List<CveEntry> entries) {
    }
}
