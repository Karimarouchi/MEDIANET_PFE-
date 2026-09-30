package com.medianet.service;

import com.medianet.entity.CveMlFeature;
import com.medianet.entity.CveRemediationRecord;
import com.medianet.entity.EpssHistorySnapshot;
import com.medianet.repository.CveMlFeatureRepo;
import com.medianet.repository.CveRemediationRecordRepo;
import com.medianet.repository.EpssHistorySnapshotRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * Builds the ML feature store: joins Phase 0 labels (CveRemediationRecord)
 * with external signals — EPSS historical trajectory (Phase 1) and CISA KEV
 * timing (already enriched live on CveEntry, reused here). One row per
 * labeled remediation record; censored records (outcome not yet known,
 * slaBreached == null) are excluded on purpose — including them as either
 * class would bias the model.
 */
@Service
public class FeatureStoreBuilderService {

    private static final Logger log = LoggerFactory.getLogger(FeatureStoreBuilderService.class);

    private final CveRemediationRecordRepo remediationRecordRepo;
    private final EpssHistorySnapshotRepo epssHistorySnapshotRepo;
    private final CveMlFeatureRepo featureRepo;

    public FeatureStoreBuilderService(CveRemediationRecordRepo remediationRecordRepo,
            EpssHistorySnapshotRepo epssHistorySnapshotRepo, CveMlFeatureRepo featureRepo) {
        this.remediationRecordRepo = remediationRecordRepo;
        this.epssHistorySnapshotRepo = epssHistorySnapshotRepo;
        this.featureRepo = featureRepo;
    }

    public record BuildSummary(int rowsBuilt, int withEpssHistory, int withoutEpssHistory, int kevListedCount) {
    }

    @Transactional
    public BuildSummary buildAll() {
        List<CveRemediationRecord> labeled = remediationRecordRepo.findBySlaBreachedIsNotNull();
        featureRepo.deleteAllFeatures();

        LocalDateTime now = LocalDateTime.now();
        int withHistory = 0, withoutHistory = 0, kevCount = 0;
        java.util.List<CveMlFeature> rows = new java.util.ArrayList<>();

        for (CveRemediationRecord r : labeled) {
            List<EpssHistorySnapshot> history = epssHistorySnapshotRepo
                    .findByCveIdOrderBySnapshotDateAsc(r.getCanonicalId());

            Double epssLatest = null;
            Double epssTrend = null;
            if (!history.isEmpty()) {
                withHistory++;
                LocalDate referenceDate = r.getFixedAt() != null
                        ? r.getFixedAt().toLocalDate() : now.toLocalDate();
                EpssHistorySnapshot latestUpToReference = history.stream()
                        .filter(h -> !h.getSnapshotDate().isAfter(referenceDate))
                        .reduce((a, b) -> b) // last one <= reference date
                        .orElse(history.get(history.size() - 1));
                epssLatest = latestUpToReference.getEpssScore();
                double earliest = history.get(0).getEpssScore();
                epssTrend = epssLatest - earliest;
            } else {
                withoutHistory++;
            }

            Integer daysToKev = null;
            if (r.isKevListed()) {
                kevCount++;
                if (r.getKevDateAdded() != null && !r.getKevDateAdded().isBlank()) {
                    try {
                        LocalDate kevDate = LocalDate.parse(r.getKevDateAdded());
                        daysToKev = (int) ChronoUnit.DAYS.between(r.getFirstSeenAt().toLocalDate(), kevDate);
                    } catch (Exception e) {
                        // malformed upstream date — leave null rather than guess
                    }
                }
            }

            CveMlFeature feature = CveMlFeature.builder()
                    .remediationRecordId(r.getId())
                    .canonicalId(r.getCanonicalId())
                    .packageName(r.getPackageName())
                    .cweId(r.getCweId())
                    .severity(r.getSeverity())
                    .cvssScore(r.getCvssScore())
                    .ecosystem(r.getEcosystem())
                    .kevListed(r.isKevListed())
                    .kevRansomware(r.isKevRansomware())
                    .daysToKevListing(daysToKev)
                    .exploitAvailable(r.isExploitAvailable())
                    .epssScoreAtDetection(r.getEpssScoreAtDetection())
                    .epssScoreLatest(epssLatest)
                    .epssScoreTrend(epssTrend)
                    .epssObservationCount(history.size())
                    .daysToFix(r.getDaysToFix())
                    .slaThresholdDays(r.getSlaThresholdDays())
                    .slaBreached(Boolean.TRUE.equals(r.getSlaBreached()))
                    .builtAt(now)
                    .build();
            rows.add(feature);
        }

        featureRepo.saveAll(rows);
        log.info("Feature store built: {} rows ({} with EPSS history, {} without), {} KEV-listed",
                rows.size(), withHistory, withoutHistory, kevCount);
        return new BuildSummary(rows.size(), withHistory, withoutHistory, kevCount);
    }
}
