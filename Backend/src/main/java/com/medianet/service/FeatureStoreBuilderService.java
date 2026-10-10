package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.CveMlFeature;
import com.medianet.entity.CveRemediationRecord;
import com.medianet.entity.EpssHistorySnapshot;
import com.medianet.repository.CveEntryRepo;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Builds the ML feature store: internal remediation labels + Medianet context
 * known at {@code first_seen} + external EPSS/KEV clipped to detection.
 * Historical averages and {@code affected_repo_count} never look at rows or
 * repositories discovered after {@code first_seen}.
 */
@Service
public class FeatureStoreBuilderService {

    private static final Logger log = LoggerFactory.getLogger(FeatureStoreBuilderService.class);

    private final CveRemediationRecordRepo remediationRecordRepo;
    private final EpssHistorySnapshotRepo epssHistorySnapshotRepo;
    private final CveMlFeatureRepo featureRepo;
    private final CveEntryRepo cveEntryRepo;

    public FeatureStoreBuilderService(CveRemediationRecordRepo remediationRecordRepo,
            EpssHistorySnapshotRepo epssHistorySnapshotRepo, CveMlFeatureRepo featureRepo,
            CveEntryRepo cveEntryRepo) {
        this.remediationRecordRepo = remediationRecordRepo;
        this.epssHistorySnapshotRepo = epssHistorySnapshotRepo;
        this.featureRepo = featureRepo;
        this.cveEntryRepo = cveEntryRepo;
    }

    public record BuildSummary(int rowsBuilt, int withEpssHistory, int withoutEpssHistory, int kevListedCount) {
    }

    @Transactional
    public BuildSummary buildAll() {
        List<CveRemediationRecord> allRecords = remediationRecordRepo.findAll();
        List<CveRemediationRecord> labeled = allRecords.stream()
                .filter(r -> r.getSlaBreached() != null)
                .toList();
        featureRepo.deleteAllFeatures();

        Map<Long, List<CveEntry>> entriesByFirstSeenScan = loadFirstSeenEntries(labeled);

        LocalDateTime now = LocalDateTime.now();
        int withHistory = 0, withoutHistory = 0, kevCount = 0;
        List<CveMlFeature> rows = new ArrayList<>();

        for (CveRemediationRecord r : labeled) {
            List<EpssHistorySnapshot> history = epssHistorySnapshotRepo
                    .findByCveIdOrderBySnapshotDateAsc(r.getCanonicalId());

            LocalDate detectionDate = r.getFirstSeenAt().toLocalDate();
            List<EpssHistorySnapshot> historyBeforeDetection = history.stream()
                    .filter(h -> !h.getSnapshotDate().isAfter(detectionDate))
                    .toList();

            Double epssLatest = null;
            Double epssTrend = null;
            if (!historyBeforeDetection.isEmpty()) {
                withHistory++;
                epssLatest = historyBeforeDetection.get(historyBeforeDetection.size() - 1).getEpssScore();
                double earliest = historyBeforeDetection.get(0).getEpssScore();
                epssTrend = historyBeforeDetection.size() > 1 ? epssLatest - earliest : null;
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

            CveEntry firstSeenEntry = findFirstSeenEntry(r, entriesByFirstSeenScan);
            rows.add(assembleFeature(r, allRecords, firstSeenEntry, epssLatest, epssTrend,
                    historyBeforeDetection.size(), daysToKev, now, true));
        }

        featureRepo.saveAll(rows);
        log.info("Feature store built: {} rows ({} with EPSS history, {} without), {} KEV-listed",
                rows.size(), withHistory, withoutHistory, kevCount);
        return new BuildSummary(rows.size(), withHistory, withoutHistory, kevCount);
    }

    /** A live finding to score: CVE id plus optional package. */
    public record FindingKey(String cveId, String packageName) {
    }

    /**
     * Features for a live CVE. Never includes {@code days_to_fix} or
     * {@code sla_breached}.
     */
    public Optional<Map<String, Object>> buildInferenceFeatures(String cveId, String packageName) {
        return buildInferenceFeaturesBatch(List.of(new FindingKey(cveId, packageName))).get(0);
    }

    /**
     * Same as {@link #buildInferenceFeatures} for many findings, loading the
     * remediation history and scan entries once instead of once per finding.
     * The result list is aligned with {@code keys}.
     */
    public List<Optional<Map<String, Object>>> buildInferenceFeaturesBatch(List<FindingKey> keys) {
        List<CveRemediationRecord> history = remediationRecordRepo.findAll();
        java.util.concurrent.atomic.AtomicReference<List<CveEntry>> scanEntries =
                new java.util.concurrent.atomic.AtomicReference<>();
        java.util.function.Supplier<List<CveEntry>> allEntries = () -> {
            if (scanEntries.get() == null) {
                scanEntries.set(cveEntryRepo.findAllWithScan());
            }
            return scanEntries.get();
        };

        List<CveRemediationRecord> targets = new ArrayList<>(keys.size());
        for (FindingKey key : keys) {
            CveRemediationRecord target = resolveRecord(key.cveId(), key.packageName(), allEntries);
            targets.add(target != null && target.getFirstSeenAt() != null ? target : null);
        }
        Map<Long, List<CveEntry>> byScan = loadFirstSeenEntries(targets.stream().filter(Objects::nonNull).toList());

        List<Optional<Map<String, Object>>> out = new ArrayList<>(keys.size());
        for (CveRemediationRecord target : targets) {
            if (target == null) {
                out.add(Optional.empty());
                continue;
            }
            List<CveRemediationRecord> scoped = history;
            if (target.getId() == null || history.stream().noneMatch(r -> Objects.equals(r.getId(), target.getId()))) {
                scoped = new ArrayList<>(history);
                scoped.add(target);
            }
            LocalDate detectionDate = target.getFirstSeenAt().toLocalDate();
            List<EpssHistorySnapshot> historyBeforeDetection = epssHistorySnapshotRepo
                    .findByCveIdOrderBySnapshotDateAsc(target.getCanonicalId()).stream()
                    .filter(h -> !h.getSnapshotDate().isAfter(detectionDate))
                    .toList();
            Double epssLatest = historyBeforeDetection.isEmpty()
                    ? null
                    : historyBeforeDetection.get(historyBeforeDetection.size() - 1).getEpssScore();
            Double epssTrend = historyBeforeDetection.size() > 1
                    ? epssLatest - historyBeforeDetection.get(0).getEpssScore()
                    : null;
            CveMlFeature feature = assembleFeature(target, scoped, findFirstSeenEntry(target, byScan),
                    epssLatest, epssTrend, historyBeforeDetection.size(), daysToKevListing(target),
                    LocalDateTime.now(), false);
            out.add(Optional.of(toInferenceMap(feature)));
        }
        return out;
    }

    /**
     * Earliest detection of this CVE+package inside the given repositories, from
     * the remediation history. Used to age a finding within one project.
     */
    public Optional<LocalDateTime> firstSeenInRepos(String cveId, String packageName, Set<Long> repositoryIds) {
        if (cveId == null || cveId.isBlank() || repositoryIds == null || repositoryIds.isEmpty()) {
            return Optional.empty();
        }
        String pkg = packageName == null ? "" : packageName.trim();
        return remediationRecordRepo.findByCanonicalIdOrderByFirstSeenAtAsc(cveId.trim()).stream()
                .filter(r -> r.getFirstSeenAt() != null && repositoryIds.contains(r.getRepositoryId()))
                .filter(r -> pkg.isEmpty() || sameText(safePackage(r.getPackageName()), pkg))
                .map(CveRemediationRecord::getFirstSeenAt)
                .findFirst();
    }

    static Map<String, Object> toInferenceMap(CveMlFeature feature) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("cvss_score", feature.getCvssScore());
        row.put("severity", feature.getSeverity());
        row.put("cwe_id", feature.getCweId());
        row.put("ecosystem", feature.getEcosystem());
        row.put("exploit_available", feature.isExploitAvailable());
        row.put("affected_repo_count", feature.getAffectedRepoCount());
        row.put("package_occurrence_count", feature.getPackageOccurrenceCount());
        row.put("hist_mean_days_cwe", feature.getHistMeanDaysCwe());
        row.put("hist_mean_days_ecosystem", feature.getHistMeanDaysEcosystem());
        row.put("hist_mean_days_repo", feature.getHistMeanDaysRepo());
        row.put("hist_mean_days_package", feature.getHistMeanDaysPackage());
        row.put("dependency_depth", feature.getDependencyDepth());
        row.put("direct_dependency", feature.getDirectDependency());
        row.put("fix_available", feature.getFixAvailableAtDetection());
        row.put("epss_score_at_detection", feature.getEpssScoreAtDetection());
        row.put("epss_score_latest", feature.getEpssScoreLatest());
        row.put("epss_score_trend", feature.getEpssScoreTrend());
        row.put("epss_observation_count", feature.getEpssObservationCount());
        row.put("kev_listed", feature.isKevListed());
        row.put("kev_ransomware", feature.isKevRansomware());
        // kev_listed already reflects the right point in time (detection for training
        // rows, today for live inference), so "known" is simply that flag.
        row.put("kev_known_before_detection", feature.isKevListed());
        return row;
    }

    /**
     * Distinct repos where the same CVE+package was already first seen at or
     * before this row's {@code first_seen}. A repo discovered later is ignored.
     */
    static int countAffectedReposAtDetection(CveRemediationRecord current, List<CveRemediationRecord> history) {
        Set<Long> repos = new HashSet<>();
        for (CveRemediationRecord other : history) {
            if (!sameCvePackage(current, other)) {
                continue;
            }
            if (other.getFirstSeenAt().isAfter(current.getFirstSeenAt())) {
                continue;
            }
            repos.add(other.getRepositoryId());
        }
        return repos.size();
    }

    /** Package rows whose first_seen is at or before detection, including this row. */
    static int countPackageOccurrencesAtDetection(CveRemediationRecord current, List<CveRemediationRecord> history) {
        int count = 0;
        String pkg = safePackage(current.getPackageName());
        for (CveRemediationRecord other : history) {
            if (!sameText(safePackage(other.getPackageName()), pkg)) {
                continue;
            }
            if (other.getFirstSeenAt().isAfter(current.getFirstSeenAt())) {
                continue;
            }
            count++;
        }
        return count;
    }

    /**
     * Mean {@code days_to_fix} of rows first seen strictly before {@code firstSeenAt}
     * AND already fixed by then ({@code fixedAt <= firstSeenAt}): a fix that only
     * happened after this detection was not knowable at detection time.
     * Null when there is no such history (no leakage via 0).
     */
    static Double meanDaysBefore(List<CveRemediationRecord> history, LocalDateTime firstSeenAt,
            Predicate<CveRemediationRecord> match) {
        if (firstSeenAt == null || match == null) {
            return null;
        }
        double sum = 0;
        int n = 0;
        for (CveRemediationRecord other : history) {
            if (other.getDaysToFix() == null || other.getFirstSeenAt() == null
                    || other.getFixedAt() == null) {
                continue;
            }
            if (!other.getFirstSeenAt().isBefore(firstSeenAt) || other.getFixedAt().isAfter(firstSeenAt)) {
                continue;
            }
            if (!match.test(other)) {
                continue;
            }
            sum += other.getDaysToFix();
            n++;
        }
        return n == 0 ? null : sum / n;
    }

    /**
     * Training rows only see KEV status as of detection (listed on or before
     * first_seen); a listing added later is future information. Live inference
     * ({@code asOfDetection=false}) legitimately uses today's status.
     */
    static boolean kevKnownAt(CveRemediationRecord r, Integer daysToKev, boolean asOfDetection) {
        if (!r.isKevListed()) {
            return false;
        }
        return !asOfDetection || (daysToKev != null && daysToKev <= 0);
    }

    private CveMlFeature assembleFeature(
            CveRemediationRecord r,
            List<CveRemediationRecord> allRecords,
            CveEntry firstSeenEntry,
            Double epssLatest,
            Double epssTrend,
            int epssObservationCount,
            Integer daysToKev,
            LocalDateTime now,
            boolean asOfDetection) {
        boolean kevKnown = kevKnownAt(r, daysToKev, asOfDetection);
        return CveMlFeature.builder()
                .remediationRecordId(r.getId() != null ? r.getId() : 0L)
                .firstSeenAt(r.getFirstSeenAt())
                .canonicalId(r.getCanonicalId())
                .packageName(r.getPackageName())
                .cweId(r.getCweId())
                .severity(r.getSeverity() != null ? r.getSeverity() : "UNKNOWN")
                .cvssScore(r.getCvssScore())
                .ecosystem(r.getEcosystem())
                .kevListed(kevKnown)
                .kevRansomware(kevKnown && r.isKevRansomware())
                .daysToKevListing(daysToKev)
                .exploitAvailable(r.isExploitAvailable())
                .epssScoreAtDetection(r.getEpssScoreAtDetection())
                .epssScoreLatest(epssLatest)
                .epssScoreTrend(epssTrend)
                .epssObservationCount(epssObservationCount)
                .affectedRepoCount(countAffectedReposAtDetection(r, allRecords))
                .packageOccurrenceCount(countPackageOccurrencesAtDetection(r, allRecords))
                .histMeanDaysCwe(meanDaysBefore(allRecords, r.getFirstSeenAt(),
                        other -> sameText(other.getCweId(), r.getCweId())))
                .histMeanDaysEcosystem(meanDaysBefore(allRecords, r.getFirstSeenAt(),
                        other -> sameText(other.getEcosystem(), r.getEcosystem())))
                .histMeanDaysRepo(meanDaysBefore(allRecords, r.getFirstSeenAt(),
                        other -> Objects.equals(other.getRepositoryId(), r.getRepositoryId())))
                .histMeanDaysPackage(meanDaysBefore(allRecords, r.getFirstSeenAt(),
                        other -> sameText(safePackage(other.getPackageName()), safePackage(r.getPackageName()))))
                .dependencyDepth(firstSeenEntry != null ? firstSeenEntry.getDependencyDepth() : null)
                .directDependency(toDirectDependency(
                        firstSeenEntry != null ? firstSeenEntry.getDirectOrTransitive() : null))
                .fixAvailableAtDetection(firstSeenEntry != null ? firstSeenEntry.isFixAvailable() : null)
                .daysToFix(r.getDaysToFix())
                .slaThresholdDays(r.getSlaThresholdDays())
                .slaBreached(Boolean.TRUE.equals(r.getSlaBreached()))
                .builtAt(now)
                .build();
    }

    private CveRemediationRecord resolveRecord(String cveId, String packageName,
            java.util.function.Supplier<List<CveEntry>> allEntries) {
        if (cveId == null || cveId.isBlank()) {
            return null;
        }
        String canonical = cveId.trim();
        String pkg = packageName == null ? "" : packageName.trim();
        List<CveRemediationRecord> matches = remediationRecordRepo.findByCanonicalIdOrderByFirstSeenAtAsc(canonical);
        if (!pkg.isEmpty()) {
            List<CveRemediationRecord> samePkg = matches.stream()
                    .filter(r -> sameText(safePackage(r.getPackageName()), pkg))
                    .toList();
            if (!samePkg.isEmpty()) {
                return samePkg.get(0);
            }
        }
        if (!matches.isEmpty()) {
            return matches.get(0);
        }
        return synthesizeFromScans(canonical, pkg, allEntries.get());
    }

    private CveRemediationRecord synthesizeFromScans(String canonical, String pkg, List<CveEntry> entries) {
        CveEntry earliest = null;
        LocalDateTime earliestAt = null;
        for (CveEntry entry : entries) {
            String id = entry.getCanonicalId() != null && !entry.getCanonicalId().isBlank()
                    ? entry.getCanonicalId() : entry.getCveId();
            if (!sameText(id, canonical)) {
                continue;
            }
            if (!pkg.isEmpty() && !sameText(safePackage(entry.getPackageName()), pkg)) {
                continue;
            }
            if (entry.getScanResult() == null || entry.getScanResult().getStartedAt() == null) {
                continue;
            }
            LocalDateTime seen = entry.getScanResult().getStartedAt();
            if (earliestAt == null || seen.isBefore(earliestAt)) {
                earliest = entry;
                earliestAt = seen;
            }
        }
        if (earliest == null || earliestAt == null) {
            return null;
        }
        Long repoId = earliest.getScanResult().getRepository() != null
                ? earliest.getScanResult().getRepository().getId() : 0L;
        return CveRemediationRecord.builder()
                .repositoryId(repoId != null ? repoId : 0L)
                .canonicalId(canonical)
                .packageName(earliest.getPackageName())
                .cweId(earliest.getCweId())
                .severity(earliest.getSeverity() != null ? earliest.getSeverity() : "UNKNOWN")
                .cvssScore(earliest.getCvssScore())
                .kevListed(earliest.isKevListed())
                .kevDateAdded(earliest.getKevDateAdded())
                .kevRansomware(earliest.isKevRansomware())
                .exploitAvailable(earliest.isExploitAvailable())
                .epssScoreAtDetection(earliest.getEpssScore())
                .ecosystem(earliest.getEcosystem())
                .firstSeenScanId(earliest.getScanResult().getId())
                .firstSeenAt(earliestAt)
                .stillOpen(true)
                .slaThresholdDays(30)
                .computedAt(LocalDateTime.now())
                .build();
    }

    private static Integer daysToKevListing(CveRemediationRecord r) {
        if (!r.isKevListed() || r.getKevDateAdded() == null || r.getKevDateAdded().isBlank()
                || r.getFirstSeenAt() == null) {
            return null;
        }
        try {
            return (int) ChronoUnit.DAYS.between(r.getFirstSeenAt().toLocalDate(), LocalDate.parse(r.getKevDateAdded()));
        } catch (Exception e) {
            return null;
        }
    }

    static Boolean toDirectDependency(String directOrTransitive) {
        if (directOrTransitive == null || directOrTransitive.isBlank()) {
            return null;
        }
        return switch (directOrTransitive.trim().toUpperCase()) {
            case "DIRECT" -> Boolean.TRUE;
            case "TRANSITIVE" -> Boolean.FALSE;
            default -> null;
        };
    }

    static boolean sameCvePackage(CveRemediationRecord a, CveRemediationRecord b) {
        return a != null && b != null
                && sameText(a.getCanonicalId(), b.getCanonicalId())
                && sameText(safePackage(a.getPackageName()), safePackage(b.getPackageName()));
    }

    private Map<Long, List<CveEntry>> loadFirstSeenEntries(List<CveRemediationRecord> labeled) {
        Set<Long> scanIds = new HashSet<>();
        for (CveRemediationRecord r : labeled) {
            if (r.getFirstSeenScanId() != null) {
                scanIds.add(r.getFirstSeenScanId());
            }
        }
        if (scanIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, List<CveEntry>> byScan = new HashMap<>();
        for (CveEntry entry : cveEntryRepo.findByScanResultIdInWithRepository(scanIds)) {
            if (entry.getScanResult() == null || entry.getScanResult().getId() == null) {
                continue;
            }
            byScan.computeIfAbsent(entry.getScanResult().getId(), k -> new ArrayList<>()).add(entry);
        }
        return byScan;
    }

    private static CveEntry findFirstSeenEntry(CveRemediationRecord record, Map<Long, List<CveEntry>> byScan) {
        List<CveEntry> entries = byScan.getOrDefault(record.getFirstSeenScanId(), List.of());
        for (CveEntry entry : entries) {
            String id = entry.getCanonicalId() != null && !entry.getCanonicalId().isBlank()
                    ? entry.getCanonicalId() : entry.getCveId();
            if (sameText(id, record.getCanonicalId())
                    && sameText(safePackage(entry.getPackageName()), safePackage(record.getPackageName()))) {
                return entry;
            }
        }
        return null;
    }

    private static String safePackage(String packageName) {
        return packageName == null ? "" : packageName;
    }

    private static boolean sameText(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return a.equals(b);
    }
}
