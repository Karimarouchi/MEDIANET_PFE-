package com.medianet.service;

import com.medianet.entity.CveEntry;
import com.medianet.entity.CveRemediationRecord;
import com.medianet.entity.ScanResult;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.CveRemediationRecordRepo;
import com.medianet.repository.ScanResultRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Derives ML training labels ("did this vulnerability get fixed within its
 * SLA?") from existing scan history — no manual remediation logging needed.
 * For each repository, walks its completed scans in chronological order: a
 * CVE/package pair present in scan N and missing from a later scan is
 * "fixed" (duration = time between the two scans); a pair still present in
 * the latest scan is "still open".
 *
 * This is a derived/materialized table, not a source of truth: every run
 * clears and rebuilds it from {@code scan_results}/{@code cve_entries}.
 */
@Service
public class RemediationLabelService {

    private static final Logger log = LoggerFactory.getLogger(RemediationLabelService.class);

    /** Industry-common vulnerability management SLA targets, in days. */
    private static final Map<String, Integer> SLA_DAYS_BY_SEVERITY = Map.of(
            "CRITICAL", 15,
            "HIGH", 30,
            "MEDIUM", 60,
            "LOW", 90);
    private static final int DEFAULT_SLA_DAYS = 60;

    private final ScanResultRepo scanResultRepo;
    private final CveEntryRepo cveEntryRepo;
    private final CveRemediationRecordRepo remediationRecordRepo;

    public RemediationLabelService(ScanResultRepo scanResultRepo, CveEntryRepo cveEntryRepo,
            CveRemediationRecordRepo remediationRecordRepo) {
        this.scanResultRepo = scanResultRepo;
        this.cveEntryRepo = cveEntryRepo;
        this.remediationRecordRepo = remediationRecordRepo;
    }

    public record DerivationSummary(int repositoriesProcessed, int recordsCreated,
            long breached, long onTime, long censored) {
    }

    @Transactional
    public DerivationSummary deriveAll() {
        List<ScanResult> completedScans = scanResultRepo
                .findByStatusOrderByRepository_IdAscStartedAtAsc(ScanResult.ScanStatus.COMPLETED);

        // Group by repository, preserving chronological order within each group.
        Map<Long, List<ScanResult>> byRepo = new LinkedHashMap<>();
        for (ScanResult s : completedScans) {
            if (s.getRepository() == null) continue;
            byRepo.computeIfAbsent(s.getRepository().getId(), k -> new ArrayList<>()).add(s);
        }

        remediationRecordRepo.deleteAllRecords();
        LocalDateTime now = LocalDateTime.now();
        List<CveRemediationRecord> toSave = new ArrayList<>();
        int reposWithEnoughHistory = 0;

        for (Map.Entry<Long, List<ScanResult>> entry : byRepo.entrySet()) {
            List<ScanResult> scans = entry.getValue();
            if (scans.size() < 2) continue; // need at least a "before" and an "after" to observe a fix
            reposWithEnoughHistory++;
            toSave.addAll(deriveForRepository(entry.getKey(), scans, now));
        }

        remediationRecordRepo.saveAll(toSave);

        long breached = toSave.stream().filter(r -> Boolean.TRUE.equals(r.getSlaBreached())).count();
        long onTime = toSave.stream().filter(r -> Boolean.FALSE.equals(r.getSlaBreached())).count();
        long censored = toSave.stream().filter(r -> r.getSlaBreached() == null).count();

        log.info("Remediation label derivation: {} repos with history, {} records ({} breached, {} on-time, {} censored)",
                reposWithEnoughHistory, toSave.size(), breached, onTime, censored);
        return new DerivationSummary(reposWithEnoughHistory, toSave.size(), breached, onTime, censored);
    }

    private List<CveRemediationRecord> deriveForRepository(Long repositoryId, List<ScanResult> scansAsc,
            LocalDateTime now) {
        // key = canonicalId + "|" + packageName -> the currently-open record being tracked.
        Map<String, CveRemediationRecord> open = new LinkedHashMap<>();
        List<CveRemediationRecord> finished = new ArrayList<>();

        for (ScanResult scan : scansAsc) {
            List<CveEntry> entries = cveEntryRepo.findByScanResultId(scan.getId());
            Map<String, CveEntry> presentThisScan = new LinkedHashMap<>();
            for (CveEntry e : entries) {
                String id = (e.getCanonicalId() != null && !e.getCanonicalId().isBlank())
                        ? e.getCanonicalId() : e.getCveId();
                if (id == null) continue;
                presentThisScan.put(id + "|" + safe(e.getPackageName()), e);
            }

            // Anything open but missing now was fixed as of this scan.
            Iterator<Map.Entry<String, CveRemediationRecord>> it = open.entrySet().iterator();
            while (it.hasNext()) {
                Map.Entry<String, CveRemediationRecord> openEntry = it.next();
                if (!presentThisScan.containsKey(openEntry.getKey())) {
                    CveRemediationRecord record = openEntry.getValue();
                    LocalDateTime fixedAt = scan.getStartedAt() != null ? scan.getStartedAt() : now;
                    record.setFixedScanId(scan.getId());
                    record.setFixedAt(fixedAt);
                    record.setStillOpen(false);
                    int days = (int) ChronoUnit.DAYS.between(record.getFirstSeenAt(), fixedAt);
                    record.setDaysToFix(Math.max(days, 0));
                    record.setSlaBreached(record.getDaysToFix() > record.getSlaThresholdDays());
                    finished.add(record);
                    it.remove();
                }
            }

            // Anything present now but not yet tracked is newly observed.
            for (Map.Entry<String, CveEntry> presentEntry : presentThisScan.entrySet()) {
                if (open.containsKey(presentEntry.getKey())) continue;
                CveEntry e = presentEntry.getValue();
                int slaDays = SLA_DAYS_BY_SEVERITY.getOrDefault(
                        e.getSeverity() != null ? e.getSeverity().toUpperCase(Locale.ROOT) : "", DEFAULT_SLA_DAYS);
                LocalDateTime firstSeenAt = scan.getStartedAt() != null ? scan.getStartedAt() : now;
                CveRemediationRecord record = CveRemediationRecord.builder()
                        .repositoryId(repositoryId)
                        .canonicalId(presentEntry.getKey().substring(0, presentEntry.getKey().indexOf('|')))
                        .packageName(e.getPackageName())
                        .cweId(e.getCweId())
                        .severity(e.getSeverity() != null ? e.getSeverity() : "UNKNOWN")
                        .cvssScore(e.getCvssScore())
                        .kevListed(e.isKevListed())
                        .exploitAvailable(e.isExploitAvailable())
                        .epssScoreAtDetection(e.getEpssScore())
                        .ecosystem(e.getEcosystem())
                        .firstSeenScanId(scan.getId())
                        .firstSeenAt(firstSeenAt)
                        .stillOpen(true)
                        .slaThresholdDays(slaDays)
                        .slaBreached(null) // unknown until fixed or confirmed overdue below
                        .computedAt(now)
                        .build();
                open.put(presentEntry.getKey(), record);
            }
        }

        // Whatever is still open at the end of history: breached if already past its SLA,
        // otherwise censored (outcome not yet known — excluded from training as-is).
        for (CveRemediationRecord record : open.values()) {
            long daysOpen = ChronoUnit.DAYS.between(record.getFirstSeenAt(), now);
            record.setSlaBreached(daysOpen > record.getSlaThresholdDays() ? Boolean.TRUE : null);
            finished.add(record);
        }

        finished.forEach(r -> r.setComputedAt(now));
        return finished;
    }

    private static String safe(String s) {
        return s != null ? s : "";
    }
}
