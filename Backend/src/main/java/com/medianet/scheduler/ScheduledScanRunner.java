package com.medianet.scheduler;

import com.medianet.dto.ScanResponse;
import com.medianet.entity.ScheduledScan;
import com.medianet.entity.ScheduledScanStatus;
import com.medianet.entity.ScanResult;
import com.medianet.repository.ScheduledScanRepository;
import com.medianet.repository.ScanResultRepo;
import com.medianet.service.ScanService;
import com.medianet.service.ScheduledScanService;
import com.medianet.service.SslLabsService;
import com.medianet.service.CensysSslService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class ScheduledScanRunner {

    private static final Logger log = LoggerFactory.getLogger(ScheduledScanRunner.class);

    private final ScheduledScanRepository scheduledScanRepo;
    private final ScheduledScanService scheduledScanService;
    private final ScanService scanService;
    private final ScanResultRepo scanResultRepo;
    private final SslLabsService sslLabsService;
    private final CensysSslService censysSslService;

    public ScheduledScanRunner(ScheduledScanRepository scheduledScanRepo,
                                ScheduledScanService scheduledScanService,
                                ScanService scanService,
                                ScanResultRepo scanResultRepo,
                                SslLabsService sslLabsService,
                                CensysSslService censysSslService) {
        this.scheduledScanRepo = scheduledScanRepo;
        this.scheduledScanService = scheduledScanService;
        this.scanService = scanService;
        this.scanResultRepo = scanResultRepo;
        this.sslLabsService = sslLabsService;
        this.censysSslService = censysSslService;
    }

    @Scheduled(fixedDelay = 60_000)
    public void executeDueScans() {
        Instant now = Instant.now();
        List<ScheduledScan> dueScans = scheduledScanRepo.findDueScans(ScheduledScanStatus.ACTIVE, now);

        if (dueScans.isEmpty()) {
            return;
        }

        log.info("[SCHEDULED_SCAN] {} due scan(s) found at {}", dueScans.size(), now);

        for (ScheduledScan scheduled : dueScans) {
            processOne(scheduled);
        }
    }

    private void processOne(ScheduledScan scheduled) {
        log.info("[SCHEDULED_SCAN] Due scan found: repository={}, scheduleId={}, type={}",
            scheduled.getRepositoryName(), scheduled.getId(), scheduled.getScheduleType());

        // 1. Check for running scan on same repository (conflict protection)
        try {
            if (scanService.existsRunningScanForRepository(scheduled.getRepositoryId())) {
                String reason = "Scan déjà en cours sur ce repository";
                scheduledScanService.onScanPostponed(scheduled, reason);
                log.warn("[SCHEDULED_SCAN] Postponed 10 min: id={}, repo={}",
                    scheduled.getId(), scheduled.getRepositoryName());
                return;
            }
        } catch (Exception e) {
            log.error("[SCHEDULED_SCAN] Error checking running scans for id={}: {}", scheduled.getId(), e.getMessage());
        }

        // 2. Mark as RUNNING to prevent double-launch
        scheduledScanService.markRunning(scheduled);

        // 3. Launch the scan
        try {
            log.info("[SCHEDULED_SCAN] Starting scheduled scan: id={}, repo={}",
                scheduled.getId(), scheduled.getRepositoryName());

            ScanResponse response = scanService.startScheduledScan(
                scheduled.getRepositoryId(),
                scheduled.getRepoUrl(),
                scheduled.getScanMode(),
                scheduled.getBranch(),
                scheduled.getTargetDomain(),
                scheduled.getDastTargetUrl()
            );

            log.info("[SCHEDULED_SCAN] Scan started successfully: scheduleId={}, scanId={}",
                scheduled.getId(), response.getScanId());

            // If this is an SSL-only scan, fire the parallel SSL Labs and Censys analyses
            if ("ssl-only".equals(scheduled.getScanMode())) {
                ScanResult scanEntity = scanResultRepo.findById(response.getScanId()).orElse(null);
                if (scanEntity != null) {
                    String dir = scanEntity.getResultsDir();
                    String domain = scheduled.getTargetDomain() != null ? scheduled.getTargetDomain()
                            : scheduled.getRepoUrl().replace("ssl://", "");
                    log.info("[SCHEDULED_SCAN] Launching parallel SSL Labs & Censys scans for domain={} and resultsDir={}", domain, dir);
                    sslLabsService.analyzeAsync(domain, dir);
                    censysSslService.analyzeAsync(domain, dir);
                }
            }

            // 4. Update metadata
            scheduledScanService.onScanSuccess(scheduled, response.getScanId());

        } catch (Exception e) {
            log.error("[SCHEDULED_SCAN] Failed to start scan: id={}, error={}",
                scheduled.getId(), e.getMessage(), e);

            // Determine if critical (repo deleted, no owner, etc.)
            boolean critical = e.getMessage() != null &&
                (e.getMessage().contains("Repository not found") ||
                 e.getMessage().contains("no owner user"));

            scheduledScanService.onScanError(scheduled, e.getMessage(), critical);
        }
    }
}
