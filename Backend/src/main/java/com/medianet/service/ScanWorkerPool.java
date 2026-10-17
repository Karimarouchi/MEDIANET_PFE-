package com.medianet.service;

import com.medianet.repository.ScanResultRepo;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Dispatches PENDING scans to dedicated worker pools, partitioned by scan
 * category instead of one shared pool — an SSL scan never waits behind a
 * heavy code scan, and vice versa. Each category claims jobs from the same
 * {@code scan_results} table via PostgreSQL's SELECT ... FOR UPDATE SKIP
 * LOCKED (see {@link ScanResultRepo#claimNextPending}), so this design is
 * already safe if a second backend instance is later pointed at the same
 * database — no code change needed to add more capacity.
 */
@Service
public class ScanWorkerPool {

    private static final Logger log = LoggerFactory.getLogger(ScanWorkerPool.class);

    /** category name -> scan modes it accepts. */
    private static final Map<String, List<String>> CATEGORIES = new LinkedHashMap<>();
    static {
        CATEGORIES.put("ssl", List.of("ssl-only"));
        CATEGORIES.put("code", List.of("auto", "dast"));
        CATEGORIES.put("image", List.of("docker-image"));
    }

    private final ScanResultRepo scanResultRepo;
    private final ScanService scanService;

    @Value("${vulnix.scan.workers.ssl:1}")
    private int sslWorkers;

    @Value("${vulnix.scan.workers.code:2}")
    private int codeWorkers;

    @Value("${vulnix.scan.workers.image:1}")
    private int imageWorkers;

    @Value("${vulnix.scan.poll-interval-ms:2000}")
    private long pollIntervalMs;

    private final List<ExecutorService> pools = new java.util.ArrayList<>();
    private final AtomicBoolean running = new AtomicBoolean(true);

    /** Live status per worker id, e.g. "code-1" -> IDLE / RUNNING scan #42. Read by the Workers UI. */
    private final Map<String, WorkerStatus> statuses = new java.util.concurrent.ConcurrentHashMap<>();

    public ScanWorkerPool(ScanResultRepo scanResultRepo, ScanService scanService) {
        this.scanResultRepo = scanResultRepo;
        this.scanService = scanService;
    }

    public record WorkerStatus(String workerId, String category, boolean busy, Long currentScanId) {
    }

    public List<WorkerStatus> currentStatuses() {
        return statuses.values().stream()
                .sorted(java.util.Comparator.comparing(WorkerStatus::workerId))
                .toList();
    }

    /**
     * A scan still RUNNING this long after it started was lost (backend stopped mid-scan): nothing will ever
     * finish it, and its page would wait forever. Long enough to never touch a scan another instance is running.
     */
    @Value("${vulnix.scan.orphan-after-minutes:180}")
    private long orphanAfterMinutes;

    @PostConstruct
    void start() {
        failOrphanedScans();
        startCategory("ssl", sslWorkers);
        startCategory("code", codeWorkers);
        startCategory("image", imageWorkers);
        log.info("ScanWorkerPool started: ssl={} code={} image={} (poll every {}ms)",
                sslWorkers, codeWorkers, imageWorkers, pollIntervalMs);
    }

    void failOrphanedScans() {
        checkOrphans(true);
    }

    /** Scans seen without a container at the previous check: declared orphaned only if still missing now. */
    private final java.util.Set<Long> orphanSuspects = java.util.concurrent.ConcurrentHashMap.newKeySet();

    /**
     * Every 2 minutes: a RUNNING scan that no worker of this backend runs and whose scanner container is gone will
     * never finish on its own (backend restarted while its container worked). It is handed to
     * ScanService.recoverOrphan, which imports its results when the container had finished, or closes it.
     */
    @org.springframework.scheduling.annotation.Scheduled(initialDelay = 120_000L, fixedDelay = 120_000L)
    void periodicOrphanCheck() {
        checkOrphans(false);
    }

    void checkOrphans(boolean atStartup) {
        try {
            java.time.LocalDateTime limit = java.time.LocalDateTime.now().minusMinutes(orphanAfterMinutes);
            java.util.Set<String> live = runningScannerContainers();
            java.util.Set<Long> missingNow = new java.util.HashSet<>();
            int n = 0;
            for (var scan : scanResultRepo.findByStatusOrderByRepository_IdAscStartedAtAsc(
                    com.medianet.entity.ScanResult.ScanStatus.RUNNING)) {
                Long id = scan.getId();
                if (scanService.isActiveHere(id)) {
                    continue;
                }
                // Precise rule when Docker answers: no scanner container for this scan = nothing will finish it.
                // Fallback when Docker cannot be queried: the age limit.
                boolean orphan = live != null
                        ? live.stream().noneMatch(name -> name.endsWith("-scan-" + id))
                        : scan.getStartedAt() != null && scan.getStartedAt().isBefore(limit);
                if (!orphan) {
                    continue;
                }
                missingNow.add(id);
                // At startup nothing of this instance runs yet; afterwards require two checks in a row so a scan
                // whose container is still starting is never touched.
                if (atStartup || orphanSuspects.contains(id)) {
                    scanService.recoverOrphan(id);
                    n++;
                }
            }
            orphanSuspects.retainAll(missingNow);
            orphanSuspects.addAll(missingNow);
            if (n > 0) {
                log.warn("Recovered or closed {} orphaned RUNNING scan(s) (no scanner container left)", n);
            }
        } catch (Exception e) {
            log.warn("Orphaned scan check skipped: {}", e.getMessage());
        }
    }

    /** Names of running scanner containers ("kali-<worker>-scan-<id>"), or null when Docker cannot be queried. */
    static java.util.Set<String> runningScannerContainers() {
        try {
            Process p = new ProcessBuilder("docker", "ps", "--filter", "name=kali-", "--format", "{{.Names}}")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            if (!p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS) || p.exitValue() != 0) {
                return null;
            }
            java.util.Set<String> names = new java.util.HashSet<>();
            for (String line : out.split("\\R")) {
                if (!line.isBlank()) names.add(line.trim());
            }
            return names;
        } catch (Exception e) {
            return null;
        }
    }

    private void startCategory(String category, int count) {
        if (count <= 0) return;
        List<String> modes = CATEGORIES.get(category);
        ExecutorService pool = Executors.newFixedThreadPool(count);
        pools.add(pool);
        for (int i = 1; i <= count; i++) {
            String workerId = category + "-" + i;
            statuses.put(workerId, new WorkerStatus(workerId, category, false, null));
            pool.submit(() -> workerLoop(workerId, category, modes));
        }
    }

    private void workerLoop(String workerId, String category, List<String> modes) {
        log.info("Worker {} started (modes={})", workerId, modes);
        while (running.get()) {
            try {
                Long scanId = scanResultRepo.claimNextPending(modes, workerId);
                if (scanId == null) {
                    Thread.sleep(pollIntervalMs);
                    continue;
                }
                statuses.put(workerId, new WorkerStatus(workerId, category, true, scanId));
                log.info("Worker {} claimed scan {}", workerId, scanId);
                try {
                    scanService.executeQueuedScan(scanId, workerId);
                } catch (Exception e) {
                    log.error("Worker {} failed executing scan {}: {}", workerId, scanId, e.getMessage(), e);
                } finally {
                    statuses.put(workerId, new WorkerStatus(workerId, category, false, null));
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                // Claim query itself failed (e.g. transient DB hiccup) — back off and retry.
                log.error("Worker {} poll failed: {}", workerId, e.getMessage(), e);
                try {
                    Thread.sleep(pollIntervalMs);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
    }

    @PreDestroy
    void stop() {
        running.set(false);
        pools.forEach(ExecutorService::shutdownNow);
    }
}
