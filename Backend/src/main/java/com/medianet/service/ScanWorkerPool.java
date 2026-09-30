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

    @PostConstruct
    void start() {
        startCategory("ssl", sslWorkers);
        startCategory("code", codeWorkers);
        startCategory("image", imageWorkers);
        log.info("ScanWorkerPool started: ssl={} code={} image={} (poll every {}ms)",
                sslWorkers, codeWorkers, imageWorkers, pollIntervalMs);
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
