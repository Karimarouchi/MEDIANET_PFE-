package com.medianet.service;

import com.medianet.dto.ScheduledScanRequest;
import com.medianet.dto.ScheduledScanResponse;
import com.medianet.entity.*;
import com.medianet.repository.RepositoryRepo;
import com.medianet.repository.ScheduledScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.*;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class ScheduledScanService {

    private static final Logger log = LoggerFactory.getLogger(ScheduledScanService.class);

    private final ScheduledScanRepository scheduledScanRepo;
    private final RepositoryRepo repositoryRepo;

    public ScheduledScanService(ScheduledScanRepository scheduledScanRepo,
                                 RepositoryRepo repositoryRepo) {
        this.scheduledScanRepo = scheduledScanRepo;
        this.repositoryRepo = repositoryRepo;
    }

    // ── Create ────────────────────────────────────────────────────────────────

    public ScheduledScanResponse createScheduledScan(ScheduledScanRequest req, User currentUser) {
        // 1. Validate or create repository on the fly
        Repository repo;
        if (req.getRepositoryId() != null) {
            repo = repositoryRepo.findById(req.getRepositoryId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Repository introuvable : " + req.getRepositoryId()));
        } else {
            String repoUrl = req.getRepoUrl();
            if (repoUrl == null || repoUrl.isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "L'URL ou l'identifiant du repository est requis pour la planification.");
            }
            String ownerLogin = currentUser.getLogin();
            repo = repositoryRepo.findByRepoUrlAndOwnerLogin(repoUrl, ownerLogin)
                .orElseGet(() -> {
                    Repository r = Repository.builder()
                        .repoUrl(repoUrl)
                        .branch(req.getBranch() != null ? req.getBranch() : "main")
                        .scanMode(req.getScanMode() != null ? req.getScanMode() : "auto")
                        .targetDomain(req.getTargetDomain())
                        .ownerLogin(ownerLogin)
                        .ownerUser(currentUser)
                        .gitProvider(AuthProvider.GITHUB) // default
                        .build();
                    return repositoryRepo.save(r);
                });
        }

        if (repo.getOwnerUser() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Impossible de planifier ce scan : le repository n'a pas de propriétaire.");
        }

        // 2. Parse and convert startAt to UTC Instant
        ScheduleType scheduleType = parseScheduleType(req.getScheduleType());
        String timezone = req.getTimezone() != null && !req.getTimezone().isBlank()
            ? req.getTimezone() : "UTC";
        Instant startAt = parseStartAt(req.getStartAt(), timezone);

        // 3. Build entity
        ScheduledScan entity = ScheduledScan.builder()
            .repositoryId(repo.getId())
            .repositoryName(req.getRepositoryName() != null ? req.getRepositoryName() : repo.getRepoUrl())
            .repoUrl(req.getRepoUrl() != null ? req.getRepoUrl() : repo.getRepoUrl())
            .branch(req.getBranch() != null ? req.getBranch() : repo.getBranch())
            .scanMode(req.getScanMode() != null ? req.getScanMode() : "auto")
            .targetDomain(req.getTargetDomain())
            .dastTargetUrl(req.getDastTargetUrl())
            .scheduleType(scheduleType)
            .startAt(startAt)
            .nextRunAt(startAt)
            .timezone(timezone)
            .status(ScheduledScanStatus.ACTIVE)
            .enabled(true)
            .build();

        entity = scheduledScanRepo.save(entity);
        log.info("[SCHEDULED_SCAN] Created: id={}, repo={}, type={}, nextRun={}",
            entity.getId(), entity.getRepositoryName(), entity.getScheduleType(), entity.getNextRunAt());
        return toResponse(entity);
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    public List<ScheduledScanResponse> listAll() {
        return scheduledScanRepo.findAllByOrderByCreatedAtDesc()
            .stream().map(this::toResponse).collect(Collectors.toList());
    }

    public List<ScheduledScanResponse> listByRepository(Long repositoryId) {
        return scheduledScanRepo.findByRepositoryIdOrderByCreatedAtDesc(repositoryId)
            .stream().map(this::toResponse).collect(Collectors.toList());
    }

    // ── Update ────────────────────────────────────────────────────────────────

    public ScheduledScanResponse updateScheduledScan(Long id, ScheduledScanRequest req) {
        ScheduledScan entity = findOrThrow(id);

        if (req.getBranch() != null) entity.setBranch(req.getBranch());
        if (req.getScanMode() != null) entity.setScanMode(req.getScanMode());
        if (req.getTargetDomain() != null) entity.setTargetDomain(req.getTargetDomain());
        if (req.getDastTargetUrl() != null) entity.setDastTargetUrl(req.getDastTargetUrl());
        if (req.getRepositoryName() != null) entity.setRepositoryName(req.getRepositoryName());

        if (req.getScheduleType() != null) {
            entity.setScheduleType(parseScheduleType(req.getScheduleType()));
        }
        if (req.getStartAt() != null) {
            String tz = req.getTimezone() != null ? req.getTimezone() : entity.getTimezone();
            Instant newStart = parseStartAt(req.getStartAt(), tz);
            entity.setStartAt(newStart);
            entity.setNextRunAt(newStart);
        }
        if (req.getTimezone() != null) entity.setTimezone(req.getTimezone());

        entity = scheduledScanRepo.save(entity);
        return toResponse(entity);
    }

    // ── Pause / Resume ────────────────────────────────────────────────────────

    public ScheduledScanResponse pause(Long id) {
        ScheduledScan entity = findOrThrow(id);
        entity.setStatus(ScheduledScanStatus.PAUSED);
        entity.setEnabled(false);
        return toResponse(scheduledScanRepo.save(entity));
    }

    public ScheduledScanResponse resume(Long id) {
        ScheduledScan entity = findOrThrow(id);
        entity.setStatus(ScheduledScanStatus.ACTIVE);
        entity.setEnabled(true);
        return toResponse(scheduledScanRepo.save(entity));
    }

    // ── Delete ────────────────────────────────────────────────────────────────

    public void delete(Long id) {
        ScheduledScan entity = findOrThrow(id);
        scheduledScanRepo.delete(entity);
    }

    // ── Scheduled execution helpers ───────────────────────────────────────────

    /**
     * Called by ScheduledScanRunner after a successful scan.
     * Updates lastRunAt, runCount, lastScanId, and calculates nextRunAt.
     */
    public void onScanSuccess(ScheduledScan entity, Long scanId) {
        Instant now = Instant.now();
        entity.setLastRunAt(now);
        entity.setRunCount(entity.getRunCount() + 1);
        entity.setLastScanId(scanId);
        entity.setLastError(null);

        if (entity.getScheduleType() == ScheduleType.ONCE) {
            entity.setStatus(ScheduledScanStatus.COMPLETED);
            entity.setEnabled(false);
            log.info("[SCHEDULED_SCAN] ONCE scan completed: id={}", entity.getId());
        } else {
            Instant next = calculateNextRunAt(entity.getScheduleType(), now);
            entity.setNextRunAt(next);
            entity.setStatus(ScheduledScanStatus.ACTIVE);
            log.info("[SCHEDULED_SCAN] Next run scheduled at: {} for id={}", next, entity.getId());
        }
        scheduledScanRepo.save(entity);
    }

    /**
     * Called by ScheduledScanRunner when a scan is skipped because one is already running.
     * Postpones 10 minutes, keeps ACTIVE.
     */
    public void onScanPostponed(ScheduledScan entity, String reason) {
        Instant retryAt = Instant.now().plusSeconds(600); // +10 minutes
        entity.setNextRunAt(retryAt);
        entity.setStatus(ScheduledScanStatus.ACTIVE);
        entity.setLastError(reason);
        scheduledScanRepo.save(entity);
        log.info("[SCHEDULED_SCAN] Postponed by 10 min: id={}, reason={}", entity.getId(), reason);
    }

    /**
     * Called by ScheduledScanRunner on technical error.
     * ONCE → FAILED/disabled. Recurring → ACTIVE with next occurrence.
     */
    public void onScanError(ScheduledScan entity, String errorMessage, boolean critical) {
        entity.setLastError(errorMessage);

        if (critical || entity.getScheduleType() == ScheduleType.ONCE) {
            entity.setStatus(ScheduledScanStatus.FAILED);
            entity.setEnabled(false);
            log.error("[SCHEDULED_SCAN] FAILED (critical): id={}, error={}", entity.getId(), errorMessage);
        } else {
            // Recurring: keep active, just update nextRunAt to next normal occurrence
            Instant next = calculateNextRunAt(entity.getScheduleType(), Instant.now());
            entity.setNextRunAt(next);
            entity.setStatus(ScheduledScanStatus.ACTIVE);
            log.warn("[SCHEDULED_SCAN] Error (non-critical), will retry at {}: id={}, error={}",
                next, entity.getId(), errorMessage);
        }
        scheduledScanRepo.save(entity);
    }

    /** Mark as RUNNING before starting (double-launch protection) */
    public void markRunning(ScheduledScan entity) {
        entity.setStatus(ScheduledScanStatus.RUNNING);
        scheduledScanRepo.save(entity);
    }

    // ── Summary for repository cards ──────────────────────────────────────────

    /**
     * Returns the next active scheduled scan for each repository.
     * Key = repositoryId, Value = next scheduled scan response.
     */
    public java.util.Map<Long, ScheduledScanResponse> getScheduledSummaryByRepository() {
        List<ScheduledScan> active = scheduledScanRepo.findAll().stream()
            .filter(s -> s.isEnabled() &&
                (s.getStatus() == ScheduledScanStatus.ACTIVE ||
                 s.getStatus() == ScheduledScanStatus.RUNNING))
            .collect(Collectors.toList());

        java.util.Map<Long, ScheduledScan> byRepo = new java.util.HashMap<>();
        for (ScheduledScan s : active) {
            byRepo.merge(s.getRepositoryId(), s, (a, b) ->
                a.getNextRunAt().isBefore(b.getNextRunAt()) ? a : b);
        }
        java.util.Map<Long, ScheduledScanResponse> result = new java.util.HashMap<>();
        byRepo.forEach((repoId, scan) -> result.put(repoId, toResponse(scan)));
        return result;
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private ScheduledScan findOrThrow(Long id) {
        return scheduledScanRepo.findById(id)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                "Planification introuvable : " + id));
    }

    public static Instant parseStartAt(String startAt, String timezone) {
        try {
            ZoneId zone = ZoneId.of(timezone);
            LocalDateTime ldt = LocalDateTime.parse(startAt);
            return ldt.atZone(zone).toInstant();
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Format de date invalide. Attendu: yyyy-MM-ddTHH:mm:ss. Reçu: " + startAt);
        }
    }

    public static ScheduleType parseScheduleType(String type) {
        try {
            return ScheduleType.valueOf(type.toUpperCase());
        } catch (Exception e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "scheduleType invalide: " + type + ". Valeurs: ONCE, WEEKLY, EVERY_15_DAYS, MONTHLY");
        }
    }

    public static Instant calculateNextRunAt(ScheduleType type, Instant from) {
        return switch (type) {
            case WEEKLY -> from.plus(java.time.Duration.ofDays(7));
            case EVERY_15_DAYS -> from.plus(java.time.Duration.ofDays(15));
            case MONTHLY -> from.atZone(ZoneOffset.UTC).plusMonths(1).toInstant();
            case ONCE -> from; // should not be called for ONCE
        };
    }

    private ScheduledScanResponse toResponse(ScheduledScan e) {
        return ScheduledScanResponse.builder()
            .id(e.getId())
            .repositoryId(e.getRepositoryId())
            .repositoryName(e.getRepositoryName())
            .repoUrl(e.getRepoUrl())
            .branch(e.getBranch())
            .scanMode(e.getScanMode())
            .targetDomain(e.getTargetDomain())
            .dastTargetUrl(e.getDastTargetUrl())
            .scheduleType(e.getScheduleType().name())
            .startAt(e.getStartAt())
            .nextRunAt(e.getNextRunAt())
            .lastRunAt(e.getLastRunAt())
            .timezone(e.getTimezone())
            .status(e.getStatus().name())
            .enabled(e.isEnabled())
            .runCount(e.getRunCount())
            .lastScanId(e.getLastScanId())
            .lastError(e.getLastError())
            .createdAt(e.getCreatedAt())
            .updatedAt(e.getUpdatedAt())
            .build();
    }
}
