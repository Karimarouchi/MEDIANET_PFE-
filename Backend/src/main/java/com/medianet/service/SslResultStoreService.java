package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.SslResultDto;
import com.medianet.entity.ScanResult;
import com.medianet.entity.SslScanSnapshot;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.SslScanSnapshotRepo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Optional;

/**
 * Persists the full SSL result DTO in PostgreSQL and frees disk by deleting the scan folder.
 *
 * Fields covered (via JSON): all SslResultDto properties including nested
 * tlsProtocols[], certificateDetail (SANs, chain, OCSP, CT, trust stores, ciphers…).
 */
@Service
public class SslResultStoreService {

    private static final Logger log = LoggerFactory.getLogger(SslResultStoreService.class);

    private final SslScanSnapshotRepo snapshotRepo;
    private final ScanResultRepo scanResultRepo;
    private final ObjectMapper objectMapper;

    public SslResultStoreService(SslScanSnapshotRepo snapshotRepo, ScanResultRepo scanResultRepo,
            ObjectMapper objectMapper) {
        this.snapshotRepo = snapshotRepo;
        this.scanResultRepo = scanResultRepo;
        this.objectMapper = objectMapper;
    }

    public Optional<SslResultDto> findStored(Long scanId) {
        return snapshotRepo.findByScanResultId(scanId).map(snap -> {
            try {
                return objectMapper.readValue(snap.getResultJson(), SslResultDto.class);
            } catch (Exception e) {
                log.warn("Failed to deserialize SSL snapshot for scan {}: {}", scanId, e.getMessage());
                return null;
            }
        }).filter(dto -> dto != null);
    }

    public boolean hasStored(Long scanId) {
        return snapshotRepo.existsByScanResultId(scanId);
    }

    /**
     * Upsert full DTO. Optionally delete on-disk results directory to free space
     * (only when external async sources are finished — SSL Labs / Censys).
     */
    @Transactional
    public void persist(ScanResult scan, SslResultDto dto, boolean cleanupDisk) {
        if (scan == null || scan.getId() == null || dto == null) {
            return;
        }
        try {
            String json = objectMapper.writeValueAsString(dto);
            SslScanSnapshot snap = snapshotRepo.findByScanResultId(scan.getId())
                    .orElse(SslScanSnapshot.builder().scanResultId(scan.getId()).build());
            snap.setDomain(dto.getDomain());
            snap.setGrade(dto.getGrade());
            snap.setCombinedGrade(dto.getCombinedGrade());
            snap.setScanStatus(dto.getScanStatus());
            snap.setResultJson(json);
            snapshotRepo.save(snap);

            if (!cleanupDisk) {
                log.info("[SSL] Snapshot saved for scan {} (disk kept — waiting for async sources)", scan.getId());
                return;
            }

            String dir = scan.getResultsDir();
            if (dir != null && !dir.isBlank() && !dir.startsWith("db://")) {
                deleteDirectoryQuietly(Path.of(dir));
                scan.setResultsDir("db://ssl/" + scan.getId());
                scanResultRepo.save(scan);
                log.info("[SSL] Snapshot saved for scan {} — disk folder removed ({})", scan.getId(), dir);
            } else {
                log.info("[SSL] Snapshot saved for scan {} (no disk folder to remove)", scan.getId());
            }
        } catch (Exception e) {
            log.error("[SSL] Failed to persist snapshot for scan {}: {}", scan.getId(), e.getMessage());
        }
    }

    private void deleteDirectoryQuietly(Path root) {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.deleteIfExists(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.deleteIfExists(dir);
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (Exception e) {
            log.warn("[SSL] Could not fully delete {}: {}", root, e.getMessage());
        }
    }
}
