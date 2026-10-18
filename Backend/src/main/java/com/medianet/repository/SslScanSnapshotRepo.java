package com.medianet.repository;

import com.medianet.entity.SslScanSnapshot;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SslScanSnapshotRepo extends JpaRepository<SslScanSnapshot, Long> {

    Optional<SslScanSnapshot> findByScanResultId(Long scanResultId);

    boolean existsByScanResultId(Long scanResultId);

    void deleteByScanResultId(Long scanResultId);

    /** Latest snapshot of a domain in a given state, e.g. COMPLETED. */
    Optional<SslScanSnapshot> findFirstByDomainIgnoreCaseAndScanStatusOrderByCreatedAtDesc(String domain, String scanStatus);
}
