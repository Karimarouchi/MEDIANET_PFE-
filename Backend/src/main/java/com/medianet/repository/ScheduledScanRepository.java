package com.medianet.repository;

import com.medianet.entity.ScheduledScan;
import com.medianet.entity.ScheduledScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface ScheduledScanRepository extends JpaRepository<ScheduledScan, Long> {

    List<ScheduledScan> findByRepositoryIdOrderByCreatedAtDesc(Long repositoryId);

    List<ScheduledScan> findAllByOrderByCreatedAtDesc();

    /** Returns all enabled ACTIVE scheduled scans whose nextRunAt is due */
    @Query("SELECT s FROM ScheduledScan s WHERE s.enabled = true AND s.status = :status AND s.nextRunAt <= :now")
    List<ScheduledScan> findDueScans(@Param("status") ScheduledScanStatus status, @Param("now") Instant now);

    /** Returns ACTIVE scans for a repository (for badge display) */
    List<ScheduledScan> findByRepositoryIdAndEnabledTrueAndStatusIn(
        Long repositoryId, java.util.Collection<ScheduledScanStatus> statuses);
}
