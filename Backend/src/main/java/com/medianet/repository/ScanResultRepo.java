package com.medianet.repository;

import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ScanResultRepo extends JpaRepository<ScanResult, Long> {
    List<ScanResult> findByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    List<ScanResult> findByRepositoryIdInOrderByStartedAtDesc(java.util.Collection<Long> repositoryIds);

    List<ScanResult> findAllByOrderByStartedAtDesc();

    List<ScanResult> findAllByRepositoryOwnerLoginOrderByStartedAtDesc(String ownerLogin);

    ScanResult findFirstByRepositoryIdOrderByStartedAtDesc(Long repositoryId);

    ScanResult findFirstByRepositoryIdAndStatusOrderByStartedAtDesc(Long repositoryId, ScanStatus status);

    boolean existsByRepositoryIdAndStatusIn(Long repositoryId, java.util.Collection<ScanStatus> statuses);

    Optional<ScanResult> findFirstByRepository_IdAndCommitShaIgnoreCaseAndStatusInOrderByStartedAtDesc(
            Long repositoryId, String commitSha, java.util.Collection<ScanStatus> statuses);

    Optional<ScanResult> findFirstByRepository_IdAndCommitShaIgnoreCaseOrderByStartedAtDesc(
            Long repositoryId, String commitSha);

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository r LEFT JOIN FETCH r.ownerUser WHERE s.id = :id")
    Optional<ScanResult> findByIdWithRepository(@Param("id") Long id);

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository ORDER BY s.startedAt DESC")
    List<ScanResult> findAllWithRepositoryOrderByStartedAtDesc();

    @Query("SELECT s FROM ScanResult s LEFT JOIN FETCH s.repository r WHERE r.id IN :repoIds ORDER BY s.startedAt DESC")
    List<ScanResult> findByRepositoryIdInWithRepositoryOrderByStartedAtDesc(
            @Param("repoIds") java.util.Collection<Long> repoIds);

    @Query("""
            SELECT s FROM ScanResult s
            LEFT JOIN FETCH s.repository r
            WHERE s.status IN :statuses
              AND (
                    s.finishedAt >= :since
                    OR (s.finishedAt IS NULL AND s.startedAt >= :since)
                  )
            ORDER BY s.startedAt DESC
            """)
    List<ScanResult> findRecentTerminalScans(
            @Param("statuses") java.util.Collection<ScanStatus> statuses,
            @Param("since") java.time.LocalDateTime since);

    @Query("""
            SELECT s FROM ScanResult s
            JOIN FETCH s.repository
            WHERE s.status = :status
              AND s.startedAt = (
                    SELECT MAX(s2.startedAt) FROM ScanResult s2
                    WHERE s2.repository.id = s.repository.id
                      AND s2.status = :status
              )
            """)
    List<ScanResult> findLatestByStatusPerRepository(@Param("status") ScanStatus status);

    /**
     * Atomically claims the oldest PENDING scan matching one of {@code modes} for
     * {@code workerId} — PostgreSQL's SELECT ... FOR UPDATE SKIP LOCKED pattern.
     * Safe under concurrent callers (multiple worker threads, or later multiple
     * backend instances pointed at the same DB) — never claims the same row twice.
     * Returns the claimed scan's id, or null if no PENDING scan matches.
     */
    @Query(value = """
            UPDATE scan_results SET status = 'RUNNING', worker_id = :workerId
            WHERE id = (
                SELECT id FROM scan_results
                WHERE status = 'PENDING' AND scan_mode IN (:modes)
                ORDER BY started_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            RETURNING id
            """, nativeQuery = true)
    Long claimNextPending(@Param("modes") List<String> modes, @Param("workerId") String workerId);

    /** All completed scans, grouped implicitly by repo when iterated (used by RemediationLabelService). */
    List<ScanResult> findByStatusOrderByRepository_IdAscStartedAtAsc(ScanStatus status);
}
