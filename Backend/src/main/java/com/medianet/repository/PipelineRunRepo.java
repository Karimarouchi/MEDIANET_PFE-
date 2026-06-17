package com.medianet.repository;

import com.medianet.entity.PipelineExecutionStatus;
import com.medianet.entity.PipelineRun;
import com.medianet.entity.PipelineStageType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface PipelineRunRepo extends JpaRepository<PipelineRun, Long> {
    List<PipelineRun> findByPipelineIdOrderByStartedAtDesc(Long pipelineId);

    PipelineRun findFirstByPipelineIdOrderByStartedAtDesc(Long pipelineId);

    boolean existsByPipelineIdAndStatusIn(Long pipelineId, Collection<PipelineExecutionStatus> statuses);

    /**
     * Eagerly loads all lazy associations needed by the async executor thread.
     * Prevents LazyInitializationException outside a JPA session.
     */
    @Query("SELECT r FROM PipelineRun r " +
           "LEFT JOIN FETCH r.pipeline p " +
           "LEFT JOIN FETCH p.runnerServer " +
           "LEFT JOIN FETCH p.stagingServer " +
           "LEFT JOIN FETCH p.productionServer " +
           "LEFT JOIN FETCH r.triggeredBy " +
           "WHERE r.id = :id")
    Optional<PipelineRun> findByIdEager(@Param("id") Long id);

    // ---- Safe update queries for the async executor thread ----
    // These avoid save(entity) which would cascade to uninitialized OneToMany collections.

    @Modifying
    @Transactional
    @Query("UPDATE PipelineRun r SET r.status = :status WHERE r.id = :id")
    void setStatus(@Param("id") Long id, @Param("status") PipelineExecutionStatus status);

    @Modifying
    @Transactional
    @Query("UPDATE PipelineRun r SET r.currentStage = :stage WHERE r.id = :id")
    void setCurrentStage(@Param("id") Long id, @Param("stage") PipelineStageType stage);

    @Modifying
    @Transactional
    @Query("UPDATE PipelineRun r SET r.status = :status, r.currentStage = :stage, r.summary = :summary WHERE r.id = :id")
    void setStatusStageAndSummary(@Param("id") Long id,
                                  @Param("status") PipelineExecutionStatus status,
                                  @Param("stage") PipelineStageType stage,
                                  @Param("summary") String summary);

    @Modifying
    @Transactional
    @Query("UPDATE PipelineRun r SET r.status = :status, r.currentStage = :stage, r.finishedAt = :finishedAt, r.summary = :summary WHERE r.id = :id")
    void finishRun(@Param("id") Long id,
                   @Param("status") PipelineExecutionStatus status,
                   @Param("stage") PipelineStageType stage,
                   @Param("finishedAt") LocalDateTime finishedAt,
                   @Param("summary") String summary);

    @Modifying
    @Transactional
    @Query("UPDATE PipelineRun r SET r.securityScanId = :scanId WHERE r.id = :id")
    void setSecurityScanId(@Param("id") Long id, @Param("scanId") Long scanId);
}