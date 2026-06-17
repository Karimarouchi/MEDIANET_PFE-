package com.medianet.repository;

import com.medianet.entity.PipelineExecutionStatus;
import com.medianet.entity.PipelineStageRun;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

public interface PipelineStageRunRepo extends JpaRepository<PipelineStageRun, Long> {
    List<PipelineStageRun> findByPipelineRunIdOrderByStageOrderAsc(Long pipelineRunId);

    // ---- Safe update queries for the async executor thread ----

    @Modifying
    @Transactional
    @Query("UPDATE PipelineStageRun s SET s.status = :status, s.startedAt = :startedAt, s.finishedAt = NULL, s.details = NULL WHERE s.id = :id")
    void markRunning(@Param("id") Long id,
                     @Param("status") PipelineExecutionStatus status,
                     @Param("startedAt") LocalDateTime startedAt);

    @Modifying
    @Transactional
    @Query("UPDATE PipelineStageRun s SET s.status = :status, s.details = :details, s.logOutput = :logOutput, s.relatedScanId = :relatedScanId, s.finishedAt = :finishedAt WHERE s.id = :id")
    void markFinished(@Param("id") Long id,
                      @Param("status") PipelineExecutionStatus status,
                      @Param("details") String details,
                      @Param("logOutput") String logOutput,
                      @Param("relatedScanId") Long relatedScanId,
                      @Param("finishedAt") LocalDateTime finishedAt);
}