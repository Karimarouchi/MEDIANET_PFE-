package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "pipeline_stage_runs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PipelineStageRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "pipeline_run_id", nullable = false)
    private PipelineRun pipelineRun;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private PipelineStageType stageType;

    @Column(nullable = false)
    private Integer stageOrder;

    @Column(nullable = false, length = 120)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PipelineExecutionStatus status;

    private LocalDateTime startedAt;
    private LocalDateTime finishedAt;

    private Long relatedScanId;

    @Column(columnDefinition = "TEXT")
    private String details;

    @Column(columnDefinition = "TEXT")
    private String logOutput;

    @PrePersist
    protected void onCreate() {
        if (status == null) {
            status = PipelineExecutionStatus.PENDING;
        }
    }
}