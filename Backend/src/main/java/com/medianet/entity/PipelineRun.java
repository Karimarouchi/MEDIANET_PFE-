package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "pipeline_runs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PipelineRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "pipeline_id", nullable = false)
    private PipelineDefinition pipeline;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "triggered_by_id")
    private User triggeredBy;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private PipelineExecutionStatus status;

    @Enumerated(EnumType.STRING)
    private PipelineStageType currentStage;

    @Builder.Default
    @Column(nullable = false)
    private Boolean approvalRequired = false;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "approved_by_id")
    private User approvedBy;

    private LocalDateTime approvedAt;
    private LocalDateTime startedAt;
    private LocalDateTime finishedAt;

    private Long securityScanId;

    @Column(columnDefinition = "TEXT")
    private String summary;

    @Builder.Default
    @OneToMany(mappedBy = "pipelineRun", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("stageOrder ASC")
    private List<PipelineStageRun> stageRuns = new ArrayList<>();
}