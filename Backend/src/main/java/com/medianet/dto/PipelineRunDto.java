package com.medianet.dto;

import java.time.LocalDateTime;
import java.util.List;

public record PipelineRunDto(
        Long id,
        Long pipelineId,
        String pipelineName,
        String status,
        String currentStage,
        boolean approvalRequired,
        Long securityScanId,
        String summary,
        String triggeredByLogin,
        String approvedByLogin,
        LocalDateTime startedAt,
        LocalDateTime finishedAt,
        LocalDateTime approvedAt,
        List<PipelineStageRunDto> stages) {
}