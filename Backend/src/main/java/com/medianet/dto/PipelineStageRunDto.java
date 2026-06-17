package com.medianet.dto;

import java.time.LocalDateTime;

public record PipelineStageRunDto(
        Long id,
        String stageType,
        String title,
        Integer stageOrder,
        String status,
        String details,
        String logOutput,
        Long relatedScanId,
        LocalDateTime startedAt,
        LocalDateTime finishedAt) {
}