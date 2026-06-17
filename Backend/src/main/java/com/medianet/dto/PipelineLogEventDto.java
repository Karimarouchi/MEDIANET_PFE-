package com.medianet.dto;

import java.time.LocalDateTime;

public record PipelineLogEventDto(
        String type,
        Long runId,
        Long stageId,
        String stageType,
        String message,
        PipelineRunDto run,
        LocalDateTime timestamp) {
}