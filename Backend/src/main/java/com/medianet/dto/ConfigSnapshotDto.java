package com.medianet.dto;

import java.time.LocalDateTime;
import java.util.List;

public record ConfigSnapshotDto(
        Long id,
        String status,
        LocalDateTime collectedAt,
        String summary,
        Integer criticalCount,
        Integer warningCount,
        Integer infoCount,
        List<String> driftChanges) {
}