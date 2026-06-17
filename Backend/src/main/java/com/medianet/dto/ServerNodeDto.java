package com.medianet.dto;

import java.time.LocalDateTime;
import java.util.List;

public record ServerNodeDto(
        Long id,
        String name,
        String host,
        Integer port,
        String username,
        String nodeType,
        String environment,
        String templateKey,
        String owner,
        String clientName,
        String projectName,
        String runbookUrl,
        List<String> tags,
        String notes,
        String description,
        LocalDateTime lastScannedAt,
        String latestStatus,
        Integer criticalCount,
        Integer warningCount,
        Integer infoCount,
        String osName,
        String kernelVersion,
        String firewallStatus) {
}