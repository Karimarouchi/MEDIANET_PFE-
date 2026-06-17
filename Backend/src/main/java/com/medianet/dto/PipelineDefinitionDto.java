package com.medianet.dto;

import java.time.LocalDateTime;

public record PipelineDefinitionDto(
        Long id,
        String name,
        String description,
        Long repositoryId,
        String repositoryLabel,
        String repoUrl,
        String branch,
        String sourceProvider,
        Long runnerServerId,
        String runnerServerName,
        Long stagingServerId,
        String stagingServerName,
        Long productionServerId,
        String productionServerName,
        String workspacePath,
        String buildCommand,
        String testCommand,
        String dockerBuildCommand,
        String containerScanCommand,
        String stagingDeployCommand,
        String dastCommand,
        String productionDeployCommand,
        boolean approvalRequired,
        boolean failOnCritical,
        boolean failOnSecrets,
        boolean active,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        LocalDateTime lastRunAt,
        PipelineRunDto lastRun,
        // Security gate info
        String securityScanStatus,   // null | PENDING | RUNNING | COMPLETED | FAILED
        Long criticalCveCount,       // null si pas de scan complété
        Long scanResultId) {         // null si pas de scan
}
