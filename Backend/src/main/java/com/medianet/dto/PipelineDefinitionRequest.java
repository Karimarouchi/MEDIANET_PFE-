package com.medianet.dto;

public record PipelineDefinitionRequest(
        String name,
        String description,
        Long repositoryId,
        String repoUrl,
        String branch,
        Long runnerServerId,
        Long stagingServerId,
        Long productionServerId,
        String workspacePath,
        String buildCommand,
        String testCommand,
        String dockerBuildCommand,
        String containerScanCommand,
        String stagingDeployCommand,
        String dastCommand,
        String productionDeployCommand,
        Boolean approvalRequired,
        Boolean failOnCritical,
        Boolean failOnSecrets,
        Boolean active) {
}