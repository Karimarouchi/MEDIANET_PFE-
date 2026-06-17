package com.medianet.dto;

import java.util.List;

public record PipelinePresetDto(
        String name,
        String description,
        String repoUrl,
        String branch,
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
        String imagePrefix,
        String dockerHubUsername,
        List<String> detectedComponents,
        String summary) {
}