package com.medianet.dto;

public record ServerDeploymentDto(
        Long id,
        Long serverId,
        String name,
        String deployPath,
        String domain,
        Long linkedRepositoryId,
        String deployBranch,
        String deployStrategy,
        Boolean autoDeployEnabled,
        String lastStatus,
        String lastCommitSha
) {
}
