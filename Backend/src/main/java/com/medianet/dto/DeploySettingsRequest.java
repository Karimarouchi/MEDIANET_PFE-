package com.medianet.dto;

public record DeploySettingsRequest(
        String name,
        String deployPath,
        String domain,
        Long linkedRepositoryId,
        String deployBranch,
        String deployStrategy
) {
}
