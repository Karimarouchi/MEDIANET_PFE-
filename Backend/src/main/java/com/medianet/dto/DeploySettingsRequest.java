package com.medianet.dto;

public record DeploySettingsRequest(
        String deployPath,
        String domain,
        Long linkedRepositoryId,
        String deployBranch
) {
}
