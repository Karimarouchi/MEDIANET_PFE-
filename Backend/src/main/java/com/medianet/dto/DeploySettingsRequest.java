package com.medianet.dto;

public record DeploySettingsRequest(
        String name,
        String deployPath,
        String domain,
        Long linkedRepositoryId,
        String deployBranch,
        String deployStrategy,
        String healthUrl,
        Boolean backupEnabled,
        String backupService,
        Boolean approvalRequired
) {
    /** Older clients send six fields. */
    public DeploySettingsRequest(String name, String deployPath, String domain, Long linkedRepositoryId,
            String deployBranch, String deployStrategy) {
        this(name, deployPath, domain, linkedRepositoryId, deployBranch, deployStrategy, null, null, null, null);
    }
}
