package com.medianet.dto;

import java.time.Instant;
import java.util.List;

public record CiTokenDto(
        Long id,
        String name,
        String tokenPrefix,
        Long clientId,
        String clientName,
        List<Long> repositoryIds,
        List<String> repositoryUrls,
        List<String> scopes,
        Instant expiresAt,
        Instant lastUsedAt,
        Instant revokedAt,
        Instant createdAt,
        boolean active,
        boolean revealable
) {
}
