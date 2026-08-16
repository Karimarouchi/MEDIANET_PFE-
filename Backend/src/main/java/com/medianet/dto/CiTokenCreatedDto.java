package com.medianet.dto;

import java.time.Instant;
import java.util.List;

/**
 * Returned only from POST /api/admin/ci-tokens. {@code token} is the plaintext secret,
 * shown once; it is never persisted or listed afterwards.
 */
public record CiTokenCreatedDto(
        Long id,
        String name,
        String token,
        String tokenPrefix,
        Long clientId,
        String clientName,
        List<Long> repositoryIds,
        List<String> repositoryUrls,
        List<String> scopes,
        Instant expiresAt,
        Instant createdAt
) {
}
