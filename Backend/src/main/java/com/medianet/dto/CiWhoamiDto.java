package com.medianet.dto;

import java.util.List;

public record CiWhoamiDto(
        Long tokenId,
        String name,
        String tokenPrefix,
        Long clientId,
        List<Long> repositoryIds,
        List<String> scopes
) {
}
