package com.medianet.dto;

public record CiVerdictFindingDto(
        String cveId,
        String severity,
        String packageName,
        String packageVersion,
        boolean justified,
        String reason
) {
}
