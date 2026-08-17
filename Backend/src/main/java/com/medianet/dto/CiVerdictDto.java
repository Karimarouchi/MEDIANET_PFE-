package com.medianet.dto;

import java.util.List;

public record CiVerdictDto(
        String verdict,
        String reason,
        String commitSha,
        Long scanId,
        Long repoId,
        List<CiVerdictFindingDto> blocking,
        List<CiVerdictFindingDto> ignored,
        String reportUrl
) {
}
