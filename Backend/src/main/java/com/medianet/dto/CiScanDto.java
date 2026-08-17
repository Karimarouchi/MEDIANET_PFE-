package com.medianet.dto;

import java.util.List;

public record CiScanDto(
        Long scanId,
        Long repoId,
        String commitSha,
        String status,
        boolean reused,
        Integer cveCount
) {
}
