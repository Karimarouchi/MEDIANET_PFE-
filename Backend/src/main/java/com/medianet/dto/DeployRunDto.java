package com.medianet.dto;

import java.time.LocalDateTime;
import java.util.List;

public record DeployRunDto(
        Long id,
        Long serverId,
        String commitSha,
        String verdict,
        String status,
        String triggerType,
        String log,
        LocalDateTime startedAt,
        LocalDateTime finishedAt,
        boolean blocked,
        List<CiVerdictFindingDto> blocking
) {
}
