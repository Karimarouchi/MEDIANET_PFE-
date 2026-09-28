package com.medianet.dto;

import java.util.List;

public record AttackGraphResponseDto(
        List<AttackGraphNodeDto> nodes,
        List<AttackGraphEdgeDto> edges) {
}
