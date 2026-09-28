package com.medianet.dto;

import java.util.List;

/**
 * One ranked attack path: an entry point (secret or CVE) reaching a
 * critical server, plus any hardening findings that amplify it.
 */
public record AttackPathDto(
        String id,
        List<String> nodeIds,
        double score,
        String narrative) {
}
