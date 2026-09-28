package com.medianet.dto;

import java.util.Map;

/**
 * A node in the attack graph: a repository, a secret, an RCE-capable CVE,
 * a server, or a hardening finding. {@code critical} marks a SERVER node
 * whose environment looks like production (the "asset" an attacker wants
 * to reach).
 */
public record AttackGraphNodeDto(
        String id,
        String type,
        String label,
        String severity,
        boolean critical,
        Map<String, Object> meta) {
}
