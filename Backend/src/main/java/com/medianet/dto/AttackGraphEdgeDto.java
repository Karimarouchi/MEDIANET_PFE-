package com.medianet.dto;

/**
 * A directed relationship in the attack graph.
 * kind: CONTAINS (repo owns a finding, weight 0, layout only),
 * DEPLOYS (repo runs on server, weight 0, layout only),
 * SECRET_ACCESS (an exposed secret grants access to a server),
 * RCE_CVE (a remote-code-execution-capable CVE compromises a server),
 * HARDENING_AMPLIFIER (a weak server config makes an existing compromise worse).
 */
public record AttackGraphEdgeDto(
        String id,
        String source,
        String target,
        String kind,
        double weight,
        String label) {
}
