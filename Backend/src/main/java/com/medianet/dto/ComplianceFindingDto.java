package com.medianet.dto;

import lombok.*;

/**
 * Idée 2 — OpenSCAP compliance rule result.
 * Represents one rule evaluated by OpenSCAP during a compliance scan.
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ComplianceFindingDto {

    /**
     * Rule ID from SCAP content (e.g.
     * "xccdf_org.ssgproject.content_rule_no_empty_passwords")
     */
    private String ruleId;

    /** Human-readable title of the rule */
    private String title;

    /** Result: "pass", "fail", "notapplicable", "notchecked", "error" */
    private String result;

    /** Severity: "high", "medium", "low", "informational" */
    private String severity;

    /** Short description of what the rule checks */
    private String description;

    /** Compliance profile name (e.g. "CIS_L1", "NIST_800-53") */
    private String profile;
}
