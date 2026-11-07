package com.medianet.service;

import com.medianet.entity.ConfigFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigGatePolicyTest {

    private static ConfigFinding finding(String severity, String category) {
        return ConfigFinding.builder().severity(severity).category(category).build();
    }

    @Test
    void byDefaultNothingBlocks() {
        ConfigGatePolicy policy = new ConfigGatePolicy("", "");
        assertFalse(policy.blocks(finding("CRITICAL", "KUBERNETES")));
        assertFalse(policy.blocks(finding("HIGH", "DOCKERFILE")));
        assertTrue(policy.blocking(List.of(finding("HIGH", "TERRAFORM"))).isEmpty());
        assertFalse(policy.blocks(null));
    }

    @Test
    void severityRuleBlocksOnlyThoseSeverities() {
        ConfigGatePolicy policy = new ConfigGatePolicy("high, critical", "");
        assertTrue(policy.blocks(finding("HIGH", "DOCKERFILE")));
        assertTrue(policy.blocks(finding("CRITICAL", "TERRAFORM")));
        assertFalse(policy.blocks(finding("MEDIUM", "DOCKERFILE")));
        assertFalse(policy.blocks(finding("UNKNOWN", "DOCKERFILE")));
    }

    @Test
    void categoryRuleNarrowsTheSeverityRule() {
        ConfigGatePolicy policy = new ConfigGatePolicy("HIGH", "KUBERNETES");
        assertTrue(policy.blocks(finding("HIGH", "KUBERNETES")));
        assertFalse(policy.blocks(finding("HIGH", "DOCKERFILE")));
        assertEquals(1, policy.blocking(List.of(finding("HIGH", "KUBERNETES"), finding("HIGH", "TERRAFORM"))).size());
    }

    @Test
    void aCategoryAloneNeverBlocks() {
        assertFalse(new ConfigGatePolicy("", "KUBERNETES").blocks(finding("CRITICAL", "KUBERNETES")));
    }
}
