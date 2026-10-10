package com.medianet.service;

import com.medianet.entity.SecretFinding;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AttackGraphSecretFilterTest {

    private static SecretFinding s(String model, String analyst) {
        return SecretFinding.builder().mlVerdict(model).analystVerdict(analyst).build();
    }

    private static SecretFinding inScope(String scope, String analyst) {
        return SecretFinding.builder().mlVerdict("LIKELY_REAL").mlScope(scope).analystVerdict(analyst).build();
    }

    @Test
    void testAndDocSecretsAreNotEntryPointsUnlessConfirmed() {
        assertThat(AttackGraphService.isNotAnEntryPoint(inScope("TEST_OR_DOC", null))).isTrue();
        assertThat(AttackGraphService.isNotAnEntryPoint(inScope("TEST_OR_DOC", "REAL"))).isFalse();
        assertThat(AttackGraphService.isNotAnEntryPoint(inScope("PRODUCTION", null))).isFalse();
    }

    @Test
    void probableFalsePositivesAreNotEntryPoints() {
        assertThat(AttackGraphService.isNotAnEntryPoint(s("LIKELY_FALSE_POSITIVE", null))).isTrue();
        assertThat(AttackGraphService.isNotAnEntryPoint(s("LIKELY_REAL", null))).isFalse();
        assertThat(AttackGraphService.isNotAnEntryPoint(s("REVIEW", null))).isFalse();
        assertThat(AttackGraphService.isNotAnEntryPoint(s(null, null))).isFalse(); // untriaged stays on the map
    }

    @Test
    void theAnalystOverridesTheModel() {
        assertThat(AttackGraphService.isNotAnEntryPoint(s("LIKELY_FALSE_POSITIVE", "REAL"))).isFalse();
        assertThat(AttackGraphService.isNotAnEntryPoint(s("LIKELY_REAL", "FALSE_POSITIVE"))).isTrue();
    }
}
