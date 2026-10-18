package com.medianet.service;

import com.medianet.entity.SecretFinding;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SecretVerdictCarryOverTest {

    private static SecretFinding secret(String rule, String file, int line, String raw, String verdict) {
        SecretFinding s = new SecretFinding();
        s.setRuleId(rule);
        s.setFile(file);
        s.setStartLine(line);
        s.setRawSecret(raw);
        s.setAnalystVerdict(verdict);
        return s;
    }

    @Test
    void sameSecretKeepsTheLatestVerdictEvenWhenItsLineMoved() {
        SecretFinding moved = secret("Token", "ml/data.csv", 40, "abc123", null);
        SecretFinding other = secret("Token", "ml/data.csv", 41, "zzz999", null);
        int copied = SecretVerdictCarryOver.apply(List.of(moved, other), List.of(
                secret("Token", "ml/data.csv", 12, "abc123", "FALSE_POSITIVE"), // newest scan
                secret("Token", "ml/data.csv", 12, "abc123", "REAL")));         // older decision, overridden
        assertThat(copied).isEqualTo(1);
        assertThat(moved.getAnalystVerdict()).isEqualTo("FALSE_POSITIVE");
        assertThat(other.getAnalystVerdict()).isNull();
    }

    @Test
    void neverOverwritesAVerdictAlreadySetNorMatchesAnotherFile() {
        SecretFinding set = secret("Token", "a.txt", 1, "v", "REAL");
        SecretFinding elsewhere = secret("Token", "b.txt", 1, "v", null);
        SecretFinding noValue = secret("Token", "a.txt", 1, null, null);
        assertThat(SecretVerdictCarryOver.apply(List.of(set, elsewhere, noValue),
                List.of(secret("Token", "a.txt", 1, "v", "FALSE_POSITIVE")))).isZero();
        assertThat(set.getAnalystVerdict()).isEqualTo("REAL");
    }
}
