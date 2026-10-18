package com.medianet.service;

import com.medianet.entity.SecretFinding;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Keeps the analyst's verdict on a secret from one scan of a repository to the next. Same secret means same rule,
 * same file and same value: the line is left out, since an edit above the secret moves it without changing it.
 */
final class SecretVerdictCarryOver {

    private SecretVerdictCarryOver() {
    }

    /** Null when the finding carries no value to compare. */
    static String key(SecretFinding s) {
        String value = s.getRawSecret() != null && !s.getRawSecret().isBlank() ? s.getRawSecret() : s.getMatch();
        if (value == null || value.isBlank()) {
            return null;
        }
        String rule = s.getRuleId() == null ? "" : s.getRuleId().trim().toLowerCase(Locale.ROOT);
        String file = s.getFile() == null ? "" : s.getFile().trim().replace('\\', '/');
        return rule + "|" + file + "|" + sha256(value.trim());
    }

    /**
     * Copies verdicts onto findings that have none yet. {@code previousNewestFirst} holds the findings of earlier
     * scans, newest scan first, so the latest decision on a secret wins. Returns the number of verdicts copied.
     */
    static int apply(List<SecretFinding> current, Collection<SecretFinding> previousNewestFirst) {
        Map<String, String> verdictByKey = new HashMap<>();
        for (SecretFinding old : previousNewestFirst) {
            String verdict = old.getAnalystVerdict();
            String k = verdict == null || verdict.isBlank() ? null : key(old);
            if (k != null) {
                verdictByKey.putIfAbsent(k, verdict);
            }
        }
        if (verdictByKey.isEmpty()) {
            return 0;
        }
        int copied = 0;
        for (SecretFinding s : current) {
            if (s.getAnalystVerdict() != null && !s.getAnalystVerdict().isBlank()) {
                continue;
            }
            String k = key(s);
            String verdict = k == null ? null : verdictByKey.get(k);
            if (verdict != null) {
                s.setAnalystVerdict(verdict);
                copied++;
            }
        }
        return copied;
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
