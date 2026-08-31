package com.medianet.service;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory GHSA → CVE map filled from OSV aliases and GitHub Advisory responses.
 * Avoids a GitHub call on every dashboard render.
 */
@Component
public class AdvisoryAliasCache {

    private final ConcurrentHashMap<String, String> ghsaToCve = new ConcurrentHashMap<>();

    public void put(String ghsaId, String cveId) {
        String ghsa = normalizeGhsa(ghsaId);
        String cve = normalizeCve(cveId);
        if (ghsa == null || cve == null) {
            return;
        }
        ghsaToCve.put(ghsa, cve);
    }

    public Optional<String> findCve(String ghsaId) {
        String ghsa = normalizeGhsa(ghsaId);
        if (ghsa == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(ghsaToCve.get(ghsa));
    }

    public Map<String, String> snapshot() {
        return Map.copyOf(ghsaToCve);
    }

    static String normalizeGhsa(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String id = raw.trim().toUpperCase();
        return id.startsWith("GHSA-") ? id : null;
    }

    static String normalizeCve(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String id = raw.trim().toUpperCase();
        return id.startsWith("CVE-") ? id : null;
    }
}
