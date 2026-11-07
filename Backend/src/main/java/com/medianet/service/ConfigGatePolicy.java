package com.medianet.service;

import com.medianet.entity.ConfigFinding;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Decides whether a misconfiguration may fail a pipeline. By default nothing does: misconfigurations are
 * informational. A later rule such as "HIGH on KUBERNETES blocks" is set with
 * {@code vulnix.ci.config-gate.severities=HIGH,CRITICAL} and {@code vulnix.ci.config-gate.categories=KUBERNETES}
 * without touching the CVE gate in {@link CiScanService}. An empty severity list means "never block".
 */
@Component
public class ConfigGatePolicy {

    private final Set<String> severities;
    private final Set<String> categories;

    public ConfigGatePolicy(
            @Value("${vulnix.ci.config-gate.severities:}") String severities,
            @Value("${vulnix.ci.config-gate.categories:}") String categories) {
        this.severities = parse(severities);
        this.categories = parse(categories);
    }

    public boolean blocks(ConfigFinding finding) {
        if (finding == null || severities.isEmpty()) {
            return false;
        }
        String severity = finding.getSeverity() == null ? "" : finding.getSeverity().toUpperCase(Locale.ROOT);
        if (!severities.contains(severity)) {
            return false;
        }
        if (categories.isEmpty()) {
            return true;
        }
        String category = finding.getCategory() == null ? "" : finding.getCategory().toUpperCase(Locale.ROOT);
        return categories.contains(category);
    }

    public List<ConfigFinding> blocking(List<ConfigFinding> findings) {
        return findings == null ? List.of() : findings.stream().filter(this::blocks).toList();
    }

    private static Set<String> parse(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(csv.split(","))
                .map(s -> s.trim().toUpperCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
