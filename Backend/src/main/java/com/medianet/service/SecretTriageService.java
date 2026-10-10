package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.SecretFinding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Triage of the secrets reported by Gitleaks: for each one, a probability that it is a real secret, a verdict
 * (LIKELY_REAL / REVIEW / LIKELY_FALSE_POSITIVE), a priority and the reasons. The model runs in a Python sidecar
 * ({@code ml/secrets/runtime.py}); nothing is sent outside the machine. It never hides a finding by itself: a failure
 * simply leaves the findings without a verdict, and the scan carries on.
 */
@Service
public class SecretTriageService {

    private static final Logger log = LoggerFactory.getLogger(SecretTriageService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path mlDir;
    private final Path pythonExe;
    private final boolean enabled;
    private final int timeoutSeconds;

    public SecretTriageService(
            @Value("${ml.dir:}") String mlDirConfig,
            @Value("${ml.python:}") String pythonConfig,
            @Value("${secrettriage.enabled:true}") boolean enabled,
            @Value("${secrettriage.timeout-seconds:120}") int timeoutSeconds) {
        this.mlDir = MlPaths.resolveMlDir(mlDirConfig);
        this.pythonExe = MlPaths.resolvePython(pythonConfig, mlDir);
        this.enabled = enabled;
        this.timeoutSeconds = timeoutSeconds;
    }

    public boolean isAvailable() {
        return enabled && Files.isRegularFile(mlDir.resolve("secrets").resolve("runtime.py"))
                && Files.isRegularFile(mlDir.resolve("secrets").resolve("artifacts").resolve("secret_triage.joblib"));
    }

    /** Summary line for the scan log, or null when nothing was triaged. */
    public String summaryLine(List<SecretFinding> secrets) {
        long real = secrets.stream().filter(s -> "LIKELY_REAL".equals(s.getMlVerdict())).count();
        long review = secrets.stream().filter(s -> "REVIEW".equals(s.getMlVerdict())).count();
        long fp = secrets.stream().filter(s -> "LIKELY_FALSE_POSITIVE".equals(s.getMlVerdict())).count();
        if (real + review + fp == 0) {
            return null;
        }
        return "[SECRETS] Tri par le modèle : " + real + " probablement réel(s), " + review + " à vérifier, "
                + fp + " faux positif(s) probable(s).";
    }

    /**
     * Fills the ML fields of the given findings in place. Uses the raw secret value when it is known (fresh scan),
     * otherwise derives it from the stored match. Never throws.
     *
     * @return number of findings that received a verdict
     */
    public int apply(List<SecretFinding> secrets) {
        if (secrets == null || secrets.isEmpty() || !isAvailable()) {
            return 0;
        }
        try {
            JsonNode answer = run(buildPayload(secrets));
            return applyAnswer(secrets, answer);
        } catch (Exception e) {
            log.warn("[SecretTriage] triage skipped: {}", e.getMessage());
            return 0;
        }
    }

    static List<Map<String, Object>> buildPayload(List<SecretFinding> secrets) {
        List<Map<String, Object>> payload = new ArrayList<>();
        for (SecretFinding s : secrets) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("RuleID", s.getRuleId());
            m.put("File", s.getFile());
            m.put("StartLine", s.getStartLine());
            m.put("Match", s.getMatch());
            if (s.getRawSecret() != null) {
                m.put("Secret", s.getRawSecret());
            }
            payload.add(m);
        }
        return payload;
    }

    /** Copies the sidecar answer (same order as the request) onto the findings; returns how many were filled. */
    int applyAnswer(List<SecretFinding> secrets, JsonNode answer) {
        if (answer == null || !answer.isArray() || answer.size() != secrets.size()) {
            throw new IllegalStateException("unexpected answer size from the triage model");
        }
        int filled = 0;
        for (int i = 0; i < secrets.size(); i++) {
            JsonNode n = answer.get(i);
            if (!n.hasNonNull("verdict")) {
                continue;
            }
            SecretFinding s = secrets.get(i);
            s.setMlVerdict(n.get("verdict").asText());
            s.setMlProba(n.path("probaReal").asDouble());
            s.setMlScope(n.path("scope").asText(null));
            s.setMlPriority(n.hasNonNull("priority") ? n.get("priority").asInt() : null);
            s.setMlModelVersion(n.path("modelVersion").asText(null));
            List<String> reasons = new ArrayList<>();
            n.path("reasons").forEach(r -> reasons.add(r.asText()));
            try {
                s.setMlReasons(MAPPER.writeValueAsString(reasons));
            } catch (Exception e) {
                s.setMlReasons("[]");
            }
            filled++;
        }
        return filled;
    }

    private JsonNode run(List<Map<String, Object>> payload) throws Exception {
        Path script = mlDir.resolve("secrets").resolve("runtime.py");
        ProcessBuilder pb = new ProcessBuilder(pythonExe.toString(), script.toString());
        pb.directory(mlDir.resolve("secrets").toFile());
        pb.environment().put("PYTHONIOENCODING", "utf-8");
        Process process = pb.start();
        CompletableFuture<String> out = CompletableFuture.supplyAsync(() -> read(process.getInputStream()));
        CompletableFuture<String> err = CompletableFuture.supplyAsync(() -> read(process.getErrorStream()));
        process.getOutputStream().write(MAPPER.writeValueAsBytes(payload));
        process.getOutputStream().close();
        if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new IllegalStateException("runtime.py timed out after " + timeoutSeconds + "s");
        }
        String stdout = out.get(5, TimeUnit.SECONDS);
        String stderr = err.get(5, TimeUnit.SECONDS);
        if (process.exitValue() != 0) {
            throw new IllegalStateException("runtime.py failed: " + (stderr.isBlank() ? stdout : stderr));
        }
        return MAPPER.readTree(stdout);
    }

    private static String read(InputStream stream) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            stream.transferTo(out);
            return out.toString(StandardCharsets.UTF_8).trim();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }
}
