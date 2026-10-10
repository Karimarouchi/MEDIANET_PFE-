package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Experiment A inference only: P(lab SLA threshold breach). Does not change CI.
 */
@Service
public class MlPredictService {

    private static final Logger log = LoggerFactory.getLogger(MlPredictService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final FeatureStoreBuilderService featureStoreBuilderService;
    private final Path mlDir;
    private final Path pythonExe;

    public MlPredictService(
            FeatureStoreBuilderService featureStoreBuilderService,
            @Value("${ml.dir:}") String mlDirConfig,
            @Value("${ml.python:}") String pythonConfig) {
        this.featureStoreBuilderService = featureStoreBuilderService;
        this.mlDir = resolveMlDir(mlDirConfig);
        this.pythonExe = resolvePython(pythonConfig, this.mlDir);
    }

    public record Prediction(
            double slaBreachProba,
            String remediationBand,
            String labelDefinition,
            String bandMethod,
            Double estimatedDays,
            Double estimatedDaysMae,
            Map<String, Object> features) {
    }

    public Prediction predictForCve(String cveId, String packageName) {
        Map<String, Object> features = featureStoreBuilderService
                .buildInferenceFeatures(cveId, packageName)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "No detection history for this CVE"));
        return predictFeatures(features);
    }

    public Prediction predictFeatures(Map<String, Object> features) {
        rejectLabels(features);
        return parsePrediction(runPython(features, 25), features);
    }

    public List<Prediction> predictFeaturesBatch(List<Map<String, Object>> featureRows) {
        if (featureRows == null || featureRows.isEmpty()) {
            return List.of();
        }
        for (Map<String, Object> features : featureRows) {
            rejectLabels(features);
        }
        JsonNode scored = runPython(featureRows, 90);
        if (!scored.isArray() || scored.size() != featureRows.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "ML batch size mismatch");
        }
        List<Prediction> out = new ArrayList<>(featureRows.size());
        for (int i = 0; i < featureRows.size(); i++) {
            out.add(parsePrediction(scored.get(i), featureRows.get(i)));
        }
        return out;
    }

    private static void rejectLabels(Map<String, Object> features) {
        if (features == null || features.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Feature payload is empty");
        }
        if (features.containsKey("days_to_fix") || features.containsKey("sla_breached")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "days_to_fix and sla_breached must not be sent to the classifier");
        }
    }

    private static Prediction parsePrediction(JsonNode scored, Map<String, Object> features) {
        double proba = scored.path("slaBreachProba").asDouble();
        String band = scored.path("remediationBand").asText(bandFromProba(proba, 1.0 / 3.0, 2.0 / 3.0));
        Double estimatedDays = scored.hasNonNull("estimatedDays") ? scored.get("estimatedDays").asDouble() : null;
        Double estimatedDaysMae = scored.hasNonNull("estimatedDaysMae") ? scored.get("estimatedDaysMae").asDouble() : null;
        return new Prediction(
                proba,
                band,
                scored.path("labelDefinition").asText(null),
                scored.path("bandMethod").asText(null),
                estimatedDays,
                estimatedDaysMae,
                features);
    }

    static String bandFromProba(double proba, double mediumMin, double highMin) {
        double low = Math.min(mediumMin, highMin);
        double high = Math.max(mediumMin, highMin);
        if (proba >= high) {
            return "ELEVE";
        }
        if (proba >= low) {
            return "MOYEN";
        }
        return "FAIBLE";
    }

    public Map<String, Object> toApiBody(Prediction prediction) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("slaBreachProba", prediction.slaBreachProba());
        body.put("remediationBand", prediction.remediationBand());
        body.put("labelDefinition", prediction.labelDefinition());
        body.put("bandMethod", prediction.bandMethod());
        body.put("estimatedDays", prediction.estimatedDays());
        body.put("estimatedDaysMae", prediction.estimatedDaysMae());
        double[] interval = daysInterval(prediction.estimatedDays(), prediction.estimatedDaysMae());
        body.put("estimatedDaysLow", interval == null ? null : interval[0]);
        body.put("estimatedDaysHigh", interval == null ? null : interval[1]);
        body.put("disclaimer",
                "P(dépassement du seuil de remédiation 15/30/60/90 de l'expérience A) "
                        + "et délai estimé à partir de l'historique Medianet, "
                        + "pas une décision de passage en production.");
        return body;
    }

    static double[] daysInterval(Double estimatedDays, Double mae) {
        if (estimatedDays == null || mae == null) {
            return null;
        }
        return new double[] { Math.max(0.0, estimatedDays - mae), estimatedDays + mae };
    }

    private JsonNode runPython(Object payload, int timeoutSeconds) {
        Path predict = mlDir.resolve("predict.py");
        Path model = mlDir.resolve("artifacts").resolve("classifier_expA.joblib");
        if (!Files.isRegularFile(predict) || !Files.isRegularFile(model)) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Experiment A model is not trained yet");
        }
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    pythonExe.toString(),
                    predict.toString(),
                    "--model", model.toString(),
                    "--meta", mlDir.resolve("artifacts").resolve("inference_meta.json").toString());
            pb.directory(mlDir.toFile());
            pb.environment().put("PYTHONPATH", mlDir.toString());
            pb.redirectErrorStream(false);
            Process process = pb.start();
            // Drain both pipes concurrently: a large batch output (or stderr noise) would
            // otherwise fill the OS pipe buffer and block the child until the timeout.
            CompletableFuture<String> stdoutFuture = CompletableFuture.supplyAsync(
                    () -> readStreamUnchecked(process.getInputStream()));
            CompletableFuture<String> stderrFuture = CompletableFuture.supplyAsync(
                    () -> readStreamUnchecked(process.getErrorStream()));
            process.getOutputStream().write(MAPPER.writeValueAsBytes(payload));
            process.getOutputStream().close();
            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new ResponseStatusException(HttpStatus.GATEWAY_TIMEOUT, "ML predict timed out");
            }
            String stdout = stdoutFuture.get(5, TimeUnit.SECONDS);
            String stderr = stderrFuture.get(5, TimeUnit.SECONDS);
            if (process.exitValue() != 0) {
                log.warn("ml/predict.py failed: {}", stderr.isBlank() ? stdout : stderr);
                throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "ML predict failed");
            }
            return MAPPER.readTree(stdout);
        } catch (ResponseStatusException e) {
            throw e;
        } catch (Exception e) {
            log.warn("ml/predict.py could not be started: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "ML runtime unavailable");
        }
    }

    private static String readStreamUnchecked(InputStream stream) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            stream.transferTo(out);
            return out.toString(StandardCharsets.UTF_8).trim();
        } catch (java.io.IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private static Path resolveMlDir(String configured) {
        return MlPaths.resolveMlDir(configured);
    }

    private static Path resolvePython(String configured, Path mlDir) {
        return MlPaths.resolvePython(configured, mlDir);
    }
}
