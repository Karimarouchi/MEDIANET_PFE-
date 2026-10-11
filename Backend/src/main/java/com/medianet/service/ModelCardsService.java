package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * The cards of the page "Modèles ML": what each model does, its version, its measured figures and its limits.
 * The text and figures live in {@code ml/model_cards.json} (copied from the metrics files, updated at each retraining);
 * this service adds what only the running server knows: is the model installed and when was it exported.
 */
@Service
public class ModelCardsService {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Path mlDir;
    private final SecretTriageService secretTriage;

    public ModelCardsService(@Value("${ml.dir:}") String mlDirConfig, SecretTriageService secretTriage) {
        this.mlDir = MlPaths.resolveMlDir(mlDirConfig);
        this.secretTriage = secretTriage;
    }

    public JsonNode cards() {
        Path file = mlDir.resolve("model_cards.json");
        ObjectNode root = MAPPER.createObjectNode();
        if (!Files.isRegularFile(file)) {
            root.set("models", MAPPER.createArrayNode());
            root.put("error", "Fichier des fiches introuvable sur ce serveur (ml/model_cards.json).");
            return root;
        }
        try {
            JsonNode doc = MAPPER.readTree(file.toFile());
            ArrayNode out = MAPPER.createArrayNode();
            for (JsonNode m : doc.path("models")) {
                out.add(enrich((ObjectNode) m.deepCopy()));
            }
            root.put("updated", doc.path("updated").asText(null));
            root.put("note", doc.path("note").asText(null));
            root.set("models", out);
            return root;
        } catch (IOException e) {
            root.set("models", MAPPER.createArrayNode());
            root.put("error", "Fiches illisibles : " + e.getMessage());
            return root;
        }
    }

    private ObjectNode enrich(ObjectNode card) {
        ArrayNode artifacts = card.has("artifacts") && card.get("artifacts").isArray() ? (ArrayNode) card.get("artifacts") : MAPPER.createArrayNode();
        String status = card.path("status").asText("");
        boolean tracked = !artifacts.isEmpty();
        boolean present = tracked;
        long newest = 0;
        for (JsonNode a : artifacts) {
            // paths in the cards are relative to the repository root ("ml/...")
            Path p = mlDir.resolveSibling(a.asText()).normalize();
            if (!Files.isRegularFile(p)) {
                present = false;
            } else {
                try {
                    newest = Math.max(newest, Files.getLastModifiedTime(p).toMillis());
                } catch (IOException ignored) {
                    // keep going: the date is informative only
                }
            }
        }
        if ("secret-triage".equals(card.path("id").asText())) {
            present = present && secretTriage.isAvailable();
        }
        ObjectNode live = MAPPER.createObjectNode();
        live.put("tracked", tracked);
        live.put("installed", present);
        live.put("exportedAt", newest > 0
                ? DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC).format(Instant.ofEpochMilli(newest))
                : null);
        card.set("live", live);
        card.put("removed", "REMOVED".equals(status));
        return card;
    }
}
