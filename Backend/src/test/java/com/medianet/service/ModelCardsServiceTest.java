package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ModelCardsServiceTest {

    private final SecretTriageService triage = mock(SecretTriageService.class);

    @Test
    void theShippedCardsFileIsValidAndHonest() {
        Path ml = Path.of("..", "ml").toAbsolutePath().normalize();
        when(triage.isAvailable()).thenReturn(true);
        JsonNode cards = new ModelCardsService(ml.toString(), triage).cards();

        assertThat(cards.has("error")).isFalse();
        assertThat(cards.path("models")).hasSizeGreaterThanOrEqualTo(4);
        for (JsonNode m : cards.path("models")) {
            String id = m.path("id").asText();
            assertThat(m.path("name").asText()).as(id).isNotBlank();
            assertThat(m.path("status").asText()).as(id).isIn("RELIABLE", "IMPROVABLE", "THIRD_PARTY", "REMOVED");
            assertThat(m.path("limits")).as("%s must state its limits", id).isNotEmpty();
            assertThat(m.has("live")).as(id).isTrue();
        }
    }

    @Test
    void theRemovedModelIsListedAsRemovedAndHasNoMetrics() {
        Path ml = Path.of("..", "ml").toAbsolutePath().normalize();
        JsonNode sla = null;
        for (JsonNode m : new ModelCardsService(ml.toString(), triage).cards().path("models")) {
            if ("sla-removed".equals(m.path("id").asText())) sla = m;
        }
        assertThat(sla).isNotNull();
        assertThat(sla.path("removed").asBoolean()).isTrue();
        assertThat(sla.path("metrics")).isEmpty();
    }

    @Test
    void installedMeansEveryArtifactIsOnDisk(@TempDir Path tmp) throws Exception {
        Path ml = tmp.resolve("ml");
        Files.createDirectories(ml.resolve("secrets/artifacts"));
        Files.writeString(ml.resolve("model_cards.json"), """
                {"updated":"2026-10-11","models":[
                  {"id":"a","name":"A","status":"RELIABLE","limits":["x"],"artifacts":["ml/secrets/artifacts/a.joblib"]},
                  {"id":"b","name":"B","status":"RELIABLE","limits":["x"],"artifacts":["ml/secrets/artifacts/missing.joblib"]},
                  {"id":"c","name":"C","status":"THIRD_PARTY","limits":["x"],"artifacts":[]}]}
                """);
        Files.writeString(ml.resolve("secrets/artifacts/a.joblib"), "x");

        JsonNode models = new ModelCardsService(ml.toString(), triage).cards().path("models");
        assertThat(models.get(0).path("live").path("installed").asBoolean()).isTrue();
        assertThat(models.get(0).path("live").path("exportedAt").asText()).matches("[0-9]{4}-[0-9]{2}-[0-9]{2}");
        assertThat(models.get(1).path("live").path("installed").asBoolean()).isFalse();
        assertThat(models.get(2).path("live").path("tracked").asBoolean()).isFalse();
    }

    @Test
    void aMissingFileGivesAnErrorMessageNotACrash(@TempDir Path tmp) {
        JsonNode cards = new ModelCardsService(tmp.toString(), triage).cards();
        assertThat(cards.path("models")).isEmpty();
        assertThat(cards.path("error").asText()).contains("introuvable");
    }
}
