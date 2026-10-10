package com.medianet.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("MlPredictService — Experiment A inference")
class MlPredictServiceTest {

    @Test
    @DisplayName("bandes calées sur les tertiles : FAIBLE / MOYEN / ELEVE")
    void bandFromProba_usesThresholds() {
        assertThat(MlPredictService.bandFromProba(0.10, 0.33, 0.66)).isEqualTo("FAIBLE");
        assertThat(MlPredictService.bandFromProba(0.40, 0.33, 0.66)).isEqualTo("MOYEN");
        assertThat(MlPredictService.bandFromProba(0.90, 0.33, 0.66)).isEqualTo("ELEVE");
    }

    @Test
    @DisplayName("predictFeatures refuse days_to_fix / sla_breached")
    void predictFeatures_rejectsLabels() {
        MlPredictService service = new MlPredictService(null, "", "");
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.predictFeatures(Map.of("cvss_score", 9.8, "days_to_fix", 4)));
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("predictFeaturesBatch refuse aussi sla_breached")
    void predictFeaturesBatch_rejectsLabels() {
        MlPredictService service = new MlPredictService(null, "", "");
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.predictFeaturesBatch(java.util.List.of(Map.of("sla_breached", true))));
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("intervalle indicatif = estimatedDays ± MAE, jamais négatif")
    void daysInterval_clipsAtZero() {
        assertThat(MlPredictService.daysInterval(4.0, 2.7)[0]).isCloseTo(1.3, org.assertj.core.data.Offset.offset(1e-9));
        assertThat(MlPredictService.daysInterval(4.0, 2.7)[1]).isCloseTo(6.7, org.assertj.core.data.Offset.offset(1e-9));
        assertThat(MlPredictService.daysInterval(1.0, 2.7)[0]).isEqualTo(0.0);
        assertThat(MlPredictService.daysInterval(null, 2.7)).isNull();
    }
}
