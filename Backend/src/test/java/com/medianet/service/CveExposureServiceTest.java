package com.medianet.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CveExposureService — surface transverse")
class CveExposureServiceTest {

    @Test
    @DisplayName("un dépôt est ouvert seulement s’il est encore dans le dernier scan et non traité")
    void isRepoStillOpen_requiresLiveDetection() {
        assertThat(CveExposureService.isRepoStillOpen(true, false, false)).isTrue();
        assertThat(CveExposureService.isRepoStillOpen(true, true, false)).isFalse();
        assertThat(CveExposureService.isRepoStillOpen(true, false, true)).isFalse();
        assertThat(CveExposureService.isRepoStillOpen(false, false, false)).isFalse();
    }

    @Test
    @DisplayName("on ne propose la propagation que si la version chef diffère")
    void canPropagate_requiresChefAndGap() {
        assertThat(CveExposureService.canPropagate(true, "2.17.1", "2.14.1")).isTrue();
        assertThat(CveExposureService.canPropagate(true, "2.17.1", "2.17.1")).isFalse();
        assertThat(CveExposureService.canPropagate(true, null, "2.14.1")).isFalse();
        assertThat(CveExposureService.canPropagate(false, "2.17.1", "2.14.1")).isFalse();
    }
}
