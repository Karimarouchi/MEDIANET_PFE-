package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.time.LocalDate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SslExpiryAlertServiceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void expiryComesFromTheCertificateDetailThenTheFlatField() {
        assertThat(SslExpiryAlertService.expiryFromResultJson(mapper,
                "{\"certificateDetail\":{\"notAfter\":\"2027-01-14T23:59:59Z\"},\"certNotAfterStr\":\"2026-01-01\"}"))
                .contains(LocalDate.of(2027, 1, 14));
        assertThat(SslExpiryAlertService.expiryFromResultJson(mapper, "{\"certNotAfterStr\":\"2026-12-30 10:00\"}"))
                .contains(LocalDate.of(2026, 12, 30));
        assertThat(SslExpiryAlertService.expiryFromResultJson(mapper, "{\"certNotAfterStr\":\"—\"}")).isEqualTo(Optional.empty());
        assertThat(SslExpiryAlertService.expiryFromResultJson(mapper, "not json")).isEmpty();
    }

    @Test
    void messageGivesTheRealExpiryDate() {
        LocalDate today = LocalDate.of(2026, 10, 18);
        String m = SslExpiryAlertService.alertMessage("pfe.example.com", "PFE", today, LocalDate.of(2026, 11, 2), today);
        assertThat(m).contains("expire le 2 novembre 2026, dans 15 jours").contains("pfe.example.com");
        assertThat(SslExpiryAlertService.alertMessage("d", "P", today, today.minusDays(1), today)).contains("a expiré le");
        assertThat(SslExpiryAlertService.alertMessage("d", "P", today, null, today)).contains("relancez un scan SSL");
    }
}
