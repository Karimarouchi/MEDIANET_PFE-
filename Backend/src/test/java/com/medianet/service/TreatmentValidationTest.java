package com.medianet.service;

import com.medianet.entity.CveRemediationStatus;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;

class TreatmentValidationTest {

    @Test
    void falsePositiveWithoutReasonIsRejected() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> TreatmentValidation.requireReason("  "));
        assertEquals(400, ex.getStatusCode().value());
    }

    @Test
    void falsePositiveWithReasonIsAccepted() {
        assertDoesNotThrow(() -> TreatmentValidation.requireReason("Package non chargé en production"));
    }

    @Test
    void computeStatusMapsLegacyAndNewStates() {
        assertEquals(CveRemediationStatus.FALSE_POSITIVE, CveJournalService.computeStatus(
                false, null, false, null, false, true, "LOW", false, false, false));
        assertEquals(CveRemediationStatus.ACCEPTED_RISK, CveJournalService.computeStatus(
                false, null, false, null, true, false, "HIGH", false, false, false));
        assertEquals(CveRemediationStatus.FIXED, CveJournalService.computeStatus(
                false, null, true, "1.2.3", false, false, "HIGH", false, false, true));
        assertEquals(CveRemediationStatus.FIX_AVAILABLE, CveJournalService.computeStatus(
                false, null, false, null, false, false, "LOW", false, false, true));
        assertEquals(CveRemediationStatus.OPEN, CveJournalService.computeStatus(
                false, null, false, null, false, false, "LOW", false, false, false));
    }
}
