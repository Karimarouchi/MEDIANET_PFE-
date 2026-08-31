package com.medianet.service;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

final class TreatmentValidation {

    private TreatmentValidation() {
    }

    static void requireReason(String reason) {
        if (reason == null || reason.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Une raison est obligatoire pour ce statut (FALSE_POSITIVE / ACCEPTED_RISK).");
        }
    }
}
