package com.medianet.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Production sets {@code server.error.include-message=never}, which hides the real
 * reason behind a generic "Internal Server Error". Always return {@code error}/{@code message}
 * so the Journal CVE and notification UI can display GitLab/GitHub commit failures.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<Map<String, Object>> handleResponseStatus(ResponseStatusException ex) {
        String reason = ex.getReason() != null && !ex.getReason().isBlank()
                ? ex.getReason()
                : ex.getStatusCode().toString();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", reason);
        body.put("message", reason);
        body.put("status", ex.getStatusCode().value());
        return ResponseEntity.status(ex.getStatusCode()).body(body);
    }
}
