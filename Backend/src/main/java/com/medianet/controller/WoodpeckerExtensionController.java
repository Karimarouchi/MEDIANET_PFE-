package com.medianet.controller;

import com.medianet.service.CiPipelineConfigService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Called by Woodpecker, not by users: no session, the request is authenticated by its ed25519 signature
 * (checked in {@link CiPipelineConfigService}). Public path in JwtAuthFilter.
 */
@RestController
public class WoodpeckerExtensionController {

    private final CiPipelineConfigService configService;

    public WoodpeckerExtensionController(CiPipelineConfigService configService) {
        this.configService = configService;
    }

    @PostMapping(value = "/api/woodpecker/config", produces = "application/json")
    public Map<String, Object> config(HttpServletRequest request, @RequestBody(required = false) byte[] body) {
        String target = request.getRequestURI() + (request.getQueryString() != null ? "?" + request.getQueryString() : "");
        return configService.configFor(target, body == null ? new byte[0] : body,
                request.getHeader("Content-Digest"), request.getHeader("Signature-Input"), request.getHeader("Signature"));
    }
}
