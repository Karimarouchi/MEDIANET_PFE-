package com.medianet.controller;

import com.medianet.dto.CiWhoamiDto;
import com.medianet.security.CiPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

/**
 * CI-only API. Authenticated exclusively with {@code Authorization: Bearer vx_live_…}.
 * User JWTs and session cookies are rejected by {@code JwtAuthFilter}.
 */
@RestController
@RequestMapping("/api/ci")
public class CiController {

    @GetMapping("/whoami")
    public ResponseEntity<CiWhoamiDto> whoami(HttpServletRequest request) {
        CiPrincipal principal = CiPrincipal.require(request);
        return ResponseEntity.ok(new CiWhoamiDto(
                principal.tokenId(),
                principal.name(),
                principal.tokenPrefix(),
                principal.clientId(),
                new ArrayList<>(principal.repositoryIds()),
                new ArrayList<>(principal.scopes())));
    }
}
