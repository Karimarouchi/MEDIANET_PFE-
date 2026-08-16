package com.medianet.controller;

import com.medianet.dto.CiTokenCreatedDto;
import com.medianet.dto.CiTokenDto;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.CiTokenService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/ci-tokens")
public class AdminCiTokenController {

    private final CiTokenService ciTokenService;
    private final UserService userService;

    public AdminCiTokenController(CiTokenService ciTokenService, UserService userService) {
        this.ciTokenService = ciTokenService;
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<CiTokenCreatedDto> create(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody CreateCiTokenRequest body) {
        User admin = userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(ciTokenService.createToken(
                admin,
                body != null ? body.name() : null,
                body != null ? body.clientId() : null,
                body != null ? body.repositoryIds() : null,
                body != null ? body.expiresInDays() : null));
    }

    @GetMapping
    public ResponseEntity<List<CiTokenDto>> list(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestParam Long clientId) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(ciTokenService.listByClient(clientId));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<CiTokenDto> revoke(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(ciTokenService.revoke(id));
    }

    public record CreateCiTokenRequest(
            String name,
            Long clientId,
            List<Long> repositoryIds,
            Integer expiresInDays
    ) {
    }
}
