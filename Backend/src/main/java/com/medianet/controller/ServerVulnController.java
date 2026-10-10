package com.medianet.controller;

import com.medianet.entity.AccessPermission;
import com.medianet.entity.User;
import com.medianet.serverscan.ServerVulnService;
import com.medianet.service.AccessRoleService;
import com.medianet.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

/** Vulnerability analysis of a server (open ports + system packages). Requires the SERVER_CONFIG permission. */
@RestController
@RequestMapping("/api/servers/{id}/vuln-scan")
public class ServerVulnController {

    private final ServerVulnService serverVulnService;
    private final UserService userService;
    private final AccessRoleService accessRoleService;

    public ServerVulnController(ServerVulnService serverVulnService, UserService userService,
            AccessRoleService accessRoleService) {
        this.serverVulnService = serverVulnService;
        this.userService = userService;
        this.accessRoleService = accessRoleService;
    }

    @PostMapping
    public ResponseEntity<ServerVulnService.ScanView> start(
            @PathVariable Long id,
            @RequestBody(required = false) StartRequest body,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        boolean external = body == null || body.external() == null || body.external();
        boolean internal = body == null || body.internal() == null || body.internal();
        return ResponseEntity.ok(serverVulnService.start(id, new ServerVulnService.Options(external, internal)));
    }

    /** Latest analysis (204 when none yet). The page polls this while the status is RUNNING. */
    @GetMapping
    public ResponseEntity<ServerVulnService.ScanView> latest(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        requireServerConfig(authHeader);
        return serverVulnService.latest(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.noContent().build());
    }

    public record StartRequest(Boolean external, Boolean internal) {
    }

    private User requireServerConfig(String authHeader) {
        User user = userService.getRequiredUser(authHeader);
        if (!accessRoleService.getEffectivePermissions(user).contains(AccessPermission.SERVER_CONFIG)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Permission SERVER_CONFIG requise.");
        }
        return user;
    }
}
