package com.medianet.controller;

import com.medianet.dto.HardeningFindingDto;
import com.medianet.dto.ServerNodeDetailDto;
import com.medianet.dto.ServerNodeDto;
import com.medianet.dto.ServerNodeRequest;
import com.medianet.service.ServerConfigService;
import com.medianet.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/servers")
public class ServerConfigController {

    private final ServerConfigService serverConfigService;
    private final UserService userService;

    public ServerConfigController(ServerConfigService serverConfigService, UserService userService) {
        this.serverConfigService = serverConfigService;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<List<ServerNodeDto>> getServers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getServers());
    }

    @PostMapping
    public ResponseEntity<ServerNodeDto> createServer(
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.createServer(request));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ServerNodeDto> updateServer(
            @PathVariable Long id,
            @Valid @RequestBody ServerNodeRequest request,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.updateServer(id, request));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        serverConfigService.deleteServer(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ServerNodeDetailDto> getServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getServer(id));
    }

    @PostMapping("/{id}/live")
    public ResponseEntity<ServerNodeDetailDto> getLiveServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getLiveServer(id));
    }

    @PostMapping("/{id}/scan")
    public ResponseEntity<ServerNodeDetailDto> scanServer(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.scanServer(id));
    }

    @GetMapping("/{id}/findings")
    public ResponseEntity<List<HardeningFindingDto>> getFindings(
            @PathVariable Long id,
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(serverConfigService.getFindings(id));
    }
}