package com.medianet.controller;

import com.medianet.dto.ClientDto;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.ClientServerService;
import com.medianet.service.ClientService;
import com.medianet.service.ReleaseReadinessService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/clients")
public class ClientController {

    private final ClientService clientService;
    private final UserService userService;
    private final ReleaseReadinessService releaseReadinessService;
    private final ClientServerService clientServerService;

    public ClientController(ClientService clientService, UserService userService,
            ReleaseReadinessService releaseReadinessService, ClientServerService clientServerService) {
        this.clientServerService = clientServerService;
        this.clientService = clientService;
        this.userService = userService;
        this.releaseReadinessService = releaseReadinessService;
    }

    @PostMapping
    public ResponseEntity<ClientDto> createClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody CreateClientRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        if (body.releaseDeadline() == null) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST, "La deadline du projet est obligatoire.");
        }
        return ResponseEntity
                .ok(clientService.createClient(currentUser, body.name(), body.company(), body.domainName(),
                        body.email(), body.releaseDeadline(), body.releaseLabel()));
    }

    @GetMapping
    public ResponseEntity<List<ClientDto>> listClients(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(clientService.listVisibleClients(currentUser));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ClientDto> getClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(clientService.getVisibleClient(currentUser, id));
    }

    @GetMapping("/{id}/release-readiness")
    public ResponseEntity<Map<String, Object>> getReleaseReadiness(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(releaseReadinessService.build(currentUser, id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ClientDto> updateClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody UpdateClientRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity
                .ok(clientService.updateClient(currentUser, id, body.name(), body.company(), body.domainName(),
                        body.email(), body.releaseDeadline(), body.releaseLabel()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        clientServerService.removeAllForClient(id);
        clientService.deleteClient(currentUser, id);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/assign-employee")
    public ResponseEntity<ClientDto> assignEmployee(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody AssignEmployeeRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(clientService.assignEmployee(currentUser, id, body.employeeId()));
    }

    @PostMapping("/{id}/assign-repo")
    public ResponseEntity<ClientDto> assignRepository(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody AssignRepositoryRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(clientService.assignRepository(currentUser, id, body.repositoryId()));
    }

    @DeleteMapping("/{id}/repos/{repoId}")
    public ResponseEntity<Void> removeRepository(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        clientService.removeRepository(currentUser, id, repoId);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/{id}/servers")
    public ResponseEntity<List<ClientServerService.ProjectServerDto>> listServers(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(clientServerService.list(currentUser, id));
    }

    @PostMapping("/{id}/servers")
    public ResponseEntity<List<ClientServerService.ProjectServerDto>> linkServer(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody LinkServerRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(clientServerService.link(currentUser, id, body.serverId()));
    }

    @DeleteMapping("/{id}/servers/{serverId}")
    public ResponseEntity<Void> unlinkServer(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long serverId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        clientServerService.unlink(currentUser, id, serverId);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/{id}/servers/lightweight")
    public ResponseEntity<List<ClientServerService.ProjectServerDto>> createLightweightServer(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody LightweightServerRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(clientServerService.createLightweight(currentUser, id, body.name(), body.host(),
                body.environment()));
    }

    public record LinkServerRequest(Long serverId) {
    }

    public record LightweightServerRequest(String name, String host, String environment) {
    }

    public record CreateClientRequest(String name, String company, String domainName, String email,
            LocalDate releaseDeadline, String releaseLabel) {
    }

    public record UpdateClientRequest(String name, String company, String domainName, String email,
            LocalDate releaseDeadline, String releaseLabel) {
    }

    public record AssignEmployeeRequest(Long employeeId) {
    }

    public record AssignRepositoryRequest(Long repositoryId) {
    }
}