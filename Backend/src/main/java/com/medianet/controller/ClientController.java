package com.medianet.controller;

import com.medianet.dto.ClientDto;
import com.medianet.entity.ProjectRepoRole;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.ClientServerService;
import com.medianet.service.ClientService;
import com.medianet.service.ProjectDeletionService;
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
    private final ProjectDeletionService projectDeletionService;

    public ClientController(ClientService clientService, UserService userService,
            ReleaseReadinessService releaseReadinessService, ClientServerService clientServerService,
            ProjectDeletionService projectDeletionService) {
        this.clientServerService = clientServerService;
        this.projectDeletionService = projectDeletionService;
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

    @PutMapping("/{id}/repositories/{repoId}/role")
    public ResponseEntity<ClientDto> setRepositoryRole(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId,
            @RequestBody RepoRoleRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(clientService.setRepositoryRole(currentUser, id, repoId, body.role()));
    }

    @PutMapping("/{id}/ssl-alert")
    public ResponseEntity<ClientDto> setSslAlert(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody SslAlertRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity.ok(clientService.setSslAlertDate(currentUser, id, body.alertDate()));
    }

    /** What deleting the project would remove, and what still blocks it (scan or deployment in progress). */
    @GetMapping("/{id}/deletion-preview")
    public ResponseEntity<ProjectDeletionService.Preview> deletionPreview(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(projectDeletionService.preview(currentUser, id));
    }

    /** Deletes the project and everything that only exists for it; {@code confirm} is the project name. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestParam(value = "confirm", required = false) String confirm) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        projectDeletionService.delete(currentUser, id, confirm);
        return ResponseEntity.noContent().build();
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

    /** What removing this repository from the project does (shared or not, scans, CI). */
    @GetMapping("/{id}/repos/{repoId}/removal-preview")
    public ResponseEntity<ProjectDeletionService.RepoRemovalPreview> repoRemovalPreview(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity.ok(projectDeletionService.repoRemovalPreview(currentUser, id, repoId));
    }

    /** Detaches the repository (and the project's CI on it); {@code deleteRepository=true} also deletes it with its scans. */
    @DeleteMapping("/{id}/repos/{repoId}")
    public ResponseEntity<Void> removeRepository(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @PathVariable Long repoId,
            @RequestParam(value = "deleteRepository", defaultValue = "false") boolean deleteRepository) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        projectDeletionService.removeRepository(currentUser, id, repoId, deleteRepository);
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

    public record SslAlertRequest(LocalDate alertDate) {
    }

    public record RepoRoleRequest(ProjectRepoRole role) {
    }

    public record AssignEmployeeRequest(Long employeeId) {
    }

    public record AssignRepositoryRequest(Long repositoryId) {
    }
}