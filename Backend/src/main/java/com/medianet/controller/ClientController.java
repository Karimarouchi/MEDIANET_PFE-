package com.medianet.controller;

import com.medianet.dto.ClientDto;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.service.ClientService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/clients")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class ClientController {

    private final ClientService clientService;
    private final UserService userService;

    public ClientController(ClientService clientService, UserService userService) {
        this.clientService = clientService;
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<ClientDto> createClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody CreateClientRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN, UserRole.EMPLOYEE);
        return ResponseEntity
                .ok(clientService.createClient(currentUser, body.name(), body.company(), body.email()));
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

    @PutMapping("/{id}")
    public ResponseEntity<ClientDto> updateClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody UpdateClientRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        return ResponseEntity
                .ok(clientService.updateClient(currentUser, id, body.name(), body.company(), body.email()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
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

    public record CreateClientRequest(String name, String company, String email) {
    }

    public record UpdateClientRequest(String name, String company, String email) {
    }

    public record AssignEmployeeRequest(Long employeeId) {
    }

    public record AssignRepositoryRequest(Long repositoryId) {
    }
}