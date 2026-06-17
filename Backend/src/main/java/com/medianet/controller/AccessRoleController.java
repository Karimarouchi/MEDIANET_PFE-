package com.medianet.controller;

import com.medianet.dto.AccessRoleDto;
import com.medianet.entity.AccessRole;
import com.medianet.entity.UserRole;
import com.medianet.service.AccessRoleService;
import com.medianet.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.List;

@RestController
@RequestMapping("/api/access-roles")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AccessRoleController {

    private final AccessRoleService accessRoleService;
    private final UserService userService;

    public AccessRoleController(AccessRoleService accessRoleService, UserService userService) {
        this.accessRoleService = accessRoleService;
        this.userService = userService;
    }

    @GetMapping
    public ResponseEntity<List<AccessRoleDto>> listRoles(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(accessRoleService.listRoles().stream().map(this::toDto).toList());
    }

    @PostMapping
    public ResponseEntity<AccessRoleDto> createRole(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody SaveAccessRoleRequest body) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        AccessRole role = accessRoleService.createRole(body.name(), body.description(), parseBaseRole(body.baseRole()),
                body.permissions());
        return ResponseEntity.ok(toDto(role));
    }

    @PutMapping("/{id}")
    public ResponseEntity<AccessRoleDto> updateRole(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody SaveAccessRoleRequest body) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        AccessRole role = accessRoleService.updateRole(id, body.name(), body.description(),
                parseBaseRole(body.baseRole()), body.permissions());
        return ResponseEntity.ok(toDto(role));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteRole(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        accessRoleService.deleteRole(id);
        return ResponseEntity.ok().build();
    }

    private AccessRoleDto toDto(AccessRole role) {
        return AccessRoleDto.builder()
                .id(role.getId())
                .roleKey(role.getRoleKey())
                .name(role.getName())
                .description(role.getDescription())
                .baseRole(role.getBaseRole() != null ? role.getBaseRole().name() : null)
                .systemRole(Boolean.TRUE.equals(role.getSystemRole()))
                .permissions(role.getPermissions() != null ? role.getPermissions().stream().map(Enum::name).toList()
                        : List.of())
                .build();
    }

    private UserRole parseBaseRole(String rawRole) {
        if (rawRole == null || rawRole.isBlank()) {
            return UserRole.EMPLOYEE;
        }
        try {
            return UserRole.valueOf(rawRole.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Base role must be ADMIN or EMPLOYEE");
        }
    }

    public record SaveAccessRoleRequest(String name, String description, String baseRole, List<String> permissions) {
    }
}