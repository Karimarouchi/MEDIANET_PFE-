package com.medianet.controller;

import com.medianet.dto.UserDto;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.UserRepo;
import com.medianet.service.AccessRoleService;
import com.medianet.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Comparator;
import java.util.List;

@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class UserController {

    private final UserService userService;
    private final UserRepo userRepo;
    private final AccessRoleService accessRoleService;

    public UserController(UserService userService, UserRepo userRepo, AccessRoleService accessRoleService) {
        this.userService = userService;
        this.userRepo = userRepo;
        this.accessRoleService = accessRoleService;
    }

    @GetMapping
    public ResponseEntity<List<UserDto>> listUsers(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        return ResponseEntity.ok(userRepo.findAll().stream()
                .sorted(Comparator.comparing(User::getCreatedAt).reversed())
                .map(this::toDto)
                .toList());
    }

    @PostMapping
    public ResponseEntity<UserDto> createUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody CreateUserRequest body) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        UserRole fallbackRole = body.role() != null ? parseAllowedRole(body.role()) : UserRole.EMPLOYEE;
        User user = userService.createLocalUser(body.login(), body.name(), body.email(), body.password(),
                body.accessRoleId(), fallbackRole);
        return ResponseEntity.ok(toDto(user));
    }

    @PutMapping("/{id}")
    public ResponseEntity<UserDto> updateUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody UpdateUserRequest body) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        UserRole fallbackRole = body.role() != null ? parseAllowedRole(body.role()) : null;
        User user = userService.updateLocalUser(id, body.login(), body.name(), body.email(), body.password(),
                body.accessRoleId(), fallbackRole);
        return ResponseEntity.ok(toDto(user));
    }

    @PutMapping("/{id}/role")
    public ResponseEntity<UserDto> updateRole(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody UpdateRoleRequest body) {
        userService.requireRole(authHeader, UserRole.ADMIN);
        UserRole fallbackRole = body.role() != null ? parseAllowedRole(body.role()) : null;
        User user = userService.updateUserAccessRole(id, body.accessRoleId(), fallbackRole);
        return ResponseEntity.ok(toDto(user));
    }

    @PutMapping("/{id}/suspension")
    public ResponseEntity<UserDto> updateSuspension(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id,
            @RequestBody UpdateSuspensionRequest body) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        if (currentUser.getId().equals(id) && Boolean.TRUE.equals(body.suspended())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "You cannot suspend your own account");
        }
        return ResponseEntity.ok(toDto(userService.updateSuspension(id, Boolean.TRUE.equals(body.suspended()))));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteUser(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @PathVariable Long id) {
        User currentUser = userService.requireRole(authHeader, UserRole.ADMIN);
        if (currentUser.getId().equals(id)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "You cannot delete your own account");
        }
        userService.deleteUser(id);
        return ResponseEntity.ok().build();
    }

    private UserDto toDto(User user) {
        return UserDto.builder()
                .id(user.getId())
                .login(user.getLogin())
                .name(user.getName())
                .avatarUrl(user.getAvatarUrl())
                .email(user.getEmail())
                .role(accessRoleService.getDisplayRoleName(user))
                .systemRole(user.getRole() != null ? user.getRole().name() : null)
                .accessRoleId(user.getAccessRole() != null ? user.getAccessRole().getId() : null)
                .accessRoleKey(accessRoleService.getRoleKey(user))
                .primaryProvider(user.getPrimaryProvider() != null ? user.getPrimaryProvider().name() : null)
                .hasGithubLinked(user.hasGithubLinked())
                .hasGitlabLinked(user.hasGitlabLinked())
                .hasLocalPassword(user.hasLocalPassword())
                .suspended(Boolean.TRUE.equals(user.getSuspended()))
                .permissions(accessRoleService.getEffectivePermissionNames(user))
                .createdAt(user.getCreatedAt())
                .aiProvider(user.getAiProvider())
                .aiModel(user.getAiModel())
                .hasCustomAiKey(user.hasCustomAiKey())
                .gitlabUrl(user.getGitlabUrl())
                .build();
    }

    // PATCH /api/users/me/ai-settings
    @PatchMapping("/me/ai-settings")
    public ResponseEntity<UserDto> updateAiSettings(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody AiSettingsRequest body) {
        User currentUser = userService.getRequiredUser(authHeader);
        User updated = userService.updateAiSettings(
                currentUser.getId(), body.aiProvider(), body.aiModel(), body.aiApiKey());
        return ResponseEntity.ok(toDto(updated));
    }

    // DELETE /api/users/me/ai-settings
    @DeleteMapping("/me/ai-settings")
    public ResponseEntity<UserDto> clearAiSettings(
            @RequestHeader(value = "Authorization", required = false) String authHeader) {
        User currentUser = userService.getRequiredUser(authHeader);
        User updated = userService.clearAiSettings(currentUser.getId());
        return ResponseEntity.ok(toDto(updated));
    }

    public record AiSettingsRequest(String aiProvider, String aiModel, String aiApiKey) {}

    private UserRole parseAllowedRole(String rawRole) {
        if (rawRole == null || rawRole.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role is required");
        }
        try {
            UserRole role = UserRole.valueOf(rawRole.trim().toUpperCase());
            if (role != UserRole.ADMIN && role != UserRole.EMPLOYEE) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role must be ADMIN or EMPLOYEE");
            }
            return role;
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role must be ADMIN or EMPLOYEE");
        }
    }

    public record CreateUserRequest(String login, String name, String email, String role, Long accessRoleId,
            String password) {
    }

    public record UpdateUserRequest(String login, String name, String email, String role, Long accessRoleId,
            String password) {
    }

    public record UpdateRoleRequest(String role, Long accessRoleId) {
    }

    public record UpdateSuspensionRequest(Boolean suspended) {
    }
}
