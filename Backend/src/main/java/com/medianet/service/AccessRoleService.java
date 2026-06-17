package com.medianet.service;

import com.medianet.entity.AccessPermission;
import com.medianet.entity.AccessRole;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.AccessRoleRepo;
import com.medianet.repository.UserRepo;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

@Service
@Transactional
public class AccessRoleService {

    private static final Pattern NON_ALNUM = Pattern.compile("[^A-Z0-9]+");

    private static final Set<AccessPermission> EMPLOYEE_DEFAULT_PERMISSIONS = EnumSet.of(
            AccessPermission.DASHBOARD,
            AccessPermission.REPOSITORIES,
            AccessPermission.SCANS,
            AccessPermission.VULNERABILITIES,
            AccessPermission.SSL_ANALYSIS,
            AccessPermission.SERVER_CONFIG,
            AccessPermission.PIPELINE,
            AccessPermission.PROFILE);

    private final AccessRoleRepo accessRoleRepo;
    private final UserRepo userRepo;

    public AccessRoleService(AccessRoleRepo accessRoleRepo, UserRepo userRepo) {
        this.accessRoleRepo = accessRoleRepo;
        this.userRepo = userRepo;
    }

    public void ensureSystemRoles() {
        AccessRole adminRole = ensureSystemRole(
                "ADMIN",
                "ADMIN",
                "Gère tous les utilisateurs, tous les projets, toutes les affectations et l’ensemble des scans.",
                UserRole.ADMIN,
                EnumSet.allOf(AccessPermission.class));

        AccessRole employeeRole = ensureSystemRole(
                "EMPLOYEE",
                "EMPLOYEE",
                "Voit les projets et dépôts qui lui sont affectés, lance des scans et consulte les résultats liés.",
                UserRole.EMPLOYEE,
                EMPLOYEE_DEFAULT_PERMISSIONS);

        List<User> users = userRepo.findAll();
        boolean dirty = false;
        for (User user : users) {
            if (user.getAccessRole() == null) {
                user.setAccessRole(user.getRole() == UserRole.ADMIN ? adminRole : employeeRole);
                dirty = true;
            }
            if (user.getAccessRole() != null && user.getRole() != user.getAccessRole().getBaseRole()) {
                user.setRole(user.getAccessRole().getBaseRole());
                dirty = true;
            }
            if (user.getSuspended() == null) {
                user.setSuspended(false);
                dirty = true;
            }
        }
        if (dirty) {
            userRepo.saveAll(users);
        }
    }

    public List<AccessRole> listRoles() {
        return accessRoleRepo.findAllByOrderBySystemRoleDescNameAsc();
    }

    public AccessRole getRequiredRole(Long id) {
        return accessRoleRepo.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found"));
    }

    public AccessRole resolveRoleAssignment(Long accessRoleId, UserRole fallbackBaseRole) {
        if (accessRoleId != null) {
            return getRequiredRole(accessRoleId);
        }
        return getSystemRole(fallbackBaseRole != null ? fallbackBaseRole : UserRole.EMPLOYEE);
    }

    public AccessRole getSystemRole(UserRole baseRole) {
        AccessRole role = accessRoleRepo.findByRoleKeyIgnoreCase(baseRole.name()).orElse(null);
        if (role != null) {
            return role;
        }
        ensureSystemRoles();
        return accessRoleRepo.findByRoleKeyIgnoreCase(baseRole.name())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "System role is missing"));
    }

    public AccessRole createRole(String name, String description, UserRole baseRole, Collection<String> permissionNames) {
        String resolvedName = requireName(name);
        UserRole resolvedBaseRole = baseRole != null ? baseRole : UserRole.EMPLOYEE;
        String roleKey = toRoleKey(resolvedName);

        if (accessRoleRepo.existsByRoleKeyIgnoreCase(roleKey)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Role already exists");
        }

        AccessRole role = AccessRole.builder()
                .roleKey(roleKey)
                .name(resolvedName)
                .description(normalizeDescription(description))
                .baseRole(resolvedBaseRole)
                .systemRole(false)
                .permissions(normalizePermissions(resolvedBaseRole, parsePermissionNames(permissionNames)))
                .build();

        return accessRoleRepo.save(role);
    }

    public AccessRole updateRole(Long id, String name, String description, UserRole requestedBaseRole,
            Collection<String> permissionNames) {
        AccessRole role = getRequiredRole(id);

        UserRole resolvedBaseRole = Boolean.TRUE.equals(role.getSystemRole())
                ? role.getBaseRole()
                : (requestedBaseRole != null ? requestedBaseRole : role.getBaseRole());

        role.setName(requireName(name));
        role.setDescription(normalizeDescription(description));
        role.setBaseRole(resolvedBaseRole);
        role.setPermissions(normalizePermissions(resolvedBaseRole, parsePermissionNames(permissionNames)));

        AccessRole savedRole = accessRoleRepo.save(role);
        synchronizeAssignedUsers(savedRole);
        return savedRole;
    }

    public void deleteRole(Long id) {
        AccessRole role = getRequiredRole(id);
        if (Boolean.TRUE.equals(role.getSystemRole())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "System roles cannot be deleted");
        }
        if (userRepo.existsByAccessRole_Id(id)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Role is still assigned to one or more users");
        }
        accessRoleRepo.delete(role);
    }

    public LinkedHashSet<AccessPermission> defaultPermissionsFor(UserRole baseRole) {
        return new LinkedHashSet<>(baseRole == UserRole.ADMIN
                ? EnumSet.allOf(AccessPermission.class)
                : EMPLOYEE_DEFAULT_PERMISSIONS);
    }

    public LinkedHashSet<AccessPermission> getEffectivePermissions(User user) {
        if (user != null && user.getAccessRole() != null && user.getAccessRole().getPermissions() != null
                && !user.getAccessRole().getPermissions().isEmpty()) {
            return normalizePermissions(user.getAccessRole().getBaseRole(), user.getAccessRole().getPermissions());
        }
        UserRole fallbackRole = user != null && user.getRole() != null ? user.getRole() : UserRole.EMPLOYEE;
        return defaultPermissionsFor(fallbackRole);
    }

    public List<String> getEffectivePermissionNames(User user) {
        return getEffectivePermissions(user).stream().map(Enum::name).toList();
    }

    public String getDisplayRoleName(User user) {
        if (user != null && user.getAccessRole() != null && user.getAccessRole().getName() != null
                && !user.getAccessRole().getName().isBlank()) {
            return user.getAccessRole().getName();
        }
        return user != null && user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name();
    }

    public String getRoleKey(User user) {
        if (user != null && user.getAccessRole() != null && user.getAccessRole().getRoleKey() != null
                && !user.getAccessRole().getRoleKey().isBlank()) {
            return user.getAccessRole().getRoleKey();
        }
        return user != null && user.getRole() != null ? user.getRole().name() : UserRole.EMPLOYEE.name();
    }

    public LinkedHashSet<AccessPermission> parsePermissionNames(Collection<String> permissionNames) {
        LinkedHashSet<AccessPermission> permissions = new LinkedHashSet<>();
        if (permissionNames == null) {
            return permissions;
        }
        for (String rawName : permissionNames) {
            if (rawName == null || rawName.isBlank()) {
                continue;
            }
            try {
                permissions.add(AccessPermission.valueOf(rawName.trim().toUpperCase(Locale.ROOT)));
            } catch (IllegalArgumentException ex) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown permission: " + rawName);
            }
        }
        return permissions;
    }

    private AccessRole ensureSystemRole(String roleKey, String name, String description, UserRole baseRole,
            Collection<AccessPermission> defaultPermissions) {
        AccessRole role = accessRoleRepo.findByRoleKeyIgnoreCase(roleKey).orElseGet(AccessRole::new);
        boolean dirty = false;

        if (role.getRoleKey() == null || role.getRoleKey().isBlank()) {
            role.setRoleKey(roleKey);
            dirty = true;
        }
        if (role.getName() == null || role.getName().isBlank()) {
            role.setName(name);
            dirty = true;
        }
        if (role.getDescription() == null || role.getDescription().isBlank()) {
            role.setDescription(description);
            dirty = true;
        }
        if (role.getBaseRole() != baseRole) {
            role.setBaseRole(baseRole);
            dirty = true;
        }
        if (!Boolean.TRUE.equals(role.getSystemRole())) {
            role.setSystemRole(true);
            dirty = true;
        }
        if (role.getPermissions() == null || role.getPermissions().isEmpty()) {
            role.setPermissions(normalizePermissions(baseRole, defaultPermissions));
            dirty = true;
        }

        return dirty || role.getId() == null ? accessRoleRepo.save(role) : role;
    }

    private void synchronizeAssignedUsers(AccessRole role) {
        List<User> assignedUsers = userRepo.findAllByAccessRole_Id(role.getId());
        boolean dirty = false;
        for (User user : assignedUsers) {
            if (user.getRole() != role.getBaseRole()) {
                user.setRole(role.getBaseRole());
                dirty = true;
            }
        }
        if (dirty) {
            userRepo.saveAll(assignedUsers);
        }
    }

    private LinkedHashSet<AccessPermission> normalizePermissions(UserRole baseRole,
            Collection<AccessPermission> requestedPermissions) {
        LinkedHashSet<AccessPermission> permissions = requestedPermissions == null
                ? new LinkedHashSet<>()
                : requestedPermissions.stream()
                        .filter(Objects::nonNull)
                        .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));

        if (baseRole != UserRole.ADMIN) {
            permissions.removeIf(permission -> permission.name().startsWith("ADMIN_"));
        }
        if (permissions.isEmpty()) {
            permissions.addAll(defaultPermissionsFor(baseRole));
        }
        return permissions;
    }

    private String requireName(String name) {
        if (name == null || name.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role name is required");
        }
        return name.trim();
    }

    private String normalizeDescription(String description) {
        return description != null && !description.isBlank() ? description.trim() : null;
    }

    private String toRoleKey(String name) {
        String normalized = NON_ALNUM.matcher(name.trim().toUpperCase(Locale.ROOT)).replaceAll("_");
        normalized = normalized.replaceAll("^_+|_+$", "").replaceAll("_+", "_");
        if (normalized.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Role name is invalid");
        }
        return normalized;
    }
}