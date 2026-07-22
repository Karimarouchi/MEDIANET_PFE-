package com.medianet.service;

import com.medianet.entity.AccessPermission;
import com.medianet.entity.AccessRole;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.AccessRoleRepo;
import com.medianet.repository.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour {@link AccessRoleService}.
 * Vérifie la gestion des permissions, la suppression des rôles système,
 * et la logique de normalisation des clés de rôle.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("AccessRoleService — gestion des rôles et permissions")
class AccessRoleServiceTest {

    @Mock private AccessRoleRepo accessRoleRepo;
    @Mock private UserRepo userRepo;

    private AccessRoleService accessRoleService;

    @BeforeEach
    void setUp() {
        accessRoleService = new AccessRoleService(accessRoleRepo, userRepo);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // parsePermissionNames — méthode publique
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("parsePermissionNames() → retourne un ensemble vide pour null")
    void parsePermissionNames_retourneVidePourNull() {
        LinkedHashSet<AccessPermission> result = accessRoleService.parsePermissionNames(null);
        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("parsePermissionNames() → convertit des noms valides en permissions")
    void parsePermissionNames_convertitNomsValides() {
        LinkedHashSet<AccessPermission> result = accessRoleService.parsePermissionNames(
                List.of("DASHBOARD", "SCANS", "VULNERABILITIES"));

        assertThat(result).containsExactlyInAnyOrder(
                AccessPermission.DASHBOARD,
                AccessPermission.SCANS,
                AccessPermission.VULNERABILITIES);
    }

    @Test
    @DisplayName("parsePermissionNames() → insensible à la casse")
    void parsePermissionNames_insensibleALaCasse() {
        LinkedHashSet<AccessPermission> result = accessRoleService.parsePermissionNames(
                List.of("dashboard", "Scans"));

        assertThat(result).contains(AccessPermission.DASHBOARD, AccessPermission.SCANS);
    }

    @Test
    @DisplayName("parsePermissionNames() → lève 400 pour une permission inconnue")
    void parsePermissionNames_lanceBadRequestPourPermissionInconnue() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> accessRoleService.parsePermissionNames(List.of("PERMISSION_QUI_NEXISTE_PAS")),
            "parsePermissionNames() devrait lancer 400 pour une permission inconnue");

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
    }

    @Test
    @DisplayName("parsePermissionNames() → ignore les entrées vides/null")
    void parsePermissionNames_ignoreEntreesVidesEtNull() {
        LinkedHashSet<AccessPermission> result = accessRoleService.parsePermissionNames(
                List.of("DASHBOARD", "", "  "));

        assertThat(result).containsExactly(AccessPermission.DASHBOARD);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // defaultPermissionsFor
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("defaultPermissionsFor(ADMIN) → contient toutes les permissions")
    void defaultPermissionsFor_adminAToutes() {
        LinkedHashSet<AccessPermission> result = accessRoleService.defaultPermissionsFor(UserRole.ADMIN);
        assertThat(result).containsAll(EnumSet.allOf(AccessPermission.class));
    }

    @Test
    @DisplayName("defaultPermissionsFor(EMPLOYEE) → ne contient pas ADMIN_USERS ni ADMIN_ROLES")
    void defaultPermissionsFor_employeeSansPermissionsAdmin() {
        LinkedHashSet<AccessPermission> result = accessRoleService.defaultPermissionsFor(UserRole.EMPLOYEE);
        assertThat(result)
                .doesNotContain(AccessPermission.ADMIN_USERS)
                .doesNotContain(AccessPermission.ADMIN_ROLES)
                .doesNotContain(AccessPermission.ADMIN_PROJECTS);
    }

    @Test
    @DisplayName("defaultPermissionsFor(EMPLOYEE) → contient DASHBOARD, SCANS, VULNERABILITIES")
    void defaultPermissionsFor_employeeAPermissionsDeBase() {
        LinkedHashSet<AccessPermission> result = accessRoleService.defaultPermissionsFor(UserRole.EMPLOYEE);
        assertThat(result).contains(
                AccessPermission.DASHBOARD,
                AccessPermission.SCANS,
                AccessPermission.VULNERABILITIES,
                AccessPermission.SSL_ANALYSIS,
                AccessPermission.PROFILE);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getEffectivePermissions
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getEffectivePermissions() → retourne les permissions du rôle si accessRole est défini")
    void getEffectivePermissions_utiliseLesPermissionsDeAccessRole() {
        AccessRole role = AccessRole.builder()
                .roleKey("CUSTOM")
                .name("Custom Role")
                .baseRole(UserRole.EMPLOYEE)
                .systemRole(false)
                .permissions(EnumSet.of(AccessPermission.DASHBOARD, AccessPermission.SCANS))
                .build();

        User user = User.builder()
                .login("test")
                .role(UserRole.EMPLOYEE)
                .accessRole(role)
                .build();

        LinkedHashSet<AccessPermission> result = accessRoleService.getEffectivePermissions(user);
        assertThat(result).contains(AccessPermission.DASHBOARD, AccessPermission.SCANS);
    }

    @Test
    @DisplayName("getEffectivePermissions() → retourne les permissions par défaut si pas de accessRole")
    void getEffectivePermissions_fallbackAuxPermissionsParDefaut() {
        User user = User.builder()
                .login("test")
                .role(UserRole.EMPLOYEE)
                .accessRole(null)
                .build();

        LinkedHashSet<AccessPermission> result = accessRoleService.getEffectivePermissions(user);
        assertThat(result).isNotEmpty();
        assertThat(result).contains(AccessPermission.DASHBOARD);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // deleteRole — contrôle d'accès
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("deleteRole() → lève 400 si le rôle est un rôle système")
    void deleteRole_echouePourRoleSysteme() {
        AccessRole systemRole = AccessRole.builder()
                .roleKey("ADMIN")
                .name("Admin")
                .baseRole(UserRole.ADMIN)
                .systemRole(true)
                .build();
        systemRole.setId(1L);

        when(accessRoleRepo.findById(1L)).thenReturn(java.util.Optional.of(systemRole));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> accessRoleService.deleteRole(1L),
            "deleteRole() devrait lancer 400 pour un rôle système");

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
        verify(accessRoleRepo, never()).delete(any());
    }

    @Test
    @DisplayName("deleteRole() → lève 409 si le rôle est encore assigné à des utilisateurs")
    void deleteRole_echoueSiRoleAssigneADesUtilisateurs() {
        AccessRole customRole = AccessRole.builder()
                .roleKey("CUSTOM_ROLE")
                .name("Custom")
                .baseRole(UserRole.EMPLOYEE)
                .systemRole(false)
                .build();
        customRole.setId(5L);

        when(accessRoleRepo.findById(5L)).thenReturn(java.util.Optional.of(customRole));
        when(userRepo.existsByAccessRole_Id(5L)).thenReturn(true);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> accessRoleService.deleteRole(5L),
            "deleteRole() devrait lancer 409 si des utilisateurs ont encore ce rôle");

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
        verify(accessRoleRepo, never()).delete(any());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getDisplayRoleName / getRoleKey
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getDisplayRoleName() → retourne le nom du accessRole si défini")
    void getDisplayRoleName_retourneNomAccessRole() {
        AccessRole role = AccessRole.builder().roleKey("CUSTOM").name("Mon Rôle").build();
        User user = User.builder().login("u").role(UserRole.EMPLOYEE).accessRole(role).build();

        assertEquals("Mon Rôle", accessRoleService.getDisplayRoleName(user));
    }

    @Test
    @DisplayName("getDisplayRoleName() → retourne le nom du UserRole si pas de accessRole")
    void getDisplayRoleName_fallbackAuUserRole() {
        User user = User.builder().login("u").role(UserRole.ADMIN).accessRole(null).build();
        assertEquals("ADMIN", accessRoleService.getDisplayRoleName(user));
    }

    @Test
    @DisplayName("getDisplayRoleName() → retourne EMPLOYEE si user est null")
    void getDisplayRoleName_retourneEmployeeSiUserNull() {
        assertEquals("EMPLOYEE", accessRoleService.getDisplayRoleName(null));
    }
}
