package com.medianet.service;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.UserRepo;
import com.medianet.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests unitaires pour les méthodes d'authentification et d'autorisation de {@link UserService}.
 * Utilise Mockito pour simuler JwtUtil et UserRepo — aucune BDD requise.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService — authentification et autorisation")
class UserServiceTest {

    @Mock private UserRepo userRepo;
    @Mock private AccessRoleService accessRoleService;
    @Mock private TokenEncryptionService tokenEncryptionService;
    @Mock private JwtUtil jwtUtil;
    @Mock private org.springframework.jdbc.core.JdbcTemplate jdbcTemplate;
    @Mock private AiGatewayService aiGatewayService;
    @Mock private GitLabService gitLabService;

    private UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(
                userRepo, accessRoleService, tokenEncryptionService, jwtUtil, jdbcTemplate, aiGatewayService,
                gitLabService);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // getRequiredUser
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("getRequiredUser() → lève 401 si le token est absent (userId null)")
    void getRequiredUser_echoueSiTokenAbsent() {
        when(jwtUtil.extractUserId(null)).thenReturn(null);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.getRequiredUser(null),
            "getRequiredUser() devrait lancer 401 si l'en-tête Authorization est null");

        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatusCode());
    }

    @Test
    @DisplayName("getRequiredUser() → lève 401 si le userId extrait est null (token invalide)")
    void getRequiredUser_echoueSiTokenInvalide() {
        when(jwtUtil.extractUserId("Bearer token.invalide")).thenReturn(null);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.getRequiredUser("Bearer token.invalide"),
            "getRequiredUser() devrait lancer 401 si le token ne contient pas d'userId valide");

        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatusCode());
    }

    @Test
    @DisplayName("getRequiredUser() → lève 401 si l'userId n'est pas trouvé en BDD")
    void getRequiredUser_echoueSiUserIdInconnu() {
        when(jwtUtil.extractUserId("Bearer valid.token")).thenReturn(999L);
        when(userRepo.findById(999L)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.getRequiredUser("Bearer valid.token"),
            "getRequiredUser() devrait lancer 401 si l'userId n'existe pas en BDD");

        assertEquals(HttpStatus.UNAUTHORIZED, ex.getStatusCode());
    }

    @Test
    @DisplayName("getRequiredUser() → lève 403 si le compte est suspendu")
    void getRequiredUser_echoueSiCompteSuspendu() {
        User suspended = buildUser(5L, UserRole.EMPLOYEE, true);

        when(jwtUtil.extractUserId("Bearer valid.token")).thenReturn(5L);
        when(userRepo.findById(5L)).thenReturn(Optional.of(suspended));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.getRequiredUser("Bearer valid.token"),
            "getRequiredUser() devrait lancer 403 si le compte est suspendu");

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
    }

    @Test
    @DisplayName("getRequiredUser() → retourne l'utilisateur si le token est valide et le compte actif")
    void getRequiredUser_retourneUserSiTokenValide() {
        User activeUser = buildUser(1L, UserRole.ADMIN, false);

        when(jwtUtil.extractUserId("Bearer good.token")).thenReturn(1L);
        when(userRepo.findById(1L)).thenReturn(Optional.of(activeUser));

        User result = userService.getRequiredUser("Bearer good.token");

        assertNotNull(result);
        assertEquals(1L, result.getId());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // requireRole
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("requireRole() → lève 403 si le rôle est insuffisant (EMPLOYEE vs ADMIN requis)")
    void requireRole_echoueSiRoleInsuffisant() {
        User employee = buildUser(2L, UserRole.EMPLOYEE, false);

        when(jwtUtil.extractUserId("Bearer emp.token")).thenReturn(2L);
        when(userRepo.findById(2L)).thenReturn(Optional.of(employee));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.requireRole("Bearer emp.token", UserRole.ADMIN),
            "requireRole() devrait lancer 403 si l'utilisateur n'a pas le rôle requis");

        assertEquals(HttpStatus.FORBIDDEN, ex.getStatusCode());
    }

    @Test
    @DisplayName("requireRole() → retourne l'utilisateur si le rôle correspond")
    void requireRole_retourneUserSiRoleCorrect() {
        User admin = buildUser(1L, UserRole.ADMIN, false);

        when(jwtUtil.extractUserId("Bearer admin.token")).thenReturn(1L);
        when(userRepo.findById(1L)).thenReturn(Optional.of(admin));

        User result = userService.requireRole("Bearer admin.token", UserRole.ADMIN);

        assertNotNull(result);
        assertEquals(UserRole.ADMIN, result.getRole());
    }

    @Test
    @DisplayName("requireRole() → accepte si l'utilisateur correspond à l'un des rôles autorisés")
    void requireRole_accepteMultiplesRolesAutorises() {
        User employee = buildUser(3L, UserRole.EMPLOYEE, false);

        when(jwtUtil.extractUserId("Bearer emp.token")).thenReturn(3L);
        when(userRepo.findById(3L)).thenReturn(Optional.of(employee));

        // ADMIN ou EMPLOYEE sont tous les deux autorisés
        User result = userService.requireRole("Bearer emp.token", UserRole.ADMIN, UserRole.EMPLOYEE);

        assertNotNull(result);
        assertEquals(UserRole.EMPLOYEE, result.getRole());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // createLocalUser — validation
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("createLocalUser() → lève 400 si l'email est absent")
    void createLocalUser_echoueSiEmailAbsent() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.createLocalUser("login", "Nom", null, "Password@1", null, UserRole.EMPLOYEE),
            "createLocalUser() devrait lancer 400 si l'email est null");

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
    }

    @Test
    @DisplayName("createLocalUser() → lève 400 si le mot de passe est absent")
    void createLocalUser_echoueSiMotDePasseAbsent() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.createLocalUser("login", "Nom", "test@test.com", null, null, UserRole.EMPLOYEE),
            "createLocalUser() devrait lancer 400 si le mot de passe est null");

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
    }

    @Test
    @DisplayName("createLocalUser() → lève 409 si l'email existe déjà")
    void createLocalUser_echoueSiEmailDejaExistant() {
        User existingUser = buildUser(10L, UserRole.EMPLOYEE, false);
        existingUser.setEmail("duplicate@test.com");

        when(userRepo.findByEmailIgnoreCase("duplicate@test.com"))
                .thenReturn(Optional.of(existingUser));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
            () -> userService.createLocalUser(null, "Nom", "duplicate@test.com", "Password@1", null, UserRole.EMPLOYEE),
            "createLocalUser() devrait lancer 409 si l'email existe déjà");

        assertEquals(HttpStatus.CONFLICT, ex.getStatusCode());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helper
    // ──────────────────────────────────────────────────────────────────────────

    private User buildUser(Long id, UserRole role, boolean suspended) {
        User user = User.builder()
                .login("user-" + id)
                .role(role)
                .suspended(suspended)
                .primaryProvider(AuthProvider.LOCAL)
                .build();
        user.setId(id);
        return user;
    }
}
