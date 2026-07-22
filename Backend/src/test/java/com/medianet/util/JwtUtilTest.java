package com.medianet.util;

import com.medianet.entity.AuthProvider;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour {@link JwtUtil}.
 * Vérifie la génération, l'extraction et la validation des tokens JWT.
 * Si un test échoue, le nom du test indique exactement quelle méthode est cassée.
 */
@DisplayName("JwtUtil — génération et validation JWT")
class JwtUtilTest {

    /** Clé de 64 caractères minimum pour HS256 avec la librairie JJWT. */
    private static final String SECRET =
            "medianet-test-secret-key-at-least-64-characters-long-for-hs256-ok";

    private JwtUtil jwtUtil;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        // Injection de la valeur @Value via ReflectionTestUtils (sans Spring Context)
        ReflectionTestUtils.setField(jwtUtil, "jwtSecret", SECRET);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // generateToken + extractUserId
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("generateToken() → retourne un JWT non vide")
    void generateToken_retourneJwtNonVide() {
        User user = buildAdminUser(42L);
        String token = jwtUtil.generateToken(user);
        assertNotNull(token, "generateToken() ne devrait pas retourner null");
        assertFalse(token.isBlank(), "generateToken() ne devrait pas retourner un token vide");
        assertTrue(token.contains("."), "Un JWT valide doit contenir des points '.'");
    }

    @Test
    @DisplayName("extractUserId() → extrait l'id correct depuis l'en-tête Authorization")
    void extractUserId_extraitLIdDepuisAuthHeader() {
        User user = buildAdminUser(99L);
        String token = jwtUtil.generateToken(user);
        String authHeader = "Bearer " + token;

        Long extractedId = jwtUtil.extractUserId(authHeader);
        assertEquals(99L, extractedId,
            "extractUserId() devrait retourner l'id de l'utilisateur encodé dans le JWT");
    }

    @Test
    @DisplayName("extractUserId() → retourne null si l'en-tête est null")
    void extractUserId_retourneNullSiHeaderNull() {
        Long result = jwtUtil.extractUserId(null);
        assertNull(result,
            "extractUserId() devrait retourner null si l'en-tête Authorization est null");
    }

    @Test
    @DisplayName("extractUserId() → retourne null si le préfixe Bearer est absent")
    void extractUserId_retourneNullSiPrefixeAbsent() {
        User user = buildAdminUser(10L);
        String token = jwtUtil.generateToken(user);
        // Header sans "Bearer "
        Long result = jwtUtil.extractUserId(token);
        assertNull(result,
            "extractUserId() devrait retourner null si le préfixe 'Bearer ' est absent");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // extractLogin
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("extractLogin() → extrait le login correct")
    void extractLogin_extraitLeLoginCorrectement() {
        User user = buildAdminUser(1L);
        user.setLogin("alice");
        String token = jwtUtil.generateToken(user);

        String login = jwtUtil.extractLogin("Bearer " + token);
        assertEquals("alice", login,
            "extractLogin() devrait retourner le login encodé dans le JWT");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // extractRole
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("extractRole() → retourne ADMIN pour un token ADMIN")
    void extractRole_retourneAdminPourTokenAdmin() {
        User user = buildAdminUser(1L);
        String token = jwtUtil.generateToken(user);

        UserRole role = jwtUtil.extractRole("Bearer " + token);
        assertEquals(UserRole.ADMIN, role,
            "extractRole() devrait retourner ADMIN pour un utilisateur ADMIN");
    }

    @Test
    @DisplayName("extractRole() → retourne null si le token est invalide")
    void extractRole_retourneNullPourTokenInvalide() {
        UserRole role = jwtUtil.extractRole("Bearer token.invalide.ici");
        assertNull(role,
            "extractRole() devrait retourner null pour un token malformé");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // parseClaimsFromAuthHeader
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("parseClaimsFromAuthHeader() → retourne null pour un token invalide")
    void parseClaims_retourneNullPourTokenInvalide() {
        var claims = jwtUtil.parseClaimsFromAuthHeader("Bearer this.is.not.a.jwt");
        assertNull(claims,
            "parseClaimsFromAuthHeader() devrait retourner null pour un token invalide");
    }

    @Test
    @DisplayName("parseClaimsFromAuthHeader() → retourne null si l'en-tête est null")
    void parseClaims_retourneNullSiHeaderNull() {
        var claims = jwtUtil.parseClaimsFromAuthHeader(null);
        assertNull(claims,
            "parseClaimsFromAuthHeader() devrait retourner null si l'en-tête est null");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // generateProviderLinkState + isValidProviderLinkState
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("isValidProviderLinkState() → true quand state valide pour GITHUB")
    void isValidProviderLinkState_trueQuandStateGithub() {
        String state = jwtUtil.generateProviderLinkState(7L, AuthProvider.GITHUB);
        assertTrue(jwtUtil.isValidProviderLinkState(state, AuthProvider.GITHUB),
            "isValidProviderLinkState() devrait retourner true pour un state GITHUB valide");
    }

    @Test
    @DisplayName("isValidProviderLinkState() → true quand state valide pour GITLAB")
    void isValidProviderLinkState_trueQuandStateGitlab() {
        String state = jwtUtil.generateProviderLinkState(7L, AuthProvider.GITLAB);
        assertTrue(jwtUtil.isValidProviderLinkState(state, AuthProvider.GITLAB),
            "isValidProviderLinkState() devrait retourner true pour un state GITLAB valide");
    }

    @Test
    @DisplayName("isValidProviderLinkState() → false quand le provider ne correspond pas")
    void isValidProviderLinkState_falseQuandMauvaisProvider() {
        // State généré pour GITHUB mais validé pour GITLAB
        String state = jwtUtil.generateProviderLinkState(7L, AuthProvider.GITHUB);
        assertFalse(jwtUtil.isValidProviderLinkState(state, AuthProvider.GITLAB),
            "isValidProviderLinkState() devrait retourner false si le provider ne correspond pas");
    }

    @Test
    @DisplayName("isValidProviderLinkState() → false pour un state invalide")
    void isValidProviderLinkState_falseQuandStateInvalide() {
        assertFalse(jwtUtil.isValidProviderLinkState("token.invalide", AuthProvider.GITHUB),
            "isValidProviderLinkState() devrait retourner false pour un state malformé");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helper
    // ──────────────────────────────────────────────────────────────────────────

    private User buildAdminUser(Long id) {
        User user = User.builder()
                .login("admin-test")
                .name("Admin Test")
                .role(UserRole.ADMIN)
                .primaryProvider(AuthProvider.LOCAL)
                .suspended(false)
                .build();
        user.setId(id);
        return user;
    }
}
