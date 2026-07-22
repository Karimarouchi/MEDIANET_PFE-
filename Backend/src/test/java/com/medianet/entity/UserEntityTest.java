package com.medianet.entity;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour les méthodes helper de l'entité {@link User}.
 * Chaque test vérifie une fonctionnalité précise — si un test échoue,
 * le nom du test indique exactement quelle méthode ne fonctionne plus.
 */
@DisplayName("User — méthodes helper")
class UserEntityTest {

    // ──────────────────────────────────────────────────────────────────────────
    // hasGithubLinked
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hasGithubLinked() → false quand ghToken est null")
    void hasGithubLinked_falseQuandTokenNull() {
        User user = User.builder().login("test").ghToken(null).build();
        assertFalse(user.hasGithubLinked(),
            "hasGithubLinked() devrait retourner false quand ghToken est null");
    }

    @Test
    @DisplayName("hasGithubLinked() → false quand ghToken est vide")
    void hasGithubLinked_falseQuandTokenVide() {
        User user = User.builder().login("test").ghToken("  ").build();
        assertFalse(user.hasGithubLinked(),
            "hasGithubLinked() devrait retourner false quand ghToken est un espace");
    }

    @Test
    @DisplayName("hasGithubLinked() → true quand ghToken est présent")
    void hasGithubLinked_trueQuandTokenPresent() {
        User user = User.builder().login("test").ghToken("gho_abc123").build();
        assertTrue(user.hasGithubLinked(),
            "hasGithubLinked() devrait retourner true quand ghToken est renseigné");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // hasGitlabLinked
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hasGitlabLinked() → false quand glToken est null")
    void hasGitlabLinked_falseQuandTokenNull() {
        User user = User.builder().login("test").glToken(null).build();
        assertFalse(user.hasGitlabLinked(),
            "hasGitlabLinked() devrait retourner false quand glToken est null");
    }

    @Test
    @DisplayName("hasGitlabLinked() → false quand glToken est vide")
    void hasGitlabLinked_falseQuandTokenVide() {
        User user = User.builder().login("test").glToken("").build();
        assertFalse(user.hasGitlabLinked(),
            "hasGitlabLinked() devrait retourner false quand glToken est vide");
    }

    @Test
    @DisplayName("hasGitlabLinked() → true quand glToken est présent")
    void hasGitlabLinked_trueQuandTokenPresent() {
        User user = User.builder().login("test").glToken("glpat_xyz789").build();
        assertTrue(user.hasGitlabLinked(),
            "hasGitlabLinked() devrait retourner true quand glToken est renseigné");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // hasLocalPassword
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hasLocalPassword() → false quand passwordHash est null")
    void hasLocalPassword_falseQuandHashNull() {
        User user = User.builder().login("test").passwordHash(null).build();
        assertFalse(user.hasLocalPassword(),
            "hasLocalPassword() devrait retourner false quand passwordHash est null");
    }

    @Test
    @DisplayName("hasLocalPassword() → false quand passwordHash est vide")
    void hasLocalPassword_falseQuandHashVide() {
        User user = User.builder().login("test").passwordHash("").build();
        assertFalse(user.hasLocalPassword(),
            "hasLocalPassword() devrait retourner false quand passwordHash est vide");
    }

    @Test
    @DisplayName("hasLocalPassword() → true quand passwordHash est présent")
    void hasLocalPassword_trueQuandHashPresent() {
        User user = User.builder().login("test").passwordHash("$2a$10$abc").build();
        assertTrue(user.hasLocalPassword(),
            "hasLocalPassword() devrait retourner true quand passwordHash est renseigné");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // hasDockerHubLinked
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hasDockerHubLinked() → false quand username et token sont null")
    void hasDockerHubLinked_falseQuandToutNull() {
        User user = User.builder().login("test")
                .dockerHubUsername(null).dockerHubToken(null).build();
        assertFalse(user.hasDockerHubLinked(),
            "hasDockerHubLinked() devrait retourner false quand username et token sont null");
    }

    @Test
    @DisplayName("hasDockerHubLinked() → false quand username présent mais token null")
    void hasDockerHubLinked_falseQuandTokenNull() {
        User user = User.builder().login("test")
                .dockerHubUsername("myuser").dockerHubToken(null).build();
        assertFalse(user.hasDockerHubLinked(),
            "hasDockerHubLinked() devrait retourner false quand token est null");
    }

    @Test
    @DisplayName("hasDockerHubLinked() → true quand username ET token sont présents")
    void hasDockerHubLinked_trueQuandToutPresent() {
        User user = User.builder().login("test")
                .dockerHubUsername("myuser").dockerHubToken("dckr_pat_xyz").build();
        assertTrue(user.hasDockerHubLinked(),
            "hasDockerHubLinked() devrait retourner true quand username et token sont renseignés");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // hasCustomAiKey
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("hasCustomAiKey() → false quand aiApiKey est null")
    void hasCustomAiKey_falseQuandKeyNull() {
        User user = User.builder().login("test")
                .aiApiKey(null).aiProvider("GEMINI").build();
        assertFalse(user.hasCustomAiKey(),
            "hasCustomAiKey() devrait retourner false quand aiApiKey est null");
    }

    @Test
    @DisplayName("hasCustomAiKey() → false quand aiProvider est null")
    void hasCustomAiKey_falseQuandProviderNull() {
        User user = User.builder().login("test")
                .aiApiKey("sk-abc").aiProvider(null).build();
        assertFalse(user.hasCustomAiKey(),
            "hasCustomAiKey() devrait retourner false quand aiProvider est null");
    }

    @Test
    @DisplayName("hasCustomAiKey() → true quand aiApiKey ET aiProvider sont présents")
    void hasCustomAiKey_trueQuandKeyEtProviderPresents() {
        User user = User.builder().login("test")
                .aiApiKey("sk-abc123").aiProvider("GEMINI").build();
        assertTrue(user.hasCustomAiKey(),
            "hasCustomAiKey() devrait retourner true quand apiKey et provider sont renseignés");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Valeurs par défaut (@PrePersist / @Builder.Default)
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("User.builder() → rôle par défaut est EMPLOYEE")
    void builderDefault_roleEstEmployee() {
        User user = User.builder().login("test").build();
        assertEquals(UserRole.EMPLOYEE, user.getRole(),
            "Le rôle par défaut d'un User devrait être EMPLOYEE");
    }

    @Test
    @DisplayName("User.builder() → suspended par défaut est false")
    void builderDefault_suspendedEstFalse() {
        User user = User.builder().login("test").build();
        assertFalse(user.getSuspended(),
            "Le champ suspended par défaut devrait être false");
    }

    @Test
    @DisplayName("User.builder() → primaryProvider par défaut est GITHUB")
    void builderDefault_primaryProviderEstGithub() {
        User user = User.builder().login("test").build();
        assertEquals(AuthProvider.GITHUB, user.getPrimaryProvider(),
            "Le primaryProvider par défaut devrait être GITHUB");
    }
}
