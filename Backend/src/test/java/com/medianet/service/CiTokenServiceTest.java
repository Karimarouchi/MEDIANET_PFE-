package com.medianet.service;

import com.medianet.dto.CiTokenCreatedDto;
import com.medianet.dto.CiTokenDto;
import com.medianet.entity.CiToken;
import com.medianet.entity.Client;
import com.medianet.entity.ClientRepositoryId;
import com.medianet.entity.Repository;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.CiTokenRepo;
import com.medianet.repository.ClientRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.RepositoryRepo;
import com.medianet.security.CiPrincipal;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("CiTokenService — jetons CI vx_live_")
class CiTokenServiceTest {

    @Mock private CiTokenRepo ciTokenRepo;
    @Mock private ClientRepo clientRepo;
    @Mock private ClientRepositoryRepo clientRepositoryRepo;
    @Mock private RepositoryRepo repositoryRepo;

    private CiTokenService ciTokenService;

    @BeforeEach
    void setUp() {
        ciTokenService = new CiTokenService(ciTokenRepo, clientRepo, clientRepositoryRepo, repositoryRepo);
    }

    @Test
    @DisplayName("createToken() → persiste le SHA-256, jamais le plaintext, préfixe vx_live_")
    void createToken_hashesPlaintextAndReturnsSecretOnce() {
        User admin = admin();
        Client client = client(12L, "CourtLinker");
        Repository repo = repository(7L, "https://github.com/org/app");

        when(clientRepo.findById(12L)).thenReturn(Optional.of(client));
        when(clientRepositoryRepo.existsById(new ClientRepositoryId(12L, 7L))).thenReturn(true);
        when(repositoryRepo.findById(7L)).thenReturn(Optional.of(repo));
        when(ciTokenRepo.save(any(CiToken.class))).thenAnswer(invocation -> {
            CiToken token = invocation.getArgument(0);
            token.setId(1L);
            return token;
        });

        CiTokenCreatedDto created = ciTokenService.createToken(admin, "GitHub Actions", 12L, List.of(7L), 90);

        assertThat(created.token()).startsWith("vx_live_");
        assertThat(created.token()).hasSizeGreaterThan(20);
        assertThat(created.tokenPrefix()).isEqualTo(created.token().substring(0, 16));
        assertThat(created.clientId()).isEqualTo(12L);
        assertThat(created.repositoryIds()).containsExactly(7L);
        assertThat(created.scopes()).contains("ci:scan", "ci:verdict");

        ArgumentCaptor<CiToken> captor = ArgumentCaptor.forClass(CiToken.class);
        verify(ciTokenRepo).save(captor.capture());
        CiToken persisted = captor.getValue();
        assertThat(persisted.getTokenHash()).isEqualTo(CiTokenService.hashToken(created.token()));
        assertThat(persisted.getTokenHash()).hasSize(64);
        assertThat(persisted.getTokenHash()).doesNotContain("vx_live_");
        assertThat(persisted.getExpiresAt()).isAfter(Instant.now().plus(89, ChronoUnit.DAYS));
    }

    @Test
    @DisplayName("createToken() → refuse un dépôt qui n'est pas lié au client")
    void createToken_rejectsRepoNotLinkedToClient() {
        when(clientRepo.findById(12L)).thenReturn(Optional.of(client(12L, "Acme")));
        when(clientRepositoryRepo.existsById(new ClientRepositoryId(12L, 99L))).thenReturn(false);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> ciTokenService.createToken(admin(), "CI", 12L, List.of(99L), 90));

        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(ciTokenRepo, never()).save(any());
    }

    @Test
    @DisplayName("createToken() → refuse un nom vide")
    void createToken_rejectsBlankName() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> ciTokenService.createToken(admin(), "  ", 12L, List.of(7L), 90));
        assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("authenticate() → jeton actif → principal scoped")
    void authenticate_activeTokenReturnsPrincipal() {
        String raw = "vx_live_abcdefghijklmnopqrstuvwx";
        CiToken token = activeToken(raw);

        when(ciTokenRepo.findDetailedByTokenHash(CiTokenService.hashToken(raw))).thenReturn(Optional.of(token));
        when(ciTokenRepo.save(token)).thenReturn(token);

        Optional<CiPrincipal> principal = ciTokenService.authenticate(raw);

        assertThat(principal).isPresent();
        assertThat(principal.get().clientId()).isEqualTo(12L);
        assertThat(principal.get().repositoryIds()).containsExactly(7L);
        assertThat(principal.get().hasScope("ci:scan")).isTrue();
        assertThat(principal.get().canAccessRepository(7L)).isTrue();
        assertThat(principal.get().canAccessRepository(99L)).isFalse();
        assertThat(token.getLastUsedAt()).isNotNull();
    }

    @Test
    @DisplayName("authenticate() → jeton révoqué → vide")
    void authenticate_revokedTokenRejected() {
        String raw = "vx_live_abcdefghijklmnopqrstuvwx";
        CiToken token = activeToken(raw);
        token.setRevokedAt(Instant.now());
        when(ciTokenRepo.findDetailedByTokenHash(CiTokenService.hashToken(raw))).thenReturn(Optional.of(token));

        assertThat(ciTokenService.authenticate(raw)).isEmpty();
        verify(ciTokenRepo, never()).save(any());
    }

    @Test
    @DisplayName("authenticate() → jeton expiré → vide")
    void authenticate_expiredTokenRejected() {
        String raw = "vx_live_abcdefghijklmnopqrstuvwx";
        CiToken token = activeToken(raw);
        token.setExpiresAt(Instant.now().minusSeconds(60));
        when(ciTokenRepo.findDetailedByTokenHash(CiTokenService.hashToken(raw))).thenReturn(Optional.of(token));

        assertThat(ciTokenService.authenticate(raw)).isEmpty();
    }

    @Test
    @DisplayName("authenticate() → jeton inconnu → vide")
    void authenticate_unknownTokenRejected() {
        when(ciTokenRepo.findDetailedByTokenHash(any())).thenReturn(Optional.empty());
        assertThat(ciTokenService.authenticate("vx_live_unknownsecrethere123456")).isEmpty();
        verify(ciTokenRepo, never()).save(any());
    }

    @Test
    @DisplayName("authenticate() → JWT utilisateur → vide sans requête SQL")
    void authenticate_userJwtRejectedWithoutLookup() {
        assertThat(ciTokenService.authenticate("eyJhbGciOiJIUzI1NiJ9.aaa.bbb")).isEmpty();
        verify(ciTokenRepo, never()).findDetailedByTokenHash(any());
    }

    @Test
    @DisplayName("revoke() → pose revokedAt et le jeton n'est plus actif")
    void revoke_setsRevokedAt() {
        CiToken token = activeToken("vx_live_abcdefghijklmnopqrstuvwx");
        token.setId(5L);
        when(ciTokenRepo.findById(5L)).thenReturn(Optional.of(token));
        when(ciTokenRepo.save(token)).thenReturn(token);

        CiTokenDto dto = ciTokenService.revoke(5L);

        assertThat(dto.revokedAt()).isNotNull();
        assertThat(dto.active()).isFalse();
        assertThat(token.isActive()).isFalse();
    }

    @Test
    @DisplayName("listByClient() → n'expose jamais le plaintext")
    void listByClient_doesNotExposeSecret() {
        CiToken token = activeToken("vx_live_abcdefghijklmnopqrstuvwx");
        token.setId(3L);
        when(clientRepo.existsById(12L)).thenReturn(true);
        when(ciTokenRepo.findDetailedByClientId(12L)).thenReturn(List.of(token));

        List<CiTokenDto> listed = ciTokenService.listByClient(12L);

        assertThat(listed).hasSize(1);
        assertThat(listed.get(0).tokenPrefix()).isEqualTo(token.getTokenPrefix());
        assertThat(listed.get(0).active()).isTrue();
    }

    @Test
    @DisplayName("isCiTokenValue() → accepte vx_live_ / vx_test_, refuse le reste")
    void isCiTokenValue_prefixCheck() {
        assertThat(CiTokenService.isCiTokenValue("vx_live_abcdefghijklmnopqrstuvwx")).isTrue();
        assertThat(CiTokenService.isCiTokenValue("vx_test_abcdefghijklmnopqrstuvwx")).isTrue();
        assertThat(CiTokenService.isCiTokenValue("vx_live_short")).isFalse();
        assertThat(CiTokenService.isCiTokenValue("Bearer vx_live_abc")).isFalse();
        assertThat(CiTokenService.isCiTokenValue(null)).isFalse();
    }

    private static User admin() {
        User user = new User();
        user.setId(1L);
        user.setLogin("admin");
        user.setRole(UserRole.ADMIN);
        return user;
    }

    private static Client client(Long id, String name) {
        Client client = new Client();
        client.setId(id);
        client.setName(name);
        return client;
    }

    private static Repository repository(Long id, String url) {
        Repository repository = new Repository();
        repository.setId(id);
        repository.setRepoUrl(url);
        return repository;
    }

    private static CiToken activeToken(String raw) {
        Repository repo = repository(7L, "https://github.com/org/app");
        return CiToken.builder()
                .id(1L)
                .name("GitHub Actions")
                .tokenHash(CiTokenService.hashToken(raw))
                .tokenPrefix(raw.substring(0, 16))
                .client(client(12L, "CourtLinker"))
                .scopes(CiToken.DEFAULT_SCOPES)
                .repositories(Set.of(repo))
                .expiresAt(Instant.now().plus(90, ChronoUnit.DAYS))
                .createdAt(Instant.now())
                .build();
    }
}
