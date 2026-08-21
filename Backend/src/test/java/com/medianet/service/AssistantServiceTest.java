package com.medianet.service;

import com.medianet.dto.AssistantChatRequest;
import com.medianet.dto.AssistantChatResponse;
import com.medianet.dto.AssistantChatTurn;
import com.medianet.dto.CveDto;
import com.medianet.entity.AccessPermission;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashSet;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AssistantServiceTest {

    @Mock private AiGatewayService aiGatewayService;
    @Mock private AccessRoleService accessRoleService;
    @Mock private ScanService scanService;
    @Mock private SslResultStoreService sslResultStoreService;
    @Mock private ServerConfigService serverConfigService;
    @Mock private CveJournalService cveJournalService;
    @Mock private PolicyDeviationService policyDeviationService;
    @Mock private ClientService clientService;

    private AssistantService assistantService;

    @BeforeEach
    void setUp() {
        assistantService = new AssistantService(
                aiGatewayService,
                accessRoleService,
                scanService,
                sslResultStoreService,
                serverConfigService,
                cveJournalService,
                policyDeviationService,
                clientService,
                null);
    }

    @Test
    @DisplayName("redactSecrets masque PAT GitLab et clés")
    void redactsTokens() {
        String out = AssistantService.redactSecrets(
                "voici glpat-abcDEF123 et api_key=secret123");
        assertThat(out).doesNotContain("glpat-abcDEF123");
        assertThat(out).doesNotContain("secret123");
        assertThat(out).contains("[REDACTED]");
    }

    @Test
    @DisplayName("resolvePage mappe les routes UI")
    void resolvesPages() {
        assertThat(AssistantService.resolvePage("/ssl-analysis/42")).isEqualTo("ssl");
        assertThat(AssistantService.resolvePage("/vulnerabilities?scanId=9")).isEqualTo("vulnerabilities");
        assertThat(AssistantService.resolvePage("/cve-journal")).isEqualTo("cve-journal");
        assertThat(AssistantService.resolvePage("/server-config/3")).isEqualTo("servers");
        assertThat(AssistantService.resolvePage("/")).isEqualTo("dashboard");
    }

    @Test
    @DisplayName("question vide → 400")
    void blankMessageRejected() {
        User user = employee();
        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("   ");
        assertThatThrownBy(() -> assistantService.chat(user, req))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(ex -> ((ResponseStatusException) ex).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    @DisplayName("scan autorisé : le prompt IA contient les CVE du périmètre")
    void groundsOnVisibleScan() {
        User user = employee();
        when(accessRoleService.getEffectivePermissions(user)).thenReturn(perms(
                AccessPermission.SCANS, AccessPermission.VULNERABILITIES, AccessPermission.PROFILE));
        when(scanService.getAuthorizedScan(user, 10L)).thenReturn(scan(10L, "https://gitlab.com/acme/app"));
        when(scanService.getCvesByScan(user, 10L)).thenReturn(List.of(
                CveDto.builder().cveId("CVE-2025-24813").severity("CRITICAL")
                        .packageName("tomcat-embed-core").packageVersion("10.1.0")
                        .fixedVersion("10.1.40").build()));
        when(aiGatewayService.generateChat(any())).thenReturn("Passe Tomcat en 10.1.40.");

        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("Que corriger en premier ?");
        req.setPage("/vulnerabilities?scanId=10");
        req.setScanId(10L);

        AssistantChatResponse res = assistantService.chat(user, req);

        assertThat(res.isUsedAi()).isTrue();
        assertThat(res.getReply()).contains("Tomcat");
        assertThat(res.getContextLabel()).contains("10");
        org.mockito.ArgumentCaptor<String> prompt = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(aiGatewayService).generateChat(prompt.capture());
        assertThat(prompt.getValue()).contains("CVE-2025-24813");
        assertThat(prompt.getValue()).contains("tomcat-embed-core");
        verify(cveJournalService, never()).getJournal();
    }

    @Test
    @DisplayName("employé sans CVE_JOURNAL : pas de dump du journal global")
    void employeeDoesNotGetGlobalJournal() {
        User user = employee();
        when(accessRoleService.getEffectivePermissions(user)).thenReturn(perms(
                AccessPermission.DASHBOARD, AccessPermission.PROFILE));
        when(aiGatewayService.generateChat(any())).thenReturn("ok");

        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("Montre-moi toutes les CVE du journal");
        req.setPage("/dashboard");

        assistantService.chat(user, req);

        verify(cveJournalService, never()).getJournal();
        verify(serverConfigService, never()).getServers();
    }

    @Test
    @DisplayName("scan inaccessible : ignoré, pas d'erreur 404 au chat")
    void inaccessibleScanIsSkipped() {
        User user = employee();
        when(accessRoleService.getEffectivePermissions(user)).thenReturn(perms(
                AccessPermission.VULNERABILITIES, AccessPermission.PROFILE));
        when(scanService.getAuthorizedScan(user, 99L))
                .thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Scan not found"));
        when(aiGatewayService.generateChat(any())).thenReturn("Je n'ai pas ce scan.");

        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("Parle-moi du scan 99");
        req.setScanId(99L);
        req.setPage("/vulnerabilities");

        AssistantChatResponse res = assistantService.chat(user, req);
        assertThat(res.getReply()).contains("scan");
        verify(scanService, never()).getCvesByScan(any(), any());
    }

    @Test
    @DisplayName("IA down : fallback français avec le dossier")
    void fallbackWhenAiMissing() {
        User user = employee();
        when(accessRoleService.getEffectivePermissions(user)).thenReturn(perms(
                AccessPermission.SCANS, AccessPermission.VULNERABILITIES));
        when(scanService.getAuthorizedScan(user, 10L)).thenReturn(scan(10L, "https://gitlab.com/acme/app"));
        when(scanService.getCvesByScan(user, 10L)).thenReturn(List.of(
                CveDto.builder().cveId("CVE-2024-1").severity("HIGH")
                        .packageName("log4j").packageVersion("2.14.0").build()));
        when(aiGatewayService.generateChat(any())).thenReturn(null);

        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("Quelles CVE ?");
        req.setScanId(10L);

        AssistantChatResponse res = assistantService.chat(user, req);
        assertThat(res.isUsedAi()).isFalse();
        assertThat(res.getReply()).contains("indisponible");
        assertThat(res.getReply()).contains("CVE-2024-1");
    }

    @Test
    @DisplayName("historique utilisateur est redacté avant l'IA")
    void historyIsRedacted() {
        User user = employee();
        when(accessRoleService.getEffectivePermissions(user)).thenReturn(perms(AccessPermission.PROFILE));
        when(aiGatewayService.generateChat(any())).thenReturn("ok");

        AssistantChatTurn turn = new AssistantChatTurn();
        turn.setRole("user");
        turn.setContent("mon token glpat-SUPERSECRET99");
        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("c'est bon ?");
        req.setHistory(List.of(turn));

        assistantService.chat(user, req);

        org.mockito.ArgumentCaptor<String> prompt = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(aiGatewayService).generateChat(prompt.capture());
        assertThat(prompt.getValue()).doesNotContain("glpat-SUPERSECRET99");
        assertThat(prompt.getValue()).contains("[REDACTED]");
    }

    @Test
    @DisplayName("FAQ GitLab : 0 appel Gemini")
    void localFaqSkipsLlm() {
        User user = employee();
        AssistantChatRequest req = new AssistantChatRequest();
        req.setMessage("Comment lier GitLab ?");
        req.setPage("/profile");

        AssistantChatResponse res = assistantService.chat(user, req);

        assertThat(res.isUsedAi()).isFalse();
        assertThat(res.getReply()).contains("Profil");
        verify(aiGatewayService, never()).generateChat(any());
    }

    private static LinkedHashSet<AccessPermission> perms(AccessPermission... values) {
        return new LinkedHashSet<>(List.of(values));
    }

    private static User employee() {
        User u = new User();
        u.setId(22L);
        u.setLogin("zied");
        u.setRole(UserRole.EMPLOYEE);
        return u;
    }

    private static ScanResult scan(Long id, String url) {
        Repository repo = Repository.builder().id(1L).repoUrl(url).scanMode("auto").branch("main").build();
        return ScanResult.builder().id(id).status(ScanStatus.COMPLETED).repository(repo).resultsDir("x").build();
    }
}
