package com.medianet.service;

import com.medianet.entity.Client;
import com.medianet.entity.ClientRepository;
import com.medianet.entity.ClientRepositoryId;
import com.medianet.entity.CveEntry;
import com.medianet.entity.EmployeeClient;
import com.medianet.entity.EmployeeClientId;
import com.medianet.entity.NotificationType;
import com.medianet.entity.Repository;
import com.medianet.entity.ScanResult;
import com.medianet.entity.ScanResult.ScanStatus;
import com.medianet.entity.User;
import com.medianet.entity.UserRole;
import com.medianet.repository.AppNotificationRepo;
import com.medianet.repository.ClientRepositoryRepo;
import com.medianet.repository.CveEntryRepo;
import com.medianet.repository.EmployeeClientRepo;
import com.medianet.repository.PolicyDeviationRequestRepo;
import com.medianet.repository.ScanResultRepo;
import com.medianet.repository.UserRepo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NotificationServiceCiScanTest {

    @Mock private AppNotificationRepo notificationRepo;
    @Mock private UserRepo userRepo;
    @Mock private AccessRoleService accessRoleService;
    @Mock private PolicyDeviationRequestRepo deviationRequestRepo;
    @Mock private ScanResultRepo scanResultRepo;
    @Mock private CveEntryRepo cveEntryRepo;
    @Mock private ClientRepositoryRepo clientRepositoryRepo;
    @Mock private EmployeeClientRepo employeeClientRepo;

    private NotificationService notificationService;

    @BeforeEach
    void setUp() {
        notificationService = new NotificationService(
                notificationRepo,
                userRepo,
                accessRoleService,
                deviationRequestRepo,
                scanResultRepo,
                cveEntryRepo,
                clientRepositoryRepo,
                employeeClientRepo,
                null);
    }

    @Test
    @DisplayName("notifyCiScanFinished() → scan UI : notifie les collaborateurs du projet")
    void notifiesProjectCollaboratorsForUiScan() {
        User zied = employee(22L, "zied");
        stubProjectWithCollaborator(zied);
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan(null, ScanStatus.COMPLETED)));
        when(cveEntryRepo.findByScanResultId(10L)).thenReturn(List.of(cve("MEDIUM")));
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        com.medianet.entity.AppNotification n = captor.getValue();
        assertThat(n.getRecipient()).isEqualTo(zied);
        assertThat(n.getType()).isEqualTo(NotificationType.SCAN_COMPLETED);
        assertThat(n.getTitle()).contains("Scan terminé");
        assertThat(n.getMessage()).contains("MEDIANET");
        assertThat(n.getTitle()).doesNotContain("git push");
    }

    @Test
    @DisplayName("notifyCiScanFinished() → git push : notifie le collaborateur avec le résumé")
    void notifiesCollaboratorForGitPushScan() {
        User zied = employee(22L, "zied");
        stubProjectWithCollaborator(zied);
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan("a1b2c3d4e5f6", ScanStatus.COMPLETED)));
        when(cveEntryRepo.findByScanResultId(10L)).thenReturn(List.of(
                cve("CRITICAL"),
                cve("HIGH"),
                cve("MEDIUM")));
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        com.medianet.entity.AppNotification n = captor.getValue();
        assertThat(n.getRecipient().getLogin()).isEqualTo("zied");
        assertThat(n.getTitle()).contains("git push");
        assertThat(n.getMessage()).contains("GitHub Actions");
        assertThat(n.getMessage()).contains("1 CRITICAL");
        assertThat(n.getLink()).isEqualTo("/vulnerabilities?scanId=10&repoId=3");
    }

    @Test
    @DisplayName("notifyCiScanFinished() → SCAN_FAILED notifie les collaborateurs")
    void notifiesFailureToCollaborators() {
        User zied = employee(22L, "zied");
        stubProjectWithCollaborator(zied);
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan("abc1234", ScanStatus.FAILED)));
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        assertThat(captor.getValue().getType()).isEqualTo(NotificationType.SCAN_FAILED);
        assertThat(captor.getValue().getRecipient()).isEqualTo(zied);
    }

    @Test
    @DisplayName("notifyCiScanFinished() → même URL GitHub, autre id repo → notifie quand même les collaborateurs")
    void notifiesWhenScannedRepoRowDiffersFromLinkedRow() {
        User zied = employee(22L, "zied");
        Client client = new Client();
        client.setId(2L);
        client.setName("MEDIANET");
        Repository linkedRepo = new Repository();
        linkedRepo.setId(99L);
        linkedRepo.setRepoUrl("https://github.com/Karimarouchi/E-commerce-coussin.git");
        ClientRepository link = ClientRepository.builder()
                .id(new ClientRepositoryId(2L, 99L))
                .client(client)
                .repository(linkedRepo)
                .build();
        EmployeeClient assignment = EmployeeClient.builder()
                .id(new EmployeeClientId(22L, 2L))
                .employee(zied)
                .client(client)
                .build();
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan(null, ScanStatus.COMPLETED)));
        when(cveEntryRepo.findByScanResultId(10L)).thenReturn(List.of(cve("LOW")));
        when(clientRepositoryRepo.findByRepository_Id(3L)).thenReturn(List.of());
        when(clientRepositoryRepo.findAllWithClientAndRepository()).thenReturn(List.of(link));
        when(employeeClientRepo.findByClient_Id(2L)).thenReturn(List.of(assignment));
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        assertThat(captor.getValue().getRecipient()).isEqualTo(zied);
        assertThat(captor.getValue().getMessage()).contains("MEDIANET");
    }
    void skipsWhenNoCollaborators() {
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan(null, ScanStatus.COMPLETED)));
        when(cveEntryRepo.findByScanResultId(10L)).thenReturn(List.of());
        when(clientRepositoryRepo.findByRepository_Id(3L)).thenReturn(List.of());
        when(clientRepositoryRepo.findAllWithClientAndRepository()).thenReturn(List.of());

        notificationService.notifyCiScanFinished(10L);

        verify(notificationRepo, never()).save(any());
    }

    private void stubProjectWithCollaborator(User collaborator) {
        Client client = new Client();
        client.setId(2L);
        client.setName("MEDIANET");
        Repository linkedRepo = new Repository();
        linkedRepo.setId(3L);
        linkedRepo.setRepoUrl("https://github.com/Karimarouchi/E-commerce-coussin");
        ClientRepository link = ClientRepository.builder()
                .id(new ClientRepositoryId(2L, 3L))
                .client(client)
                .repository(linkedRepo)
                .build();
        EmployeeClient assignment = EmployeeClient.builder()
                .id(new EmployeeClientId(collaborator.getId(), 2L))
                .employee(collaborator)
                .client(client)
                .build();
        when(clientRepositoryRepo.findByRepository_Id(3L)).thenReturn(List.of(link));
        when(clientRepositoryRepo.findAllWithClientAndRepository()).thenReturn(List.of(link));
        when(employeeClientRepo.findByClient_Id(2L)).thenReturn(List.of(assignment));
    }

    private static ScanResult scan(String sha, ScanStatus status) {
        Repository repo = new Repository();
        repo.setId(3L);
        repo.setRepoUrl("https://github.com/Karimarouchi/E-commerce-coussin");
        return ScanResult.builder()
                .id(10L)
                .status(status)
                .commitSha(sha)
                .repository(repo)
                .resultsDir("/tmp")
                .build();
    }

    private static User employee(Long id, String login) {
        User user = new User();
        user.setId(id);
        user.setLogin(login);
        user.setEmail(login + "@medianet.com.tn");
        user.setRole(UserRole.EMPLOYEE);
        user.setSuspended(false);
        return user;
    }

    private static CveEntry cve(String severity) {
        CveEntry entry = new CveEntry();
        entry.setCveId("CVE-2024-1");
        entry.setSeverity(severity);
        return entry;
    }
}
