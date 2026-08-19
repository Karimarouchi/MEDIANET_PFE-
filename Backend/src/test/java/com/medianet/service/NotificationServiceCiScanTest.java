package com.medianet.service;

import com.medianet.entity.CveEntry;
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
                employeeClientRepo);
    }

    @Test
    @DisplayName("notifyCiScanFinished() → ignore un scan UI sans commit SHA")
    void skipsScanWithoutCommitSha() {
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan(null, ScanStatus.COMPLETED)));

        notificationService.notifyCiScanFinished(10L);

        verify(notificationRepo, never()).save(any());
    }

    @Test
    @DisplayName("notifyCiScanFinished() → notifie l’admin avec le résumé CRITICAL/HIGH")
    void notifiesAdminWithCveSummary() {
        ScanResult scan = scan("a1b2c3d4e5f6", ScanStatus.COMPLETED);
        User admin = admin();
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan));
        when(cveEntryRepo.findByScanResultId(10L)).thenReturn(List.of(
                cve("CRITICAL"),
                cve("HIGH"),
                cve("MEDIUM")));
        when(clientRepositoryRepo.findByRepository_Id(3L)).thenReturn(List.of());
        when(userRepo.findAll()).thenReturn(List.of(admin));
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        com.medianet.entity.AppNotification n = captor.getValue();
        assertThat(n.getRecipient()).isEqualTo(admin);
        assertThat(n.getType()).isEqualTo(NotificationType.SCAN_COMPLETED);
        assertThat(n.getTitle()).contains("FAIL");
        assertThat(n.getMessage()).contains("a1b2c3d");
        assertThat(n.getMessage()).contains("1 CRITICAL");
        assertThat(n.getLink()).isEqualTo("/vulnerabilities?scanId=10&repoId=3");
    }

    @Test
    @DisplayName("notifyCiScanFinished() → SCAN_FAILED si Kali a planté")
    void notifiesFailure() {
        when(scanResultRepo.findByIdWithRepository(10L)).thenReturn(Optional.of(scan("abc1234", ScanStatus.FAILED)));
        when(userRepo.findAll()).thenReturn(List.of(admin()));
        when(clientRepositoryRepo.findByRepository_Id(3L)).thenReturn(List.of());
        when(notificationRepo.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        notificationService.notifyCiScanFinished(10L);

        ArgumentCaptor<com.medianet.entity.AppNotification> captor =
                ArgumentCaptor.forClass(com.medianet.entity.AppNotification.class);
        verify(notificationRepo).save(captor.capture());
        assertThat(captor.getValue().getType()).isEqualTo(NotificationType.SCAN_FAILED);
        assertThat(captor.getValue().getTitle()).contains("échec");
    }

    private static ScanResult scan(String sha, ScanStatus status) {
        Repository repo = new Repository();
        repo.setId(3L);
        repo.setRepoUrl("https://github.com/Karimarouchi/E-commerce-coussin");
        ScanResult scan = ScanResult.builder()
                .id(10L)
                .status(status)
                .commitSha(sha)
                .repository(repo)
                .resultsDir("/tmp")
                .build();
        return scan;
    }

    private static User admin() {
        User user = new User();
        user.setId(1L);
        user.setLogin("admin");
        user.setRole(UserRole.ADMIN);
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
