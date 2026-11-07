package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.dto.ClientDto;
import com.medianet.entity.ServerDeployment;
import com.medianet.entity.User;
import com.medianet.repository.ServerDeploymentRepo;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** The overview reads the built-in monitoring when no Uptime Kuma address is configured. */
class UptimeServiceBuiltInTest {

    private final ClientService clients = mock(ClientService.class);
    private final ServerDeploymentRepo deployments = mock(ServerDeploymentRepo.class);
    private final SiteMonitorService monitor = mock(SiteMonitorService.class);
    private final User user = new User();

    private UptimeService service(String kumaUrl) {
        return new UptimeService(clients, deployments, new ObjectMapper(), monitor, kumaUrl, "vulnix");
    }

    private void project(String domain, Long... repoIds) {
        when(clients.getVisibleClient(user, 7L)).thenReturn(ClientDto.builder().id(7L).domainName(domain)
                .repositoryIds(List.of(repoIds)).build());
    }

    @Test
    void withoutKumaTheProjectDomainsAreWatchedByVulnixItself() {
        project("https://Courtlinker.com/");
        when(monitor.isEnabled()).thenReturn(true);
        var line = new UptimeService.Monitor(1, "courtlinker.com", "UP", 1.0, "t", "HTTP 200 · 80 ms");
        when(monitor.snapshot(Set.of("courtlinker.com"))).thenReturn(List.of(line));

        UptimeService.ProjectUptime u = service("").forProject(user, 7L);

        assertThat(u.configured()).isTrue();
        assertThat(u.reachable()).isTrue();
        assertThat(u.domains()).containsExactly("courtlinker.com");
        assertThat(u.monitors()).containsExactly(line);
    }

    @Test
    void theDeploymentDomainsOfTheLinkedRepositoriesAreWatchedToo() {
        project("a.com", 3L);
        ServerDeployment d = new ServerDeployment();
        d.setDomain("Prod.A.com");
        when(deployments.findByLinkedRepositoryId(3L)).thenReturn(List.of(d));
        when(monitor.isEnabled()).thenReturn(true);
        when(monitor.snapshot(anySet())).thenReturn(List.of());

        UptimeService.ProjectUptime u = service(" ").forProject(user, 7L);

        assertThat(u.domains()).containsExactly("a.com", "prod.a.com");
        verify(monitor).snapshot(Set.of("a.com", "prod.a.com"));
    }

    @Test
    void whenMonitoringIsSwitchedOffTheOverviewSaysSo() {
        project("a.com");
        when(monitor.isEnabled()).thenReturn(false);
        UptimeService.ProjectUptime u = service("").forProject(user, 7L);
        assertThat(u.configured()).isFalse();
        assertThat(u.monitors()).isEmpty();
    }
}
