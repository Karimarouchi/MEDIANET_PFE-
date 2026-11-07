package com.medianet.service;

import com.medianet.entity.SiteCheck;
import com.medianet.repository.SiteCheckRepo;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SiteMonitorServiceTest {

    private HttpServer server;
    private final AtomicInteger answer = new AtomicInteger(200);
    private final AtomicInteger hits = new AtomicInteger();
    private SiteCheckRepo repo;
    private SiteMonitorService monitor;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> {
            hits.incrementAndGet();
            if (answer.get() == 301) ex.getResponseHeaders().add("Location", "http://127.0.0.1:1/never-followed");
            ex.sendResponseHeaders(answer.get(), -1);
            ex.close();
        });
        server.start();
        repo = mock(SiteCheckRepo.class);
        when(repo.save(any(SiteCheck.class))).thenAnswer(i -> i.getArgument(0));
        // Private targets allowed: the test server is on the loopback address.
        monitor = new SiteMonitorService(repo, new SslTargetGuard(true), Runnable::run);
        monitor.setEnabled(true);
    }

    @AfterEach
    void stop() {
        try {
            server.stop(0);
        } catch (RuntimeException ignored) {
            // already stopped by the test
        }
    }

    private String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @Test
    void aSiteThatAnswers200IsUpWithItsResponseTime() {
        SiteCheck c = monitor.checkNow(url());
        assertThat(c.getState()).isEqualTo("UP");
        assertThat(c.getStatusCode()).isEqualTo(200);
        assertThat(c.getResponseMs()).isNotNull().isGreaterThanOrEqualTo(0);
        assertThat(c.getMessage()).startsWith("HTTP 200");
    }

    @Test
    void aRedirectionCountsAsUpAndIsNotFollowed() {
        answer.set(301);
        SiteCheck c = monitor.checkNow(url());
        assertThat(c.getState()).isEqualTo("UP");
        assertThat(c.getStatusCode()).isEqualTo(301);
        assertThat(hits.get()).isEqualTo(1);
    }

    @Test
    void aServerErrorIsDown() {
        answer.set(503);
        SiteCheck c = monitor.checkNow(url());
        assertThat(c.getState()).isEqualTo("DOWN");
        assertThat(c.getMessage()).isEqualTo("HTTP 503");
    }

    @Test
    void aClosedPortIsDownWithAReadableReason() {
        int port = server.getAddress().getPort();
        server.stop(0);
        SiteCheck c = monitor.checkNow("http://127.0.0.1:" + port);
        assertThat(c.getState()).isEqualTo("DOWN");
        assertThat(c.getMessage()).isEqualTo("connexion refusée ou interrompue");
    }

    @Test
    void anInternalAddressIsNeverRequested() {
        SiteMonitorService strict = new SiteMonitorService(repo, new SslTargetGuard(false), Runnable::run);
        strict.setEnabled(true);
        SiteCheck c = strict.checkNow(url());
        assertThat(c.getState()).isEqualTo("SKIPPED");
        assertThat(c.getMessage()).contains("non publique");
        assertThat(hits.get()).isZero();
    }

    @Test
    void anInvalidDomainIsSkippedNotDown() {
        SiteCheck c = monitor.checkNow("pas un domaine");
        assertThat(c.getState()).isEqualTo("SKIPPED");
    }

    @Test
    void domainsAreTakenFromProjectsAndDeploymentsWithoutDuplicates() {
        when(repo.projectDomains()).thenReturn(List.of("https://CourtLinker.com/", "a.com"));
        when(repo.deploymentDomains()).thenReturn(List.of("courtlinker.com", " b.com/path "));
        assertThat(monitor.monitoredDomains()).containsExactly("courtlinker.com", "a.com", "b.com");
    }

    @Test
    void snapshotShowsPendingThenAsksForTheFirstCheckOnlyOnce() {
        // A one-word name is not a valid domain: the first check is skipped without any network access.
        when(repo.findFirstByDomainOrderByCheckedAtDesc("pendingsite")).thenReturn(Optional.empty());
        List<UptimeService.Monitor> first = monitor.snapshot(Set.of("pendingsite"));
        assertThat(first).singleElement().satisfies(m -> {
            assertThat(m.status()).isEqualTo("PENDING");
            assertThat(m.uptime24h()).isNull();
            assertThat(m.message()).contains("première vérification");
        });
        monitor.snapshot(Set.of("pendingsite"));
        // The direct executor ran the first check once; asking again must not start a second one.
        verify(repo, org.mockito.Mockito.times(1)).save(any(SiteCheck.class));
    }

    @Test
    void snapshotComputesAvailabilityOverTwentyFourHours() {
        SiteCheck last = SiteCheck.builder().domain("a.com").state("DOWN").message("HTTP 503")
                .checkedAt(LocalDateTime.of(2026, 10, 27, 10, 0)).build();
        when(repo.findFirstByDomainOrderByCheckedAtDesc("a.com")).thenReturn(Optional.of(last));
        when(repo.countSince(eq("a.com"), eq("UP"), any())).thenReturn(3L);
        when(repo.countSince(eq("a.com"), eq("DOWN"), any())).thenReturn(1L);
        UptimeService.Monitor m = monitor.snapshot(Set.of("a.com")).get(0);
        assertThat(m.status()).isEqualTo("DOWN");
        assertThat(m.uptime24h()).isEqualTo(0.75);
        assertThat(m.message()).isEqualTo("HTTP 503");
        assertThat(m.lastCheck()).isEqualTo("2026-10-27T10:00");
        verify(repo, never()).save(any());
    }

    @Test
    void skippedChecksNeverCountInTheAvailability() {
        SiteCheck last = SiteCheck.builder().domain("intranet.local").state("SKIPPED").message("adresse non publique : non surveillée")
                .checkedAt(LocalDateTime.now()).build();
        when(repo.findFirstByDomainOrderByCheckedAtDesc("intranet.local")).thenReturn(Optional.of(last));
        UptimeService.Monitor m = monitor.snapshot(Set.of("intranet.local")).get(0);
        assertThat(m.status()).isEqualTo("UNKNOWN");
        assertThat(m.uptime24h()).isNull();
    }

    @Test
    void nothingIsAskedWhenMonitoringIsOff() {
        monitor.setEnabled(false);
        when(repo.findFirstByDomainOrderByCheckedAtDesc("x.example.com")).thenReturn(Optional.empty());
        monitor.snapshot(Set.of("x.example.com"));
        monitor.checkAll();
        verify(repo, never()).save(any());
    }
}
