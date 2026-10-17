package com.medianet.service;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SslTargetGuardTest {

    private final SslTargetGuard guard = new SslTargetGuard(false);

    @Test
    void pastedUrlBecomesHostAndPort() {
        assertThat(SslTargetGuard.normalize("https://Site.COM/page?x=1#top").canonical()).isEqualTo("site.com");
        assertThat(SslTargetGuard.normalize("  http://site.com:8443/a ").canonical()).isEqualTo("site.com:8443");
        assertThat(SslTargetGuard.normalize("site.com.").canonical()).isEqualTo("site.com");
        assertThat(SslTargetGuard.normalize("site.com:443").canonical()).isEqualTo("site.com");
        assertThat(SslTargetGuard.normalize("expired.badssl.com").host()).isEqualTo("expired.badssl.com");
    }

    @Test
    void internationalNamesAreConvertedToAscii() {
        assertThat(SslTargetGuard.normalize("café.fr").host()).isEqualTo("xn--caf-dma.fr");
    }

    @Test
    void malformedTargetsAreRefusedWithAMessage() {
        for (String bad : new String[] {"", "   ", "site", "site.com:0", "site.com:70000", "site.com:abc",
                "user:pass@site.com", "-bad-.com", "a..com", "[::1]:443", "::1", "999.1.1.1", "site.123",
                "si te.com", "site.com;rm -rf /"}) {
            assertThatThrownBy(() -> SslTargetGuard.normalize(bad))
                    .as(bad)
                    .isInstanceOf(ResponseStatusException.class)
                    .satisfies(e -> assertThat(((ResponseStatusException) e).getReason()).isNotBlank());
        }
    }

    @Test
    void internalAddressesAreRefused() {
        assertThatThrownBy(() -> guard.check("localhost")).isInstanceOf(ResponseStatusException.class);
        for (String target : new String[] {"127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1",
                "169.254.169.254", "0.0.0.0", "100.64.0.1"}) {
            assertThatThrownBy(() -> guard.check(target))
                    .as(target)
                    .isInstanceOf(ResponseStatusException.class)
                    .hasMessageContaining("adresse interne");
        }
    }

    @Test
    void publicIpLiteralIsAccepted() {
        assertThat(guard.check("8.8.8.8").canonical()).isEqualTo("8.8.8.8");
    }

    @Test
    void privateTargetsCanBeAllowedByConfiguration() {
        assertThat(new SslTargetGuard(true).check("127.0.0.1").host()).isEqualTo("127.0.0.1");
    }

    @Test
    void addressClassification() throws Exception {
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("::1"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("fd00::1"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("fe80::1"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("::ffff:10.0.0.1"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("64:ff9b::a9fe:a9fe"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("2002:7f00:0001::"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("224.0.0.1"))).isTrue();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("172.32.0.1"))).isFalse();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("100.128.0.1"))).isFalse();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("1.1.1.1"))).isFalse();
        assertThat(SslTargetGuard.isInternal(InetAddress.getByName("2606:4700:4700::1111"))).isFalse();
    }
}
