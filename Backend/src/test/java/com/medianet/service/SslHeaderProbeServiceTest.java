package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Web server read from the "Server" header, to show the matching configuration lines on the SSL page. */
class SslHeaderProbeServiceTest {

    @Test
    void webServerIsNamedFromTheServerHeader() {
        assertThat(SslHeaderProbeService.webServer("nginx")).isEqualTo("nginx");
        assertThat(SslHeaderProbeService.webServer("nginx/1.25.3")).isEqualTo("nginx");
        assertThat(SslHeaderProbeService.webServer("openresty/1.21")).isEqualTo("nginx");
        assertThat(SslHeaderProbeService.webServer("Apache/2.4.58 (Ubuntu)")).isEqualTo("apache");
        assertThat(SslHeaderProbeService.webServer("cloudflare")).isEqualTo("cloudflare");
        assertThat(SslHeaderProbeService.webServer(null)).isNull();
    }
}
