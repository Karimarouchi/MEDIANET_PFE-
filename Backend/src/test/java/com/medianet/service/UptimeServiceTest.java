package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UptimeServiceTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    @Test
    void monitorsAreMatchedToTheProjectDomainsWithTheirLastStatus() throws Exception {
        // Shapes returned by Uptime Kuma 1.23 (status page and heartbeat endpoints), captured on the local install.
        var page = JSON.readTree("{\"publicGroupList\":[{\"monitorList\":[{\"id\":1,\"name\":\"courtlinker.com\"},{\"id\":2,\"name\":\"other.org\"}]}]}");
        var beats = JSON.readTree("{\"heartbeatList\":{\"1\":[{\"status\":2,\"time\":\"t1\",\"msg\":\"\"},{\"status\":0,\"time\":\"t2\",\"msg\":\"503 - Service Unavailable\"}]},"
                + "\"uptimeList\":{\"1_24\":0.25}}");
        List<UptimeService.Monitor> m = UptimeService.match(page, beats, Set.of("courtlinker.com"));
        assertThat(m).singleElement().satisfies(x -> {
            assertThat(x.name()).isEqualTo("courtlinker.com");
            assertThat(x.status()).isEqualTo("DOWN");
            assertThat(x.uptime24h()).isEqualTo(0.25);
            assertThat(x.message()).isEqualTo("503 - Service Unavailable");
        });
        assertThat(UptimeService.match(page, beats, Set.of("absent.net"))).isEmpty();
    }
}
