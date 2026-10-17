package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** SSL Labs and Censys parsing, and the "source never answered" timeout. */
class SslExternalSourcesTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private static final String TWO_ENDPOINTS = """
            {"status":"READY","testTime":1760000000000,
             "endpoints":[
               {"ipAddress":"1.1.1.1","grade":"A","statusMessage":"Ready","hasWarnings":false,
                "details":{"protocols":[{"version":"1.2"},{"version":"1.3"}],"forwardSecrecy":4,
                  "suites":[{"protocol":771,"list":[{"name":"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}]}]}},
               {"ipAddress":"2.2.2.2","grade":"B","statusMessage":"Ready","hasWarnings":true,
                "details":{"protocols":[{"version":"1.0"},{"version":"1.2"}],"forwardSecrecy":1,
                  "suites":[{"protocol":769,"list":[{"name":"TLS_RSA_WITH_3DES_EDE_CBC_SHA"}]}]}}
             ],
             "certs":[]}
            """;

    @Test
    void sslLabsGradeIsTheWorstEndpointAndFlawsAreTheUnion() throws Exception {
        Map<String, Object> r = SslLabsService.parseResult(mapper.readTree(TWO_ENDPOINTS), "site.com");
        assertThat(r.get("grade")).isEqualTo("B");
        assertThat(r.get("tls10")).isEqualTo(true);
        assertThat(r.get("tls13")).isEqualTo(true);
        assertThat(r.get("has3des")).isEqualTo(true);
        assertThat(r.get("forwardSecrecy")).isEqualTo(false);
        assertThat(r.get("hasWarnings")).isEqualTo(true);
        assertThat((List<?>) r.get("endpoints")).hasSize(2);
        assertThat(r.get("testTime")).isEqualTo("2025-10-09T08:53:20Z");
    }

    @Test
    void threeDesIsReadFromSuitesNotGuessedFromTls10() throws Exception {
        // TLS 1.0 with CBC suites but no 3DES: the old guess said 3DES, the suite list says no.
        String json = """
                {"status":"READY","endpoints":[{"ipAddress":"1.1.1.1","grade":"B","statusMessage":"Ready",
                  "details":{"protocols":[{"version":"1.0"}],"supportsCBC":true,
                    "suites":[{"protocol":769,"list":[{"name":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"}]}]}}]}
                """;
        assertThat(SslLabsService.parseResult(mapper.readTree(json), "x.com").get("has3des")).isEqualTo(false);
        // v3 shape: suites is an object with a list
        JsonNode v3 = mapper.readTree("{\"list\":[{\"name\":\"TLS_RSA_WITH_3DES_EDE_CBC_SHA\"}]}");
        assertThat(SslLabsService.offers3des(v3)).isTrue();
    }

    @Test
    void trustAndMismatchGradesRankAsFailures() throws Exception {
        String json = """
                {"status":"READY","endpoints":[
                  {"ipAddress":"1.1.1.1","grade":"A","statusMessage":"Ready"},
                  {"ipAddress":"2.2.2.2","grade":"T","statusMessage":"Ready"}]}
                """;
        assertThat(SslLabsService.parseResult(mapper.readTree(json), "x.com").get("grade")).isEqualTo("T");
    }

    @Test
    void unreachableEndpointGivesAReasonInsteadOfAGrade() throws Exception {
        String json = """
                {"status":"READY","endpoints":[{"ipAddress":"1.1.1.1","statusMessage":"Unable to connect to the server"}]}
                """;
        Map<String, Object> r = SslLabsService.parseResult(mapper.readTree(json), "x.com");
        assertThat(r.get("grade")).isEqualTo("?");
        assertThat(r.get("error")).isEqualTo("Unable to connect to the server");
    }

    @Test
    void censysNoLongerPenalisesNinetyDayCertificatesOrRewardsEv() {
        // Let's Encrypt: 90-day certificates, renewed at 30 days left → A, not B
        assertThat(CensysSslService.certificateGrade(false, true, 60, "RSA", 2048, true)).isEqualTo("A");
        assertThat(CensysSslService.certificateGrade(false, true, 300, "RSA", 4096, true)).isEqualTo("A");
        assertThat(CensysSslService.certificateGrade(false, true, 60, "RSA", 2048, false)).isEqualTo("B");
        assertThat(CensysSslService.certificateGrade(false, true, 10, "RSA", 2048, true)).isEqualTo("C");
        assertThat(CensysSslService.certificateGrade(false, true, 3, "RSA", 2048, true)).isEqualTo("D");
        assertThat(CensysSslService.certificateGrade(true, true, -1, "RSA", 2048, true)).isEqualTo("F");
        assertThat(CensysSslService.certificateGrade(false, false, 60, "RSA", 2048, true)).isEqualTo("F");
        // a 256-bit ECDSA key is strong
        assertThat(CensysSslService.certificateGrade(false, true, 60, "ECDSA", 256, true)).isEqualTo("A");
        assertThat(CensysSslService.certificateGrade(false, true, 60, "RSA", 1024, true)).isEqualTo("C");
    }

    @Test
    void sourceStuckInPendingBecomesTimeout(@TempDir Path dir) throws Exception {
        File f = dir.resolve("ssl-labs-result.json").toFile();
        Files.writeString(f.toPath(), "{\"status\":\"PENDING\"}");
        assertThat(SslResultAssembler.staleAware("PENDING", f, Duration.ofMinutes(15))).isEqualTo("PENDING");
        assertThat(f.setLastModified(System.currentTimeMillis() - Duration.ofMinutes(20).toMillis())).isTrue();
        assertThat(SslResultAssembler.staleAware("PENDING", f, Duration.ofMinutes(15))).isEqualTo("TIMEOUT");
        assertThat(SslResultAssembler.staleAware("READY", f, Duration.ofMinutes(15))).isEqualTo("READY");
    }

    @Test
    void liveHeaderCheckNeverConnectsToAnInternalAddress() {
        SslHeaderProbeService probe = new SslHeaderProbeService(new SslTargetGuard(false));
        SslHeaderProbeService.Probe p = probe.probe(SslTargetGuard.normalize("localhost.localdomain.test:1"));
        assertThat(p.headers()).isNull();
        SslHeaderProbeService.Probe local = probe.probe(new SslTargetGuard.Target("127.0.0.1", 443));
        assertThat(local.headers()).isNull();
        assertThat(local.error()).contains("adresse interne");
    }
}
