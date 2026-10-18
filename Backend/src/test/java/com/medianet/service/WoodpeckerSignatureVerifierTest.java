package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/** Real request captured from Woodpecker 3.18.1 (manual pipeline on Karimarouchi/E-commerce-coussin). */
class WoodpeckerSignatureVerifierTest {

    private static byte[] read(String name) throws Exception {
        try (InputStream in = WoodpeckerSignatureVerifierTest.class.getResourceAsStream("/woodpecker/" + name)) {
            return in.readAllBytes();
        }
    }

    private final JsonNode h;
    private final byte[] body;
    private final PublicKey key;
    private final Instant signedAt;

    WoodpeckerSignatureVerifierTest() throws Exception {
        h = new ObjectMapper().readTree(read("config-request.headers.json"));
        body = read("config-request.body.json");
        key = WoodpeckerSignatureVerifier.parsePem(h.get("publicKeyPem").asText());
        signedAt = Instant.ofEpochSecond(Long.parseLong(h.get("signatureInput").asText().replaceAll(".*created=(\\d+).*", "$1")));
    }

    private String verify(String target, byte[] b, Instant now) {
        return WoodpeckerSignatureVerifier.verify(key, target, b, h.get("contentDigest").asText(),
                h.get("signatureInput").asText(), h.get("signature").asText(), now);
    }

    @Test
    void genuineWoodpeckerRequestPasses() {
        assertThat(verify(h.get("path").asText(), body, signedAt.plusSeconds(30))).isNull();
    }

    @Test
    void changedBodyFails() {
        byte[] tampered = Arrays.copyOf(body, body.length);
        tampered[10] ^= 1;
        assertThat(verify(h.get("path").asText(), tampered, signedAt)).isNotNull();
    }

    @Test
    void otherTargetFails() {
        assertThat(verify("/api/other", body, signedAt)).isEqualTo("signature invalide");
    }

    @Test
    void oldSignatureFails() {
        assertThat(verify(h.get("path").asText(), body, signedAt.plusSeconds(600))).isEqualTo("signature expirée");
    }

    @Test
    void missingHeadersFail() {
        assertThat(WoodpeckerSignatureVerifier.verify(key, "/config", body, null, null, null, signedAt)).isNotNull();
    }
}
