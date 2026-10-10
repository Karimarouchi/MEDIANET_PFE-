package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.SecretFinding;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("SecretTriageService — tri des secrets gitleaks par le modèle")
class SecretTriageServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static SecretFinding finding(String rule, String file, String match, String raw) {
        return SecretFinding.builder().ruleId(rule).file(file).startLine(3).match(match).rawSecret(raw).build();
    }

    @Test
    @DisplayName("payload : la valeur brute est envoyée seulement quand elle est connue")
    void payloadUsesRawSecretOnlyWhenKnown() {
        List<Map<String, Object>> payload = SecretTriageService.buildPayload(List.of(
                finding("generic-api-key", "/r/a.js", "k: \"v\"", "v"),
                finding("generic-api-key", "/r/b.js", "k: \"w\"", null)));
        assertThat(payload.get(0)).containsEntry("Secret", "v").containsEntry("Match", "k: \"v\"");
        assertThat(payload.get(1)).doesNotContainKey("Secret");
    }

    @Test
    @DisplayName("réponse : verdict, probabilité, priorité et raisons recopiés dans l'ordre")
    void applyAnswerCopiesVerdicts() throws Exception {
        SecretTriageService svc = new SecretTriageService("", "", true, 30);
        List<SecretFinding> list = new ArrayList<>(List.of(finding("r", "/a", "m", "s"), finding("r", "/b", "m", "s")));
        int filled = svc.applyAnswer(list, MAPPER.readTree("""
                [{"verdict":"LIKELY_REAL","probaReal":0.97,"scope":"PRODUCTION","priority":1,"reasons":["a","b"],"modelVersion":"secrets-v1"},
                 {"verdict":"LIKELY_FALSE_POSITIVE","probaReal":0.02,"scope":"TEST_OR_DOC","priority":4,"reasons":[],"modelVersion":"secrets-v1"}]
                """));
        assertThat(filled).isEqualTo(2);
        assertThat(list.get(0).getMlVerdict()).isEqualTo("LIKELY_REAL");
        assertThat(list.get(0).getMlPriority()).isEqualTo(1);
        assertThat(list.get(0).getMlReasons()).isEqualTo("[\"a\",\"b\"]");
        assertThat(list.get(1).getMlVerdict()).isEqualTo("LIKELY_FALSE_POSITIVE");
        assertThat(svc.summaryLine(list)).contains("1 probablement réel").contains("1 faux positif");
    }

    @Test
    @DisplayName("réponse de mauvaise taille : refusée, aucun verdict n'est inventé")
    void sizeMismatchIsRejected() throws Exception {
        SecretTriageService svc = new SecretTriageService("", "", true, 30);
        List<SecretFinding> list = List.of(finding("r", "/a", "m", "s"));
        assertThatThrownBy(() -> svc.applyAnswer(list, MAPPER.readTree("[]"))).isInstanceOf(IllegalStateException.class);
        assertThat(list.get(0).getMlVerdict()).isNull();
    }

    @Test
    @DisplayName("désactivé : apply() ne fait rien et ne lève pas d'erreur")
    void disabledDoesNothing() {
        SecretTriageService svc = new SecretTriageService("", "", false, 30);
        List<SecretFinding> list = List.of(finding("r", "/a", "m", "s"));
        assertThat(svc.apply(list)).isZero();
        assertThat(svc.apply(null)).isZero();
        assertThat(svc.summaryLine(list)).isNull();
    }

    @Test
    @DisplayName("modèle réel (Python) : placeholder = faux positif probable, clé AWS en production = réel")
    void realModelEndToEnd() {
        Path ml = Path.of("..", "ml").toAbsolutePath().normalize();
        assumeTrue(Files.isRegularFile(ml.resolve("secrets/artifacts/secret_triage.joblib")), "bundle not exported");
        SecretTriageService svc = new SecretTriageService(ml.toString(), "", true, 120);
        assumeTrue(svc.isAvailable());

        List<SecretFinding> list = new ArrayList<>(List.of(
                finding("generic-api-key", "/workspace/repo/src/db.py", "password = \"<YOUR_PASSWORD>\"", "<YOUR_PASSWORD>"),
                finding("aws-access-token", "/workspace/repo/src/aws.py", "aws_key = \"AKIAQ3RT7XK2M9WZP4LD\"",
                        "AKIAQ3RT7XK2M9WZP4LD"),
                finding("generic-api-key", "/workspace/repo/docs/guide.md", "SECRET_KEY = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'", null)));
        assertThat(svc.apply(list)).isEqualTo(3);

        assertThat(list.get(0).getMlVerdict()).isEqualTo("LIKELY_FALSE_POSITIVE");
        assertThat(list.get(1).getMlVerdict()).isEqualTo("LIKELY_REAL");
        assertThat(list.get(1).getMlScope()).isEqualTo("PRODUCTION");
        assertThat(list.get(2).getMlScope()).isEqualTo("TEST_OR_DOC"); // stored match only: value derived from it
        assertThat(list).allSatisfy(s -> {
            assertThat(s.getMlProba()).isBetween(0.0, 1.0);
            assertThat(s.getMlModelVersion()).isNotBlank();
        });
    }
}
