package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.SupplyChainScore;
import com.medianet.repository.SupplyChainScoreRepo;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

@DisplayName("SupplyChainService — dépistage des dépendances npm (indicateur, jamais un blocage)")
class SupplyChainServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final SupplyChainService service = new SupplyChainService(
            mock(SupplyChainScoreRepo.class), "", "", "v4", 30, 400, true, true, 300);

    @Test
    @DisplayName("extrait les composants npm du SBOM Syft, sans doublon, avec les paquets à portée")
    void extractsNpmComponents() throws Exception {
        JsonNode sbom = MAPPER.readTree("""
                {"artifacts":[
                  {"name":"lodash","version":"4.17.21","type":"npm","purl":"pkg:npm/lodash@4.17.21"},
                  {"name":"@babel/core","version":"7.0.0","type":"npm","purl":"pkg:npm/%40babel/core@7.0.0"},
                  {"name":"lodash","version":"4.17.21","type":"npm","purl":"pkg:npm/lodash@4.17.21"},
                  {"name":"spring-core","version":"6.0.0","type":"java-archive","purl":"pkg:maven/org.springframework/spring-core@6.0.0"},
                  {"name":"","version":"1","type":"npm","purl":"pkg:npm/x@1"}
                ]}""");
        List<SupplyChainService.Component> out = SupplyChainService.extractNpmComponents(sbom);
        assertThat(out).extracting(SupplyChainService.Component::name).containsExactly("lodash", "@babel/core");
    }

    @Test
    @DisplayName("extrait aussi les paquets PyPI, avec le nom normalisé (PEP 503)")
    void extractsPypiComponents() throws Exception {
        JsonNode sbom = MAPPER.readTree("""
                {"artifacts":[
                  {"name":"Django_REST.framework","version":"3.14.0","type":"python","purl":"pkg:pypi/djangorestframework@3.14.0"},
                  {"name":"requests","version":"2.31.0","type":"python","purl":"pkg:pypi/requests@2.31.0"},
                  {"name":"requests","version":"2.31.0","type":"python","purl":"pkg:pypi/requests@2.31.0"},
                  {"name":"lodash","version":"4.17.21","type":"npm","purl":"pkg:npm/lodash@4.17.21"},
                  {"name":"guava","version":"32","type":"java-archive","purl":"pkg:maven/com.google.guava/guava@32"}
                ]}""");
        List<SupplyChainService.Component> all = SupplyChainService.extractComponents(sbom);
        assertThat(all).extracting(SupplyChainService.Component::key)
                .containsExactly("pypi:django-rest-framework@3.14.0", "pypi:requests@2.31.0", "npm:lodash@4.17.21");
        assertThat(SupplyChainService.extractNpmComponents(sbom)).hasSize(1);
        assertThat(SupplyChainService.normalizePypiName("Foo__Bar.baz")).isEqualTo("foo-bar-baz");
    }

    @Test
    @DisplayName("le cache distingue l'écosystème : un même nom npm et PyPI ne se mélange pas")
    void keysIncludeTheEcosystem() {
        assertThat(new SupplyChainService.Component("npm", "x", "1").key())
                .isNotEqualTo(new SupplyChainService.Component("pypi", "x", "1").key());
    }

    @Test
    @DisplayName("SBOM vide ou absent : aucune dépendance, pas d'erreur")
    void emptySbom() throws Exception {
        assertThat(SupplyChainService.extractNpmComponents(null)).isEmpty();
        assertThat(SupplyChainService.extractNpmComponents(MAPPER.readTree("{}"))).isEmpty();
    }

    @Test
    @DisplayName("une erreur réseau n'est jamais mise en cache (on réessaie au prochain scan)")
    void transientErrorsAreNotCached() throws Exception {
        var c = new SupplyChainService.Component("npm", "pkg", "1.0.0");
        assertThat(service.toEntity(c, MAPPER.readTree("{\"status\":\"NETWORK_ReadTimeout\"}"))).isNull();
        assertThat(service.toEntity(c, MAPPER.readTree("{\"status\":\"REGISTRY_503\"}"))).isNull();
        assertThat(service.toEntity(c, MAPPER.readTree("{\"status\":\"ERROR_ValueError\"}"))).isNull();
        assertThat(service.toEntity(c, MAPPER.readTree("{\"status\":\"NOT_FOUND\"}"))).isNotNull();
    }

    @Test
    @DisplayName("un paquet connu malveillant (OSSF) est stocké avec son identifiant")
    void knownMaliciousIsStored() throws Exception {
        var c = new SupplyChainService.Component("npm", "evil", "1.0.0");
        SupplyChainScore s = service.toEntity(c, MAPPER.readTree("""
                {"status":"SCORED","tier":"KNOWN_MALICIOUS","suspicionProba":1.0,"knownMaliciousId":"MAL-2022-2",
                 "reasons":["Listé comme malveillant par OSSF malicious-packages"]}"""));
        assertThat(s.getTier()).isEqualTo("KNOWN_MALICIOUS");
        assertThat(s.getKnownMaliciousId()).isEqualTo("MAL-2022-2");
        assertThat(SupplyChainService.parseReasons(s.getReasonsJson())).hasSize(1);
        assertThat(s.getModelVersion()).isEqualTo("v4");
    }

    @Test
    @DisplayName("le rapport compte chaque niveau, trie du plus grave au moins grave et signale les paquets en attente")
    void reportSummaryAndOrdering() {
        var comps = List.of(
                new SupplyChainService.Component("npm", "a", "1"), new SupplyChainService.Component("npm", "b", "1"),
                new SupplyChainService.Component("npm", "c", "1"), new SupplyChainService.Component("npm", "d", "1"),
                new SupplyChainService.Component("npm", "e", "1"), new SupplyChainService.Component("npm", "f", "1"));
        Map<String, SupplyChainScore> cached = Map.of(
                "npm:a@1", row("a", "REVIEW", 0.30),
                "npm:b@1", row("b", "KNOWN_MALICIOUS", 1.0),
                "npm:c@1", row("c", "HIGH_CONFIDENCE", 0.91),
                "npm:d@1", row("d", "LOW", 0.001),
                "npm:e@1", notScored("e"));
        Map<String, Object> report = service.buildReport(7L, comps, cached, false);

        @SuppressWarnings("unchecked")
        Map<String, Object> summary = (Map<String, Object>) report.get("summary");
        assertThat(summary).containsEntry("knownMalicious", 1).containsEntry("highConfidence", 1)
                .containsEntry("review", 1).containsEntry("low", 1).containsEntry("notAnalysed", 1)
                .containsEntry("pending", 1);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> flagged = (List<Map<String, Object>>) report.get("flagged");
        assertThat(flagged).extracting(m -> m.get("name")).containsExactly("b", "c", "a");
        assertThat(report.get("totalComponents")).isEqualTo(6);
        assertThat((String) report.get("disclaimer")).contains("pas une décision de blocage");
    }

    @Test
    @DisplayName("le rapport liste TOUTES les dépendances analysées (preuve de travail) et celles ignorées")
    void reportListsEveryAnalysedDependency() {
        var comps = List.of(
                new SupplyChainService.Component("npm", "a", "1"), new SupplyChainService.Component("npm", "b", "1"),
                new SupplyChainService.Component("npm", "e", "1"));
        Map<String, SupplyChainScore> cached = Map.of(
                "npm:a@1", row("a", "LOW", 0.02),
                "npm:b@1", row("b", "REVIEW", 0.30),
                "npm:e@1", notScored("e"));
        Map<String, Object> report = service.buildReport(1L, comps, cached, false);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> analyzed = (List<Map<String, Object>>) report.get("analyzed");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> skipped = (List<Map<String, Object>>) report.get("skipped");
        assertThat(analyzed).extracting(m -> m.get("name")).containsExactly("b", "a"); // most suspicious first
        assertThat(analyzed.get(1)).containsEntry("suspicionProba", 0.02).containsEntry("tier", "LOW");
        assertThat(skipped).extracting(m -> m.get("name")).containsExactly("e");
        assertThat(skipped.get(0)).containsEntry("status", "NOT_FOUND");
    }

    @Test
    @DisplayName("la vérification à la demande refuse les demandes vides, trop grandes ou aux noms dangereux")
    void checkRequestValidation() {
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> SupplyChainService.validateCheckRequest(List.of()));
        List<SupplyChainService.Component> tooMany = new java.util.ArrayList<>();
        for (int i = 0; i < SupplyChainService.MAX_CHECK_PACKAGES + 1; i++) {
            tooMany.add(new SupplyChainService.Component("npm", "p" + i, "1"));
        }
        org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> SupplyChainService.validateCheckRequest(tooMany));
        for (String bad : List.of("a b", "x;rm -rf", "../../etc", "a\"b", "")) {
            org.junit.jupiter.api.Assertions.assertThrows(org.springframework.web.server.ResponseStatusException.class,
                    () -> SupplyChainService.validateCheckRequest(
                            List.of(new SupplyChainService.Component("npm", bad, "1"))), bad);
        }
    }

    @Test
    @DisplayName("la vérification accepte les noms npm (portée, tirets) et normalise les noms PyPI")
    void checkRequestAcceptsRealNames() {
        List<SupplyChainService.Component> ok = SupplyChainService.validateCheckRequest(List.of(
                new SupplyChainService.Component("npm", "@angular/core", "17.0.0"),
                new SupplyChainService.Component("NPM", "--hiljson", ""),
                new SupplyChainService.Component("pypi", "Django_REST.framework", "3.14.0")));
        assertThat(ok).extracting(SupplyChainService.Component::key).containsExactly(
                "npm:@angular/core@17.0.0", "npm:--hiljson@", "pypi:django-rest-framework@3.14.0");
    }

    @Test
    @DisplayName("le journal du scan annonce la recherche de paquets malveillants puis son bilan")
    void scanLogLines() {
        var comps = List.of(new SupplyChainService.Component("npm", "a", "1"),
                new SupplyChainService.Component("npm", "b", "1"),
                new SupplyChainService.Component("pypi", "c", "1"));
        assertThat(SupplyChainService.startLine(comps, 3))
                .isEqualTo("[SUPPLY-CHAIN] Recherche des paquets malveillants dans 3 dépendances (npm : 2, PyPI : 1)...");
        assertThat(SupplyChainService.startLine(comps, 1)).contains("2 déjà connues en cache");

        Map<String, SupplyChainScore> cached = Map.of(
                "npm:a@1", row("a", "KNOWN_MALICIOUS", 1.0),
                "npm:b@1", row("b", "REVIEW", 0.3),
                "pypi:c@1", notScored("c"));
        Map<String, Object> report = service.buildReport(1L, comps, cached, false);
        assertThat(SupplyChainService.summaryLine(report)).isEqualTo(
                "[SUPPLY-CHAIN] Terminé : 2 analysées — 1 connu(s) malveillant(s), 0 confiance élevée, "
                        + "1 à vérifier, 1 non analysable(s).");
    }

    @Test
    @DisplayName("sans dépendance npm/PyPI, le journal le dit et le scan n'est pas bloqué")
    void scanLogWhenNothingToAnalyse() {
        var scan = new com.medianet.entity.ScanResult();
        scan.setId(5L);
        scan.setResultsDir("does-not-exist");
        List<String> lines = new java.util.ArrayList<>();
        service.analyzeDuringScan(scan, lines::add);
        assertThat(lines).containsExactly("[SUPPLY-CHAIN] Aucune dépendance npm ou PyPI dans le SBOM : rien à analyser.");
    }

    @Test
    @DisplayName("un score d'une autre version du modèle ou trop ancien n'est pas réutilisé")
    void freshness() {
        SupplyChainScore ok = row("a", "LOW", 0.0);
        assertThat(service.isFresh(ok, LocalDateTime.now().minusDays(30))).isTrue();
        ok.setModelVersion("v3");
        assertThat(service.isFresh(ok, LocalDateTime.now().minusDays(30))).isFalse();
        SupplyChainScore old = row("b", "LOW", 0.0);
        old.setScoredAt(LocalDateTime.now().minusDays(45));
        assertThat(service.isFresh(old, LocalDateTime.now().minusDays(30))).isFalse();
    }

    @Test
    @DisplayName("les niveaux sont triés : connu malveillant, confiance élevée, à vérifier")
    void tierRanking() {
        assertThat(SupplyChainService.tierRank("KNOWN_MALICIOUS")).isLessThan(SupplyChainService.tierRank("HIGH_CONFIDENCE"));
        assertThat(SupplyChainService.tierRank("HIGH_CONFIDENCE")).isLessThan(SupplyChainService.tierRank("REVIEW"));
        assertThat(SupplyChainService.tierRank("REVIEW")).isLessThan(SupplyChainService.tierRank("LOW"));
    }

    private static SupplyChainScore row(String name, String tier, double proba) {
        return SupplyChainScore.builder().ecosystem("npm").name(name).version("1").status("SCORED").tier(tier)
                .suspicionProba(proba).modelVersion("v4").reasonsJson("[\"raison\"]").scoredAt(LocalDateTime.now()).build();
    }

    private static SupplyChainScore notScored(String name) {
        return SupplyChainScore.builder().ecosystem("npm").name(name).version("1").status("NOT_FOUND")
                .modelVersion("v4").scoredAt(LocalDateTime.now()).build();
    }
}
