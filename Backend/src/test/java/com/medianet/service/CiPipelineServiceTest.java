package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.CiPipelineLink;
import com.medianet.repository.CiPipelineLinkRepo;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CiPipelineServiceTest {

    private final ObjectMapper json = new ObjectMapper();

    @Test
    void onlyGithubUrlsAreSupported() {
        assertThat(CiPipelineService.githubFullName("https://github.com/Karimarouchi/E-commerce-coussin"))
                .isEqualTo("Karimarouchi/E-commerce-coussin");
        assertThat(CiPipelineService.githubFullName("https://github.com/antigone-agency/E-commerce-vetement.git"))
                .isEqualTo("antigone-agency/E-commerce-vetement");
        assertThat(CiPipelineService.githubFullName("https://gitlab.com/a/b")).isNull();
        assertThat(CiPipelineService.githubFullName("https://github.com/a/b/../../x")).isNull();
    }

    /** Shape returned by Woodpecker 3.18.1 for GET /api/repos/1/pipelines/2 (observed on E-commerce-coussin). */
    @Test
    void readsPipelineStepsAndHidesLinterWarnings() throws Exception {
        JsonNode p = json.readTree("""
                {"number":2,"status":"failure","event":"manual","branch":"main","commit":"9513675079","message":"MANUAL PIPELINE @ main",
                 "author":"Karimarouchi","created":1792338910,"started":1792338912,"finished":0,
                 "errors":[{"type":"bad_habit","message":"Consider adding a when block","is_warning":true},
                           {"type":"linter","message":"steps.x: image is required","is_warning":false}],
                 "workflows":[{"name":"vulnix","children":[
                   {"id":3,"name":"clone","state":"success","exit_code":0,"started":1792338913,"finished":1792338920},
                   {"id":4,"name":"vulnix-scan","state":"failure","exit_code":1,"error":"exit code 1","started":1792338921}]}]}
                """);
        CiPipelineService.PipelineDetail d = CiPipelineService.detail(p);
        assertThat(d.pipeline().number()).isEqualTo(2);
        assertThat(d.pipeline().finished()).isNull();
        assertThat(d.steps()).extracting(CiPipelineService.Step::name).containsExactly("clone", "vulnix-scan");
        assertThat(d.steps().get(1).exitCode()).isEqualTo(1);
        assertThat(d.errors()).containsExactly("steps.x: image is required");
    }

    @Test
    void decodesBase64LogLines() throws Exception {
        JsonNode logs = json.readTree("[{\"line\":0,\"data\":\"KyBlY2hvIGhpCg==\"},{\"line\":1,\"data\":\"aGkK\"}]");
        assertThat(CiPipelineService.decodeLogs(logs)).extracting(CiPipelineService.LogLine::text)
                .containsExactly("+ echo hi", "hi");
    }

    @Test
    void configForARepoNotEnabledInVulnixFails() {
        CiPipelineLinkRepo repo = mock(CiPipelineLinkRepo.class);
        when(repo.findByWoodpeckerRepoId(anyLong())).thenReturn(Optional.empty());
        CiPipelineConfigService s = new CiPipelineConfigService(null, repo, json, null, "http://host.docker.internal:8080");
        String yaml = s.pipelineYaml("{\"repo\":{\"id\":7,\"full_name\":\"x/y\"},\"pipeline\":{\"commit\":\"abc\"}}".getBytes());
        assertThat(yaml).contains("vulnix-config").contains("pas activée dans Vulnix").doesNotContain("vulnix-scan");
    }

    @Test
    void woodpeckerErrorsAreExplained() {
        assertThat(WoodpeckerClient.woodpeckerReason(
                "Error #01: could not fetch branch head: dial tcp: lookup api.github.com on 127.0.0.11:53: server misbehaving\n"))
                .contains("n'arrive pas à joindre GitHub");
        assertThat(WoodpeckerClient.woodpeckerReason("Error #01: branch not found\n")).isEqualTo(" : branch not found");
        assertThat(WoodpeckerClient.woodpeckerReason("<html>oops</html>")).isEqualTo(".");
        assertThat(WoodpeckerClient.woodpeckerReason(null)).isEqualTo(".");
    }

    @Test
    void githubNetrcCarriesTheTokenAsLogin() throws Exception {
        assertThat(CiPipelineConfigService.netrcToken(json.readTree(
                "{\"machine\":\"github.com\",\"login\":\"gho_abc\",\"password\":\"x-oauth-basic\"}"))).isEqualTo("gho_abc");
        assertThat(CiPipelineConfigService.netrcToken(json.readTree(
                "{\"machine\":\"gitea.example\",\"login\":\"bob\",\"password\":\"tok\"}"))).isEqualTo("tok");
        assertThat(CiPipelineConfigService.netrcToken(json.readTree("{}"))).isEmpty();
    }

    @Test
    void configForAnotherForgeNameFails() {
        CiPipelineLinkRepo repo = mock(CiPipelineLinkRepo.class);
        when(repo.findByWoodpeckerRepoId(7L)).thenReturn(Optional.of(CiPipelineLink.builder()
                .woodpeckerRepoId(7L).forgeFullName("owner/real").repositoryId(3L).build()));
        CiPipelineConfigService s = new CiPipelineConfigService(null, repo, json, null, "http://host.docker.internal:8080");
        String yaml = s.pipelineYaml(("{\"repo\":{\"id\":7,\"full_name\":\"owner/renamed\"},\"pipeline\":{\"commit\":\""
                + "a".repeat(40) + "\"}}").getBytes());
        assertThat(yaml).contains("vulnix-config");
    }

    @SuppressWarnings("unused")
    private static InputStream res(String name) {
        return CiPipelineServiceTest.class.getResourceAsStream(name);
    }
}
