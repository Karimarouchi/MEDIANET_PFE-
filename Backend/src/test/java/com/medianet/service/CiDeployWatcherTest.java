package com.medianet.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.medianet.entity.DeployStrategy;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CiDeployWatcherTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String A = "a".repeat(40);
    private static final String B = "b".repeat(40);

    private static JsonNode list(String json) throws Exception {
        return JSON.readTree(json);
    }

    private static String p(long n, String status, String branch, String event, String sha) {
        return "{\"number\":" + n + ",\"status\":\"" + status + "\",\"branch\":\"" + branch + "\",\"event\":\"" + event
                + "\",\"commit\":\"" + sha + "\"}";
    }

    @Test
    void firstRoundOnlyRecordsWhereThingsStand() throws Exception {
        CiDeployWatcher.Decision d = CiDeployWatcher.decide(list("[" + p(5, "success", "main", "push", A) + "]"), "main", null);
        assertThat(d.newestFinished()).isEqualTo(5L);
        assertThat(d.toDeploy()).isNull(); // the first install is done by hand
    }

    @Test
    void newGreenPipelineIsDeployedOnce() throws Exception {
        JsonNode pipelines = list("[" + p(6, "success", "main", "push", B) + "," + p(5, "success", "main", "push", A) + "]");
        CiDeployWatcher.Decision d = CiDeployWatcher.decide(pipelines, "main", 5L);
        assertThat(d.toDeploy().path("commit").asText()).isEqualTo(B);
        assertThat(d.newestFinished()).isEqualTo(6L);
        assertThat(CiDeployWatcher.decide(pipelines, "main", 6L).toDeploy()).isNull();
    }

    @Test
    void redPipelineMovesNothingAndAnOlderGreenIsNeverDeployedAfterIt() throws Exception {
        JsonNode pipelines = list("[" + p(7, "failure", "main", "push", B) + "," + p(6, "success", "main", "push", A) + "]");
        CiDeployWatcher.Decision d = CiDeployWatcher.decide(pipelines, "main", 5L);
        assertThat(d.toDeploy()).isNull();
        assertThat(d.newestFinished()).isEqualTo(7L);
    }

    @Test
    void runningPipelinesAndOtherBranchesAreIgnored() throws Exception {
        JsonNode pipelines = list("[" + p(9, "running", "main", "push", B) + "," + p(8, "success", "dev", "push", B) + ","
                + p(7, "success", "main", "pull_request", B) + "," + p(6, "success", "main", "push", A) + "]");
        CiDeployWatcher.Decision d = CiDeployWatcher.decide(pipelines, "main", 5L);
        assertThat(d.toDeploy().path("number").asLong()).isEqualTo(6L);
    }

    @Test
    void deployScriptPutsTheExactCommitChecksHealthAndRollsBack() {
        String s = DeployService.buildDeployScript("/opt/antigone/app", "main", DeployStrategy.DOCKER_COMPOSE, A,
                "http://localhost:8080/api/health");
        assertThat(s)
                .contains("cd '/opt/antigone/app'")
                .contains("git fetch origin 'main'")
                .contains("TARGET='" + A + "'")
                .contains("git reset --hard \"$TARGET\"")
                .contains("docker compose up -d --build")
                .contains("curl -fsS -o /dev/null --max-time 5 'http://localhost:8080/api/health'")
                .contains("git reset --hard \"$PREV\"")
                .contains("exit " + DeployService.EXIT_ROLLED_BACK)
                .doesNotContain("origin/main)");
        String manual = DeployService.buildDeployScript("/opt/x", "main", DeployStrategy.DOCKER_COMPOSE, null, null);
        assertThat(manual).contains("TARGET=$(git rev-parse 'origin/main')").contains("docker compose ps -a --format");
    }

    @Test
    void deployedCommitIsReadFromTheScriptOutput() {
        assertThat(DeployService.deployedCommit("[CD] Version en place : " + A + "\n[CD] Nouvelle version : " + B + "\n")).isEqualTo(B);
        assertThat(DeployService.deployedCommit("[CD] Dossier introuvable sur le serveur")).isNull();
    }
}
