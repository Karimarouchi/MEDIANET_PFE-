package com.medianet.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("DeployFieldValidator — allowlist chemin / branche / domaine")
class DeployFieldValidatorTest {

    @Test
    void acceptsSimpleAbsolutePath() {
        assertThat(DeployFieldValidator.normalizePath("/var/www/pfe/MEDIANET_PFE-", false))
                .isEqualTo("/var/www/pfe/MEDIANET_PFE-");
    }

    @Test
    void rejectsPathTraversalAndShellMetacharacters() {
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizePath("/tmp/../etc", false));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizePath("/tmp;rm -rf /", false));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizePath("/tmp$(id)", false));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizePath("relative/path", false));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizePath("", true));
    }

    @Test
    void blankOptionalPathBecomesNull() {
        assertThat(DeployFieldValidator.normalizePath("  ", false)).isNull();
        assertThat(DeployFieldValidator.normalizePath(null, false)).isNull();
    }

    @Test
    void acceptsSafeBranchAndDomain() {
        assertThat(DeployFieldValidator.normalizeBranch("feature/v1.2")).isEqualTo("feature/v1.2");
        assertThat(DeployFieldValidator.normalizeBranch("")).isEqualTo("main");
        assertThat(DeployFieldValidator.normalizeDomain("https://pfe.exemple.com/"))
                .isEqualTo("pfe.exemple.com");
    }

    @Test
    void acceptsKnownDeployStrategies() {
        assertThat(DeployFieldValidator.normalizeStrategy(null).name()).isEqualTo("DOCKER_COMPOSE");
        assertThat(DeployFieldValidator.normalizeStrategy("static_nginx").name()).isEqualTo("STATIC_NGINX");
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizeStrategy("rm -rf"));
    }

    @Test
    void rejectsUnsafeBranchAndDomain() {
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizeBranch("main;reboot"));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizeDomain("evil.com;id"));
        assertThrows(ResponseStatusException.class, () -> DeployFieldValidator.normalizeDomain("not a host"));
    }
}
