package com.medianet.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Dependency-Check package identity, so its CVE rows merge with the Grype/Trivy rows for the same package. */
class DependencyCheckIdentityTest {

    private final ObjectMapper mapper = new ObjectMapper();

    private ResultParserService.DcIdentity id(String json, String fileName) throws Exception {
        return ResultParserService.dcIdentity(mapper.readTree(json), fileName);
    }

    @Test
    void npmPackageFromPackageUrl() throws Exception {
        // was: name "braces:3.0", no version, ecosystem guessed "maven"
        var d = id("{\"packages\":[{\"id\":\"pkg:npm/braces@3.0.3\"}]}", "braces:3.0.3");
        assertThat(d.name()).isEqualTo("braces");
        assertThat(d.version()).isEqualTo("3.0.3");
        assertThat(d.ecosystem()).isEqualTo("npm");
    }

    @Test
    void scopedNpmAndMavenPackages() throws Exception {
        assertThat(id("{\"packages\":[{\"id\":\"pkg:npm/%40babel/core@7.29.0\"}]}", "x").name()).isEqualTo("@babel/core");
        var m = id("{\"packages\":[{\"id\":\"pkg:maven/org.springframework/spring-core@6.2.19\"}]}", "spring-core-6.2.19.jar");
        assertThat(m.name()).isEqualTo("org.springframework:spring-core");
        assertThat(m.version()).isEqualTo("6.2.19");
        assertThat(m.ecosystem()).isEqualTo("maven");
    }

    @Test
    void fileNameFallbacks() throws Exception {
        var npm = id("{}", "postcss:7.0.39");
        assertThat(npm.name()).isEqualTo("postcss");
        assertThat(npm.version()).isEqualTo("7.0.39");
        var jar = id("{}", "spring-core-6.1.4.jar");
        assertThat(jar.name()).isEqualTo("spring-core");
        assertThat(jar.version()).isEqualTo("6.1.4");
    }
}
