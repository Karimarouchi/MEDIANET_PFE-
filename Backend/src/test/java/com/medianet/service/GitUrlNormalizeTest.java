package com.medianet.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class GitUrlNormalizeTest {

    @Test
    void addsHttpsAndDropsATrailingSlash() {
        assertThat(ScanService.normalizeGitUrl("github.com/org/repo/")).isEqualTo("https://github.com/org/repo");
        assertThat(ScanService.normalizeGitUrl("https://gitlab.com/group/project.git"))
                .isEqualTo("https://gitlab.com/group/project.git");
    }

    @Test
    void rejectsAnythingThatIsNotARepositoryPath() {
        assertThat(ScanService.normalizeGitUrl("")).isNull();
        assertThat(ScanService.normalizeGitUrl("github.com")).isNull();
        assertThat(ScanService.normalizeGitUrl("docker://nginx")).isNull();
        assertThat(ScanService.normalizeGitUrl("not a url")).isNull();
    }
}
