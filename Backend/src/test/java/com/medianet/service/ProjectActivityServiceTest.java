package com.medianet.service;

import com.medianet.entity.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/** Which project member a commit belongs to, and the diff counter used for GitLab. */
class ProjectActivityServiceTest {

    private static RepoCommitService.CommitInfo commit(String name, String email, String login) {
        return new RepoCommitService.CommitInfo("a".repeat(40), "aaaaaaa", "feat", "feat", name, email, login, Instant.now(), null);
    }

    private final User rania = User.builder().id(1L).login("raniakhedri").email("rania@medianet.tn").name("Rania Khedri").build();

    @Test
    void commitIsTheMembersByLoginEmailNoreplyOrName() {
        assertThat(ProjectActivityService.matches(rania, commit("x", "x@y.z", "RaniaKhedri"))).isTrue();
        assertThat(ProjectActivityService.matches(rania, commit("x", "Rania@Medianet.tn", null))).isTrue();
        assertThat(ProjectActivityService.matches(rania, commit("x", "123456+raniakhedri@users.noreply.github.com", null))).isTrue();
        assertThat(ProjectActivityService.matches(rania, commit("rania khedri", "perso@gmail.com", null))).isTrue();
    }

    @Test
    void anotherAuthorIsNotTheMember() {
        assertThat(ProjectActivityService.matches(rania, commit("Karim", "karim@medianet.tn", "Karimarouchi"))).isFalse();
        assertThat(ProjectActivityService.matches(rania, commit(null, null, null))).isFalse();
        // A local account whose login is its e-mail.
        User local = User.builder().id(2L).login("karim@medianet.tn").build();
        assertThat(ProjectActivityService.matches(local, commit("K", "karim@medianet.tn", null))).isTrue();
    }

    @Test
    void gitLabDiffLinesAreCounted() {
        int[] c = RepoCommitService.countDiff("--- a/x\n+++ b/x\n@@ -1,2 +1,3 @@\n-old\n+new\n+added\n same");
        assertThat(c).containsExactly(2, 1);
    }

    @Test
    void gitHubFullNameIsReadFromTheUrl() {
        assertThat(RepoCommitService.githubFullName("https://github.com/Karimarouchi/Antigone_finance.git")).isEqualTo("Karimarouchi/Antigone_finance");
        assertThat(RepoCommitService.githubFullName("https://github.com/a/b/")).isEqualTo("a/b");
    }
}
