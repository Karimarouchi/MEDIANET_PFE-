package com.medianet.service;

import com.medianet.util.ClientIp;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Scan parameters that become scanner arguments, GitLab token host binding, and the rate-limit client address. */
class ScanInputValidatorTest {

    private final ScanInputValidator validator = new ScanInputValidator(new SslTargetGuard(false));

    @Test
    void acceptsTheValuesTheUiOffers() {
        assertThat(ScanInputValidator.branch("feature/login-v2")).isEqualTo("feature/login-v2");
        assertThat(ScanInputValidator.commitSha("ABCDEF1")).isEqualTo("abcdef1");
        assertThat(ScanInputValidator.targetOs("ubuntu:22.04")).isEqualTo("ubuntu:22.04");
        assertThat(ScanInputValidator.complianceProfile("cis_l1")).isEqualTo("CIS_L1");
        assertThat(ScanInputValidator.dockerImage("antigoneagency/ecommerce-frontoffice:latest")).isNotNull();
        assertThat(ScanInputValidator.containerPort(3000)).isEqualTo(3000);
        assertThat(ScanInputValidator.branch(null)).isNull();
    }

    @Test
    void refusesValuesThatWouldBecomeOptionsOrExtraArguments() {
        for (Runnable r : new Runnable[] {
                () -> ScanInputValidator.branch("--upload-pack=touch /tmp/x"),
                () -> ScanInputValidator.branch("a..b"),
                () -> ScanInputValidator.commitSha("--output=/etc/x"),
                () -> ScanInputValidator.targetOs("ubuntu:22.04 -o template -t /etc/passwd"),
                () -> ScanInputValidator.complianceProfile("CIS_L1; rm -rf /"),
                () -> ScanInputValidator.dockerImage("--privileged"),
                () -> ScanInputValidator.containerPort(0),
        }) {
            assertThatThrownBy(r::run).isInstanceOf(ResponseStatusException.class);
        }
    }

    @Test
    void dastAndDomainTargetsMustBePublic() {
        assertThatThrownBy(() -> validator.dastTargetUrl("http://169.254.169.254/latest/meta-data/"))
                .hasMessageContaining("adresse interne");
        assertThatThrownBy(() -> validator.dastTargetUrl("http://user:pw@8.8.8.8/")).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> validator.dastTargetUrl("file:///etc/passwd")).isInstanceOf(ResponseStatusException.class);
        assertThatThrownBy(() -> validator.targetDomain("10.0.0.1")).hasMessageContaining("adresse interne");
        assertThat(validator.dastTargetUrl("https://8.8.8.8/app")).isEqualTo("https://8.8.8.8/app");
    }

    @Test
    void gitlabTokenOnlyForTheUsersOwnHostOverHttps() {
        assertThat(ScanService.isTrustedGitlabUrl("https://gitlab.com/group/repo.git", null)).isTrue();
        assertThat(ScanService.isTrustedGitlabUrl("https://attacker.example/gitlab.com/repo.git", null)).isFalse();
        assertThat(ScanService.isTrustedGitlabUrl("https://gitlab.com.attacker.example/repo.git", null)).isFalse();
        assertThat(ScanService.isTrustedGitlabUrl("http://gitlab.com/repo.git", null)).isFalse();
        assertThat(ScanService.isTrustedGitlabUrl("https://x@gitlab.com/repo.git", null)).isFalse();
        assertThat(ScanService.isTrustedGitlabUrl("https://git.company.tn/a/b.git", "https://git.company.tn")).isTrue();
        assertThat(ScanService.isTrustedGitlabUrl("https://gitlab.com/a/b.git", "https://git.company.tn")).isFalse();
    }

    @Test
    void forwardedForIsTrustedOnlyFromALocalProxyAndOnlyItsLastEntry() {
        MockHttpServletRequest direct = new MockHttpServletRequest();
        direct.setRemoteAddr("203.0.113.9");
        direct.addHeader("X-Forwarded-For", "1.2.3.4");
        assertThat(ClientIp.of(direct)).isEqualTo("203.0.113.9");

        MockHttpServletRequest viaNginx = new MockHttpServletRequest();
        viaNginx.setRemoteAddr("172.18.0.5");
        viaNginx.addHeader("X-Forwarded-For", "6.6.6.6, 198.51.100.7"); // client-forged first, proxy-added last
        assertThat(ClientIp.of(viaNginx)).isEqualTo("198.51.100.7");
    }
}
