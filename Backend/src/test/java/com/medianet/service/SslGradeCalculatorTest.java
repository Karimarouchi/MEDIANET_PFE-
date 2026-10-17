package com.medianet.service;

import com.medianet.service.SslGradeCalculator.SourceGrade;
import com.medianet.service.SslGradeCalculator.SslyzeFacts;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SslGradeCalculatorTest {

    private static SourceGrade g(String source, String grade, int w) {
        return new SourceGrade(source, grade, w);
    }

    @Test
    void scoresAndBackAreConsistent() {
        for (String grade : List.of("A+", "A", "A-", "B", "C", "D", "E", "F")) {
            assertThat(SslGradeCalculator.fromScore(SslGradeCalculator.score(grade))).as(grade).isEqualTo(grade);
        }
        assertThat(SslGradeCalculator.score("T")).isZero();
        assertThat(SslGradeCalculator.score("M")).isZero();
        assertThat(SslGradeCalculator.score("?")).isEqualTo(-1);
    }

    @Test
    void noGradeGivesQuestionMark() {
        assertThat(SslGradeCalculator.combine(List.of())).isEqualTo("?");
        assertThat(SslGradeCalculator.combine(List.of(g("kali", "?", 25)))).isEqualTo("?");
    }

    @Test
    void anyFailingToolGivesF() {
        assertThat(SslGradeCalculator.combine(List.of(g("ssllabs", "A+", 40), g("kali", "A", 25), g("censys", "F", 10))))
                .isEqualTo("F");
        // SSL Labs "T" = certificate not trusted
        assertThat(SslGradeCalculator.combine(List.of(g("ssllabs", "T", 40), g("sslyze", "A", 25)))).isEqualTo("F");
    }

    @Test
    void oneSevereOpinionIsNotAveragedAway() {
        // The weighted mean is A, but a D from one tool caps the summary one step above it, at C
        assertThat(SslGradeCalculator.combine(List.of(g("ssllabs", "A+", 40), g("kali", "A+", 25),
                g("sslyze", "A+", 25), g("censys", "D", 10)))).isEqualTo("C");
    }

    @Test
    void agreeingToolsKeepTheirGrade() {
        assertThat(SslGradeCalculator.combine(List.of(g("ssllabs", "A", 40), g("kali", "A", 25), g("sslyze", "A", 25))))
                .isEqualTo("A");
        assertThat(SslGradeCalculator.combine(List.of(g("ssllabs", "B", 40), g("kali", "B", 25)))).isEqualTo("B");
    }

    private static SslyzeFacts facts(boolean trusted, boolean mismatch, Integer days, boolean ssl30, boolean tls10,
            boolean tls12, boolean tls13, int key, boolean ocsp) {
        return new SslyzeFacts(false, false, false, trusted, mismatch, days, false, ssl30, tls10, false, tls12, tls13,
                key, ocsp);
    }

    @Test
    void sslyzeGradeFollowsTheSslLabsGuide() {
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, false, true, true, 2048, true))).isEqualTo("A+");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, false, true, true, 2048, false))).isEqualTo("A");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, true, true, true, 2048, true))).isEqualTo("B");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, false, true, false, 2048, true))).isEqualTo("B");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, true, false, true, true, 2048, true))).isEqualTo("C");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, false, true, true, 1024, true))).isEqualTo("C");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, 80, false, true, false, false, 2048, true))).isEqualTo("C");
    }

    @Test
    void certificatesABrowserRefusesGiveF() {
        assertThat(SslGradeCalculator.sslyzeGrade(facts(false, false, 80, false, false, true, true, 2048, true)))
                .as("self-signed / untrusted").isEqualTo("F");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, true, 80, false, false, true, true, 2048, true)))
                .as("wrong host").isEqualTo("F");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, -3, false, false, true, true, 2048, true)))
                .as("expired").isEqualTo("F");
        assertThat(SslGradeCalculator.sslyzeGrade(facts(true, false, null, false, false, true, true, 2048, true)))
                .as("unknown expiry is not a failure").isEqualTo("A+");
    }
}
