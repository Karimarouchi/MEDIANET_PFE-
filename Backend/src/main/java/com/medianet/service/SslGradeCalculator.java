package com.medianet.service;

import java.util.List;
import java.util.Locale;

/**
 * Grade rules for the SSL sources, kept apart from file parsing so they can be tested on their own.
 *
 * The verdict shown at the top of the SSL page is the category score computed by the page (each lost point is
 * listed). The grades here are the opinion of each tool, and {@link #combine} is a summary of those opinions
 * ("note des outils"), not the verdict.
 */
public final class SslGradeCalculator {

    private SslGradeCalculator() {
    }

    /** Grade of one source, with its weight in the tools' summary. */
    public record SourceGrade(String source, String grade, int weight) {
    }

    /**
     * Weights of the tools' summary. SSL Labs is the public reference with a published grading guide, so it counts
     * most; Kali and SSLyze test the server directly; Censys only sees the certificate from its Internet index,
     * sometimes days old, so it counts least.
     */
    public static final int WEIGHT_KALI = 25;
    public static final int WEIGHT_SSLLABS = 40;
    public static final int WEIGHT_CENSYS = 10;
    public static final int WEIGHT_SSLYZE = 25;

    private static final List<String> ORDER = List.of("A+", "A", "A-", "B", "C", "D", "E", "F");

    /** Points of a grade on 100. SSL Labs "T" (untrusted certificate) and "M" (name mismatch) count as F. -1 = unknown. */
    public static int score(String grade) {
        if (grade == null) {
            return -1;
        }
        return switch (grade.trim().toUpperCase(Locale.ROOT)) {
            case "A+" -> 100;
            case "A" -> 90;
            case "A-" -> 85;
            case "B" -> 75;
            case "C" -> 60;
            case "D" -> 45;
            case "E" -> 30;
            case "F", "T", "M" -> 0;
            default -> -1;
        };
    }

    /** Back from points to a grade, with thresholds halfway between the points of two grades. */
    public static String fromScore(double s) {
        if (s >= 95) {
            return "A+";
        }
        if (s >= 87.5) {
            return "A";
        }
        if (s >= 80) {
            return "A-";
        }
        if (s >= 67.5) {
            return "B";
        }
        if (s >= 52.5) {
            return "C";
        }
        if (s >= 37.5) {
            return "D";
        }
        if (s >= 15) {
            return "E";
        }
        return "F";
    }

    /** 0 = A+ … 7 = F. Unknown grades rank as F. */
    static int rank(String grade) {
        int s = score(grade);
        if (s == 0) {
            return ORDER.size() - 1;
        }
        int i = ORDER.indexOf(grade == null ? "" : grade.trim().toUpperCase(Locale.ROOT));
        return i < 0 ? ORDER.size() - 1 : i;
    }

    /**
     * Summary of the tools' grades: weighted mean of the known grades, F as soon as one tool says F (or T/M), and
     * never more than one step better than the most severe tool, so a single bad opinion is not averaged away.
     * Returns "?" when no tool gave a grade.
     */
    public static String combine(List<SourceGrade> grades) {
        double sum = 0;
        double weight = 0;
        int worst = -1;
        for (SourceGrade g : grades) {
            int s = score(g.grade());
            if (s < 0 || g.weight() <= 0) {
                continue;
            }
            if (s == 0) {
                return "F";
            }
            sum += s * (double) g.weight();
            weight += g.weight();
            worst = Math.max(worst, rank(g.grade()));
        }
        if (weight == 0) {
            return "?";
        }
        String mean = fromScore(sum / weight);
        int capRank = Math.max(0, worst - 1);
        return rank(mean) < capRank ? ORDER.get(capRank) : mean;
    }

    /** Facts SSLyze measured, for its grade. {@code daysLeft} null when unknown. */
    public record SslyzeFacts(boolean heartbleed, boolean robot, boolean ccsInjection, boolean chainTrusted,
            boolean hostnameMismatch, Integer daysLeft, boolean ssl20, boolean ssl30, boolean tls10, boolean tls11,
            boolean tls12, boolean tls13, int keySize, boolean ocspStapling) {
    }

    /**
     * SSLyze grade, on the lines of the SSL Labs grading guide: F for a critical flaw or a certificate a browser
     * refuses (expired, untrusted, wrong name, SSL 2.0); C for SSL 3.0, no TLS 1.2 or a key under 2048 bits; B for
     * TLS 1.0/1.1 or no TLS 1.3; A+ needs OCSP stapling on top.
     */
    public static String sslyzeGrade(SslyzeFacts f) {
        boolean expired = f.daysLeft() != null && f.daysLeft() < 0;
        if (f.heartbleed() || f.robot() || f.ccsInjection() || !f.chainTrusted() || f.hostnameMismatch()
                || expired || f.ssl20()) {
            return "F";
        }
        if (f.ssl30() || !f.tls12() && !f.tls13() || (f.keySize() > 0 && f.keySize() < 2048)) {
            return "C";
        }
        if (f.tls10() || f.tls11() || !f.tls13()) {
            return "B";
        }
        return f.ocspStapling() ? "A+" : "A";
    }
}
