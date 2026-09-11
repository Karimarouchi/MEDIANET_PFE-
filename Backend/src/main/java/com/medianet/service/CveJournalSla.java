package com.medianet.service;

import com.medianet.entity.CveRemediationStatus;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Remediation KPIs for the CVE journal: mean time open, KEV 24h SLA, overdue KEV.
 */
final class CveJournalSla {

    static final int SLA_HOURS = 24;

    record Sample(
            boolean kevListed,
            CveRemediationStatus status,
            LocalDateTime firstSeenAt,
            LocalDateTime closedAt
    ) {
    }

    private CveJournalSla() {
    }

    static boolean isStillOpen(CveRemediationStatus status) {
        if (status == null) {
            return true;
        }
        return switch (status) {
            case FIXED, CORRIGE, FALSE_POSITIVE, ACCEPTED_RISK, ACCEPTE_RISQUE -> false;
            default -> true;
        };
    }

    static boolean isRemediated(CveRemediationStatus status) {
        return status == CveRemediationStatus.FIXED || status == CveRemediationStatus.CORRIGE;
    }

    static Double daysBetween(LocalDateTime from, LocalDateTime to) {
        if (from == null || to == null || to.isBefore(from)) {
            return null;
        }
        double days = Duration.between(from, to).toMinutes() / (60.0 * 24.0);
        return Math.round(days * 10.0) / 10.0;
    }

    static Double daysOpen(CveRemediationStatus status, LocalDateTime firstSeenAt,
            LocalDateTime closedAt, LocalDateTime now) {
        if (firstSeenAt == null) {
            return null;
        }
        LocalDateTime end = isStillOpen(status) ? now : closedAt;
        return daysBetween(firstSeenAt, end);
    }

    static boolean isKevOverdue(boolean kevListed, CveRemediationStatus status,
            LocalDateTime firstSeenAt, LocalDateTime now) {
        if (!kevListed || !isStillOpen(status) || firstSeenAt == null || now == null) {
            return false;
        }
        return Duration.between(firstSeenAt, now).compareTo(Duration.ofHours(SLA_HOURS)) >= 0;
    }

    static Map<String, Object> compute(Collection<Sample> rows, LocalDateTime now) {
        double openDaysSum = 0;
        int openWithAge = 0;
        int kevTotal = 0;
        int kevOpen = 0;
        int kevOverdue = 0;
        int kevClosedWithTiming = 0;
        int kevFixedWithin24h = 0;

        for (Sample row : rows == null ? java.util.List.<Sample>of() : rows) {
            if (row.kevListed()) {
                kevTotal++;
            }
            if (isStillOpen(row.status())) {
                if (row.kevListed()) {
                    kevOpen++;
                    if (isKevOverdue(true, row.status(), row.firstSeenAt(), now)) {
                        kevOverdue++;
                    }
                }
                Double days = daysOpen(row.status(), row.firstSeenAt(), row.closedAt(), now);
                if (days != null) {
                    openDaysSum += days;
                    openWithAge++;
                }
            } else if (row.kevListed() && isRemediated(row.status())
                    && row.firstSeenAt() != null && row.closedAt() != null) {
                kevClosedWithTiming++;
                Duration age = Duration.between(row.firstSeenAt(), row.closedAt());
                if (!age.isNegative() && age.compareTo(Duration.ofHours(SLA_HOURS)) <= 0) {
                    kevFixedWithin24h++;
                }
            }
        }

        Map<String, Object> sla = new LinkedHashMap<>();
        sla.put("slaHours", SLA_HOURS);
        sla.put("meanDaysOpen", openWithAge == 0
                ? null
                : Math.round((openDaysSum / openWithAge) * 10.0) / 10.0);
        sla.put("openWithAgeCount", openWithAge);
        sla.put("kevTotal", kevTotal);
        sla.put("kevOpenCount", kevOpen);
        sla.put("kevOverdueCount", kevOverdue);
        sla.put("kevClosedWithTimingCount", kevClosedWithTiming);
        sla.put("kevFixedWithin24hCount", kevFixedWithin24h);
        sla.put("kevFixedWithin24hPercent", kevClosedWithTiming == 0
                ? null
                : Math.round(100.0 * kevFixedWithin24h / kevClosedWithTiming));
        return sla;
    }
}
