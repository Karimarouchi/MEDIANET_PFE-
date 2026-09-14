package com.medianet.service;

import com.medianet.entity.CveRemediationStatus;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Remediation KPIs: mean time open, internal KEV 24h SLA, CISA KEV due date.
 */
final class CveJournalSla {

    static final int SLA_HOURS = 24;
    /** BOD 22-01 default when the CISA catalogue has dateAdded but no dueDate. */
    static final int CISA_DEFAULT_DAYS = 14;
    static final String CISA_SOURCE_CATALOG = "CISA_CATALOG";
    static final String CISA_SOURCE_BOD = "BOD_22_01_DEFAULT";

    record Sample(
            boolean kevListed,
            CveRemediationStatus status,
            LocalDateTime firstSeenAt,
            LocalDateTime closedAt,
            LocalDate cisaDueDate
    ) {
        Sample(boolean kevListed, CveRemediationStatus status,
                LocalDateTime firstSeenAt, LocalDateTime closedAt) {
            this(kevListed, status, firstSeenAt, closedAt, null);
        }
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

    static LocalDate parseIsoDate(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim();
        int t = value.indexOf('T');
        if (t > 0) {
            value = value.substring(0, t);
        }
        try {
            return LocalDate.parse(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    static LocalDate resolveCisaDueDate(String catalogDueDate, String dateAdded) {
        LocalDate fromCatalog = parseIsoDate(catalogDueDate);
        if (fromCatalog != null) {
            return fromCatalog;
        }
        LocalDate added = parseIsoDate(dateAdded);
        return added != null ? added.plusDays(CISA_DEFAULT_DAYS) : null;
    }

    static String resolveCisaDueSource(String catalogDueDate, String dateAdded) {
        if (parseIsoDate(catalogDueDate) != null) {
            return CISA_SOURCE_CATALOG;
        }
        if (parseIsoDate(dateAdded) != null) {
            return CISA_SOURCE_BOD;
        }
        return null;
    }

    static boolean isCisaOverdue(boolean kevListed, CveRemediationStatus status,
            LocalDate dueDate, LocalDate today) {
        if (!kevListed || !isStillOpen(status) || dueDate == null || today == null) {
            return false;
        }
        return today.isAfter(dueDate);
    }

    static Integer daysUntilCisaDue(LocalDate dueDate, LocalDate today) {
        if (dueDate == null || today == null) {
            return null;
        }
        return (int) (dueDate.toEpochDay() - today.toEpochDay());
    }

    static Map<String, Object> compute(Collection<Sample> rows, LocalDateTime now) {
        double openDaysSum = 0;
        int openWithAge = 0;
        int kevTotal = 0;
        int kevOpen = 0;
        int kevOverdue = 0;
        int kevCisaOverdue = 0;
        int kevClosedWithTiming = 0;
        int kevFixedWithin24h = 0;
        LocalDate today = now != null ? now.toLocalDate() : null;

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
                    if (isCisaOverdue(true, row.status(), row.cisaDueDate(), today)) {
                        kevCisaOverdue++;
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
        sla.put("cisaDefaultDays", CISA_DEFAULT_DAYS);
        sla.put("meanDaysOpen", openWithAge == 0
                ? null
                : Math.round((openDaysSum / openWithAge) * 10.0) / 10.0);
        sla.put("openWithAgeCount", openWithAge);
        sla.put("kevTotal", kevTotal);
        sla.put("kevOpenCount", kevOpen);
        sla.put("kevOverdueCount", kevOverdue);
        sla.put("kevCisaOverdueCount", kevCisaOverdue);
        sla.put("kevClosedWithTimingCount", kevClosedWithTiming);
        sla.put("kevFixedWithin24hCount", kevFixedWithin24h);
        sla.put("kevFixedWithin24hPercent", kevClosedWithTiming == 0
                ? null
                : Math.round(100.0 * kevFixedWithin24h / kevClosedWithTiming));
        return sla;
    }
}
