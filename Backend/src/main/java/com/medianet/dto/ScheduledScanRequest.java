package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ScheduledScanRequest {
    private Long repositoryId;
    private String repositoryName;
    private String repoUrl;
    private String branch;
    private String scanMode;
    private String targetDomain;
    private String dastTargetUrl;
    private String scheduleType;   // "ONCE" | "WEEKLY" | "EVERY_15_DAYS" | "MONTHLY"
    private String startAt;        // ISO-8601 string, e.g. "2026-06-20T08:00:00"
    private String timezone;       // IANA tz, e.g. "Africa/Tunis"
}
