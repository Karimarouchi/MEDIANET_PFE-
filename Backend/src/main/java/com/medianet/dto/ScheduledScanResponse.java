package com.medianet.dto;

import lombok.*;
import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScheduledScanResponse {
    private Long id;
    private Long repositoryId;
    private String repositoryName;
    private String repoUrl;
    private String branch;
    private String scanMode;
    private String targetDomain;
    private String dastTargetUrl;
    private String scheduleType;
    private Instant startAt;
    private Instant nextRunAt;
    private Instant lastRunAt;
    private String timezone;
    private String status;
    private boolean enabled;
    private int runCount;
    private Long lastScanId;
    private String lastError;
    private Instant createdAt;
    private Instant updatedAt;
}
