package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "scheduled_scans")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScheduledScan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long repositoryId;

    @Column(nullable = false)
    private String repositoryName;

    @Column(nullable = false)
    private String repoUrl;

    private String branch;

    @Column(nullable = false)
    private String scanMode;

    private String targetDomain;
    private String dastTargetUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScheduleType scheduleType;

    /** User-chosen first run date/time, stored in UTC */
    @Column(nullable = false)
    private Instant startAt;

    /** Next scheduled run, stored in UTC */
    @Column(nullable = false)
    private Instant nextRunAt;

    /** Last actual run time */
    private Instant lastRunAt;

    /** IANA timezone name sent by the frontend, e.g. "Africa/Tunis" */
    @Column(nullable = false)
    @Builder.Default
    private String timezone = "UTC";

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    @Builder.Default
    private ScheduledScanStatus status = ScheduledScanStatus.ACTIVE;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private int runCount = 0;

    /** scan_result id of the last executed scan */
    private Long lastScanId;

    @Column(length = 1000)
    private String lastError;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = Instant.now();
    }
}
