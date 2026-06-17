package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "config_snapshots")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConfigSnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_node_id", nullable = false)
    private ServerNode serverNode;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ConfigSnapshotStatus status;

    @Column(nullable = false, updatable = false)
    private LocalDateTime collectedAt;

    private String hostname;
    private String osName;
    private String kernelVersion;
    private String cpuSummary;
    private String memorySummary;
    private String diskSummary;
    private String firewallStatus;
    private String sshRootLogin;
    private String dockerSummary;
    private String certificateSummary;

    @Column(length = 1500)
    private String summary;

    @Column(columnDefinition = "TEXT")
    private String journalExcerpt;

    private Integer criticalCount;
    private Integer warningCount;
    private Integer infoCount;

    @Column(columnDefinition = "TEXT")
    private String driftSummary;

    @Column(columnDefinition = "TEXT")
    private String rawHostname;

    @Column(columnDefinition = "TEXT")
    private String rawOsRelease;

    @Column(columnDefinition = "TEXT")
    private String rawUname;

    @Column(columnDefinition = "TEXT")
    private String rawCpu;

    @Column(columnDefinition = "TEXT")
    private String rawMemory;

    @Column(columnDefinition = "TEXT")
    private String rawDisk;

    @Column(columnDefinition = "TEXT")
    private String rawPorts;

    @Column(columnDefinition = "TEXT")
    private String rawServices;

    @Column(columnDefinition = "TEXT")
    private String rawFirewall;

    @Column(columnDefinition = "TEXT")
    private String rawSshd;

    @Column(columnDefinition = "TEXT")
    private String rawNginx;

    @Column(columnDefinition = "TEXT")
    private String rawDocker;

    @Column(columnDefinition = "TEXT")
    private String rawJournal;

    @Builder.Default
    @OneToMany(mappedBy = "configSnapshot", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("portNumber ASC")
    private List<PortExposure> portExposures = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "configSnapshot", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("serviceName ASC")
    private List<ServiceStatus> services = new ArrayList<>();

    @Builder.Default
    @OneToMany(mappedBy = "configSnapshot", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<HardeningFinding> findings = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        this.collectedAt = LocalDateTime.now();
        if (this.criticalCount == null) {
            this.criticalCount = 0;
        }
        if (this.warningCount == null) {
            this.warningCount = 0;
        }
        if (this.infoCount == null) {
            this.infoCount = 0;
        }
    }
}