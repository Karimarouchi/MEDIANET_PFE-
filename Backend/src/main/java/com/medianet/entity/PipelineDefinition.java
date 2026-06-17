package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "pipeline_definitions")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PipelineDefinition {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 180)
    private String name;

    @Column(length = 2000)
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id")
    private Repository repository;

    @Column(length = 800)
    private String repoUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    @Builder.Default
    private AuthProvider sourceProvider = AuthProvider.GITHUB;

    @Column(length = 160)
    private String branch;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "runner_server_id")
    private ServerNode runnerServer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "staging_server_id")
    private ServerNode stagingServer;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "production_server_id")
    private ServerNode productionServer;

    @Column(length = 1000)
    private String workspacePath;

    @Column(columnDefinition = "TEXT")
    private String buildCommand;

    @Column(columnDefinition = "TEXT")
    private String testCommand;

    @Column(columnDefinition = "TEXT")
    private String dockerBuildCommand;

    @Column(columnDefinition = "TEXT")
    private String containerScanCommand;

    @Column(columnDefinition = "TEXT")
    private String stagingDeployCommand;

    @Column(columnDefinition = "TEXT")
    private String dastCommand;

    @Column(columnDefinition = "TEXT")
    private String productionDeployCommand;

    @Builder.Default
    @Column(nullable = false)
    private Boolean approvalRequired = false;

    @Builder.Default
    @Column(nullable = false)
    private Boolean failOnCritical = true;

    @Builder.Default
    @Column(nullable = false)
    private Boolean failOnSecrets = true;

    @Builder.Default
    @Column(nullable = false)
    private Boolean active = true;

    private LocalDateTime lastRunAt;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by_id")
    private User createdBy;

    @Builder.Default
    @OneToMany(mappedBy = "pipeline", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("startedAt DESC")
    private List<PipelineRun> runs = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (approvalRequired == null) {
            approvalRequired = false;
        }
        if (failOnCritical == null) {
            failOnCritical = true;
        }
        if (failOnSecrets == null) {
            failOnSecrets = true;
        }
        if (active == null) {
            active = true;
        }
        if (sourceProvider == null) {
            sourceProvider = AuthProvider.GITHUB;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}