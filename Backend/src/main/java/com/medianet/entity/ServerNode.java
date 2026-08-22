package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "server_nodes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServerNode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(nullable = false)
    private String host;

    @Builder.Default
    @Column(nullable = false)
    private Integer port = 22;

    @Column(nullable = false)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ServerNodeType nodeType;

    @Column(length = 80)
    private String environment;

    @Column(length = 80)
    private String templateKey;

    @Column(length = 180)
    private String owner;

    @Column(length = 180)
    private String clientName;

    @Column(length = 180)
    private String projectName;

    @Column(length = 1000)
    private String runbookUrl;

    @Column(length = 1200)
    private String tags;

    @Column(length = 2500)
    private String notes;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private SshAuthMethod authMethod;

    @Column(length = 4096)
    private String encryptedPassword;

    @Column(columnDefinition = "TEXT")
    private String encryptedPrivateKey;

    @Column(length = 4096)
    private String encryptedPrivateKeyPassphrase;

    @Column(length = 1200)
    private String description;

    @Column(name = "deploy_path", length = 500)
    private String deployPath;

    @Column(name = "domain", length = 255)
    private String domain;

    @Column(name = "linked_repository_id")
    private Long linkedRepositoryId;

    @Column(name = "deploy_branch", length = 80)
    private String deployBranch;

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "deploy_strategy", length = 40)
    private DeployStrategy deployStrategy = DeployStrategy.DOCKER_COMPOSE;

    @Builder.Default
    @Column(name = "auto_deploy_enabled", nullable = false)
    private Boolean autoDeployEnabled = false;

    @Builder.Default
    @Column(nullable = false)
    private Boolean active = true;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    private LocalDateTime lastScannedAt;

    @Builder.Default
    @OneToMany(mappedBy = "serverNode", cascade = CascadeType.ALL, orphanRemoval = true)
    @OrderBy("collectedAt DESC")
    private List<ConfigSnapshot> snapshots = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.port == null) {
            this.port = 22;
        }
        if (this.active == null) {
            this.active = true;
        }
        if (this.autoDeployEnabled == null) {
            this.autoDeployEnabled = false;
        }
        if (this.deployBranch == null || this.deployBranch.isBlank()) {
            this.deployBranch = "main";
        }
        if (this.deployStrategy == null) {
            this.deployStrategy = DeployStrategy.DOCKER_COMPOSE;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}