package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "server_deployments")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServerDeployment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "server_node_id", nullable = false)
    private ServerNode serverNode;

    @Column(nullable = false, length = 180)
    private String name;

    @Column(name = "deploy_path", length = 500)
    private String deployPath;

    @Column(length = 255)
    private String domain;

    @Column(name = "linked_repository_id")
    private Long linkedRepositoryId;

    @Builder.Default
    @Column(name = "deploy_branch", length = 80)
    private String deployBranch = "main";

    @Builder.Default
    @Enumerated(EnumType.STRING)
    @Column(name = "deploy_strategy", length = 40)
    private DeployStrategy deployStrategy = DeployStrategy.DOCKER_COMPOSE;

    @Builder.Default
    @Column(name = "auto_deploy_enabled", nullable = false)
    private Boolean autoDeployEnabled = false;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        this.createdAt = now;
        this.updatedAt = now;
        if (this.deployBranch == null || this.deployBranch.isBlank()) {
            this.deployBranch = "main";
        }
        if (this.deployStrategy == null) {
            this.deployStrategy = DeployStrategy.DOCKER_COMPOSE;
        }
        if (this.autoDeployEnabled == null) {
            this.autoDeployEnabled = false;
        }
        if (this.name == null || this.name.isBlank()) {
            this.name = "Déploiement";
        }
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
