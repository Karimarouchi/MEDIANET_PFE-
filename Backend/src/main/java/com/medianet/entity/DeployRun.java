package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "deploy_runs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeployRun {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "server_node_id", nullable = false)
    private ServerNode serverNode;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_deployment_id")
    private ServerDeployment serverDeployment;

    @Column(name = "commit_sha", length = 40)
    private String commitSha;

    /** Database backup taken right before this deploy (path on the server) and its size in bytes. */
    @Column(name = "backup_file", length = 300)
    private String backupFile;

    @Column(name = "backup_bytes")
    private Long backupBytes;

    /** Who approved or refused a deploy waiting for approval. */
    @Column(name = "decided_by", length = 120)
    private String decidedBy;

    /** Woodpecker pipeline whose green result started this deploy (CI trigger), else null. */
    @Column(name = "pipeline_number")
    private Long pipelineNumber;

    @Column(length = 40)
    private String verdict;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Status status;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private TriggerType triggerType;

    @Column(columnDefinition = "TEXT")
    private String log;

    @Column(nullable = false)
    private LocalDateTime startedAt;

    private LocalDateTime finishedAt;

    public enum Status {
        BLOCKED, RUNNING, SUCCESS, FAILED,
        /** The new version failed its check; the previous one was put back and runs. */
        ROLLED_BACK,
        /** The database backup failed: nothing was deployed. */
        BACKUP_FAILED,
        /** Green pipeline waiting for a "Déployer" click. */
        PENDING_APPROVAL,
        /** Someone clicked "Refuser". */
        REFUSED,
        /** A newer green pipeline replaced this one before it was approved. */
        SUPERSEDED
    }

    public enum TriggerType {
        MANUAL, AUTO, FORCE,
        /** Green Woodpecker pipeline (tests + Vulnix gate) on the deployment branch. */
        CI
    }
}
