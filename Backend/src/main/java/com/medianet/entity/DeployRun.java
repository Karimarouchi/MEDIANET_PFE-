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

    @Column(name = "commit_sha", length = 40)
    private String commitSha;

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
        BLOCKED, RUNNING, SUCCESS, FAILED
    }

    public enum TriggerType {
        MANUAL, AUTO, FORCE
    }
}
