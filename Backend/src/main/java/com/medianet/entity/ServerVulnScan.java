package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/** One vulnerability analysis of a server (open ports + system packages). The report itself is stored as JSON. */
@Entity
@Table(name = "server_vuln_scans")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServerVulnScan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "server_node_id", nullable = false)
    private ServerNode serverNode;

    /** RUNNING, COMPLETED, PARTIAL (one source failed) or FAILED. */
    @Column(nullable = false, length = 20)
    private String status;

    @Column(name = "started_at", nullable = false)
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;

    @Column(name = "report_json", columnDefinition = "TEXT")
    private String reportJson;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;
}
