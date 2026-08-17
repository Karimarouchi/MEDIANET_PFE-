package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan_results", indexes = {
        @Index(name = "idx_scan_repo_sha", columnList = "repository_id, commit_sha")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status;

    /** Git commit scanned by CI (lowercase hex). Null for UI / scheduled scans. */
    @Column(name = "commit_sha", length = 40)
    private String commitSha;

    private LocalDateTime startedAt;
    private LocalDateTime finishedAt;

    @Column(nullable = false)
    private String resultsDir;

    @Column(columnDefinition = "TEXT")
    private String ecosystemsDetected;

    @Column(columnDefinition = "TEXT")
    private String toolsExecuted;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "repository_id", nullable = false)
    private Repository repository;

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<CveEntry> cveEntries = new ArrayList<>();

    @OneToMany(mappedBy = "scanResult", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<SecretFinding> secretFindings = new ArrayList<>();

    public enum ScanStatus {
        PENDING, RUNNING, COMPLETED, FAILED
    }
}
