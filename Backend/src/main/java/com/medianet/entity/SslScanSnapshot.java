package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Full SSL scan result persisted after parse so the on-disk results folder can be deleted.
 * {@code resultJson} stores the complete {@link com.medianet.dto.SslResultDto}
 * (flat fields + tlsProtocols + certificateDetail).
 */
@Entity
@Table(name = "ssl_scan_snapshots", indexes = {
        @Index(name = "idx_ssl_snapshot_scan", columnList = "scan_result_id", unique = true)
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SslScanSnapshot {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "scan_result_id", nullable = false, unique = true)
    private Long scanResultId;

    @Column(length = 255)
    private String domain;

    @Column(length = 16)
    private String grade;

    @Column(name = "combined_grade", length = 16)
    private String combinedGrade;

    @Column(name = "scan_status", length = 32)
    private String scanStatus;

    /** Complete SslResultDto JSON (all UI fields). */
    @Column(name = "result_json", nullable = false, columnDefinition = "TEXT")
    private String resultJson;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        if (createdAt == null) {
            createdAt = now;
        }
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }
}
