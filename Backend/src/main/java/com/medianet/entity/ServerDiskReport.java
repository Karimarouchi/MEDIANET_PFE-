package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/** Last disk measurement of a server: free space and what a cleanup could give back (nothing is removed here). */
@Entity
@Table(name = "server_disk_reports", indexes = @Index(name = "idx_disk_report_server", columnList = "server_node_id", unique = true))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServerDiskReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "server_node_id", nullable = false)
    private Long serverNodeId;

    @Column(name = "measured_at", nullable = false)
    private LocalDateTime measuredAt;

    @Column(name = "disk_total")
    private Long diskTotal;

    @Column(name = "disk_used")
    private Long diskUsed;

    @Column(name = "disk_free")
    private Long diskFree;

    /** Untagged images left by rebuilds ("<none>"), not used by any container: what docker image prune removes. */
    @Column(name = "old_images")
    private Integer oldImages;

    @Column(name = "old_images_bytes")
    private Long oldImagesBytes;

    /** Build cache beyond what is kept to make the next build (and a rollback rebuild) fast. */
    @Column(name = "build_cache_bytes")
    private Long buildCacheBytes;

    /** One line per old image: id | repository | age | size. */
    @Column(name = "details", columnDefinition = "TEXT")
    private String details;

    @Column(name = "alerted_at")
    private LocalDateTime alertedAt;

    @Column(name = "last_cleanup_at")
    private LocalDateTime lastCleanupAt;

    @Column(name = "last_cleanup_freed", length = 60)
    private String lastCleanupFreed;
}
