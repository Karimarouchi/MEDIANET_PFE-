package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "hardening_findings")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class HardeningFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "config_snapshot_id", nullable = false)
    private ConfigSnapshot configSnapshot;

    @Column(nullable = false)
    private String category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingSeverity severity;

    @Column(nullable = false)
    private String title;

    @Column(length = 2000)
    private String description;

    @Column(length = 2000)
    private String recommendation;

    @Column(length = 1200)
    private String detectedValue;
}