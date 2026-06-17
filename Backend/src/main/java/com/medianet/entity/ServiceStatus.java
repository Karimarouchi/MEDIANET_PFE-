package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "service_statuses")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ServiceStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "config_snapshot_id", nullable = false)
    private ConfigSnapshot configSnapshot;

    @Column(nullable = false)
    private String serviceName;

    private String state;
    private String subState;
    private String enabledStatus;
}