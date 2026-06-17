package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "port_exposures")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PortExposure {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "config_snapshot_id", nullable = false)
    private ConfigSnapshot configSnapshot;

    @Column(nullable = false)
    private Integer portNumber;

    @Column(nullable = false)
    private String protocol;

    private String bindAddress;
    private String processName;
    private String serviceName;
    private String exposureLevel;
    private String state;
}