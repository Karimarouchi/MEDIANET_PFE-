package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "secret_findings")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecretFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String ruleId;
    private String description;
    private String file;
    private Integer startLine;
    private Integer endLine;

    @Column(columnDefinition = "TEXT")
    private String match;

    private String author;
    private String email;
    private String date;
    private String commit;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_result_id", nullable = false)
    private ScanResult scanResult;
}
