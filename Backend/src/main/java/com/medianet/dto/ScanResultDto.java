package com.medianet.dto;

import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResultDto {
    private Long id;
    private Long repoId;
    private String repoUrl;
    private String gitProvider;
    private String branch;
    private String scanMode;
    private String targetDomain;
    private List<Long> clientIds;
    private List<String> clientNames;
    private String status;
    private LocalDateTime startedAt;
    private LocalDateTime finishedAt;
    private String ecosystemsDetected;
    private String toolsExecuted;
    private int cveCount;
    private int secretCount;
}
