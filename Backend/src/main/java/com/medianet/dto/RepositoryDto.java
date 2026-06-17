package com.medianet.dto;

import lombok.*;
import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RepositoryDto {
    private Long id;
    private String repoUrl;
    private String gitProvider;
    private String branch;
    private String scanMode;
    private String targetDomain;
    private List<Long> clientIds;
    private List<String> clientNames;
    private LocalDateTime createdAt;
    private LocalDateTime lastScannedAt;
}
