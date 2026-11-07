package com.medianet.dto;

import lombok.*;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ConfigFindingDto {
    private Long id;
    private String ruleId;
    private List<String> ruleIds;
    private String title;
    private String description;
    private String resolution;
    private String severity;
    private String category;
    private String file;
    private Integer startLine;
    private Integer endLine;
    private String resource;
    private List<String> sources;
    private String referenceUrl;
}
