package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SecretDto {
    private Long id;
    private String ruleId;
    private String description;
    private String file;
    private Integer startLine;
    private Integer endLine;
    private String author;
    private String date;
    private String commit;
    private String maskedMatch;
    private java.util.List<String> detectors;
    private String mlVerdict;
    private Double mlProba;
    private String mlScope;
    private Integer mlPriority;
    private java.util.List<String> mlReasons;
    private String analystVerdict;
}
