package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SastFindingDto {
    private String checkId;
    private String file;
    private Integer line;
    private String message;
    private String severity;
    private String owaspCategory;
}
