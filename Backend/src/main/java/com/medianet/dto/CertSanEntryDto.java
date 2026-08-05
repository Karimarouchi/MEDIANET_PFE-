package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertSanEntryDto {
    /** dns | ip */
    private String type;
    private String value;
    /** MATCH | WILDCARD_MATCH | NO_MATCH | N_A */
    private String matchStatus;
}
