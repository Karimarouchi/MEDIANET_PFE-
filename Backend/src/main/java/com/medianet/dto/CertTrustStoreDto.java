package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertTrustStoreDto {
    /** Mozilla | Windows | Apple | Android | Java */
    private String platform;
    /** TRUSTED | NOT_TRUSTED | NOT_TESTED */
    private String status;
    private String storeVersion;
    private String validationError;
}
