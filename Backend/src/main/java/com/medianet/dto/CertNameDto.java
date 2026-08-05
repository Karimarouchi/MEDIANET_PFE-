package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class CertNameDto {
    private String commonName;
    private String organization;
    private String country;
    private String countryName;
    private String rfc4514;
}
