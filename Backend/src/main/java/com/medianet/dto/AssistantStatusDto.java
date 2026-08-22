package com.medianet.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssistantStatusDto {
    /** True si le provider chatbot répond encore (clé OK, tokens restants). */
    private boolean available;
    private String provider;
    private String detail;
}
