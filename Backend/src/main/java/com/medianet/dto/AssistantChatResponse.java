package com.medianet.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssistantChatResponse {
    private String reply;
    private String contextLabel;
    @Builder.Default
    private List<AssistantLinkDto> links = new ArrayList<>();
    private boolean usedAi;
}
