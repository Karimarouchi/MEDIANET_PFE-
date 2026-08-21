package com.medianet.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class AssistantChatTurn {
    /** "user" or "assistant" */
    private String role;
    private String content;
}
