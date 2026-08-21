package com.medianet.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
public class AssistantChatRequest {
    private String message;
    /** Current UI path, e.g. /vulnerabilities or /ssl-analysis/12 */
    private String page;
    private Long scanId;
    private Long serverId;
    private List<AssistantChatTurn> history;
}
