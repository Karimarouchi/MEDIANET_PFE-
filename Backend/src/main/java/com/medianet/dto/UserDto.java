package com.medianet.dto;

import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserDto {
    private Long id;
    private String login;
    private String name;
    private String avatarUrl;
    private String email;
    private String role;
    private String systemRole;
    private Long accessRoleId;
    private String accessRoleKey;
    private String primaryProvider;
    private boolean hasGithubLinked;
    private boolean hasGitlabLinked;
    private String gitlabUrl;
    private boolean hasLocalPassword;
    private boolean suspended;
    private List<String> permissions;
    private LocalDateTime createdAt;
    private String aiProvider;       // "GEMINI", "CLAUDE", "OPENAI" or null
    private String aiModel;          // model name or null
    private boolean hasCustomAiKey;  // true if user has set their own key (key itself never sent)
}
