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
    private boolean hasLocalPassword;
    private boolean suspended;
    private List<String> permissions;
    private LocalDateTime createdAt;
}