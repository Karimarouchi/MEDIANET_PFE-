package com.medianet.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class GitRepoDto {
    private String name;
    private String fullName;
    private String description;
    private String language;
    private boolean isPrivate;
    private int stars;
    private String htmlUrl;
    private String updatedAt;
    private String provider;
}