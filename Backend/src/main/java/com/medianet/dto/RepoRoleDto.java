package com.medianet.dto;

import com.medianet.entity.ProjectRepoRole;
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
public class RepoRoleDto {
    private Long repositoryId;
    private ProjectRepoRole role;
}
