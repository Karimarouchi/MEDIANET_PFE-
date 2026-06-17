package com.medianet.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessRoleDto {
    private Long id;
    private String roleKey;
    private String name;
    private String description;
    private String baseRole;
    private boolean systemRole;
    private List<String> permissions;
}