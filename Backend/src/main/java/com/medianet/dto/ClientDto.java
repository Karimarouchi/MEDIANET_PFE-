package com.medianet.dto;

import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientDto {
    private Long id;
    private String name;
    private String company;
    private String email;
    private Long createdById;
    private String createdByLogin;
    private List<Long> employeeIds;
    private List<String> employeeLogins;
    private List<Long> repositoryIds;
    private List<String> repositoryUrls;
    private LocalDateTime createdAt;
}