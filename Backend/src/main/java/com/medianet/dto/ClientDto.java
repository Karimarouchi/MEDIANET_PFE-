package com.medianet.dto;

import lombok.*;

import java.time.LocalDate;
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
    private String domainName;
    private String email;
    private LocalDate releaseDeadline;
    private String releaseLabel;
    /** Day chosen to receive the SSL expiry alert. Null when no alert is set. */
    private LocalDate sslAlertDate;
    /** Expiry of the certificate seen by the latest SSL scan of the domain; filled only when an alert is set. */
    private LocalDate sslCertExpiresOn;
    private Long createdById;
    private String createdByLogin;
    private List<Long> employeeIds;
    private List<String> employeeLogins;
    private List<Long> repositoryIds;
    private List<String> repositoryUrls;
    /** Role of each repository inside this project. Missing entries mean OTHER. */
    private List<RepoRoleDto> repositoryRoles;
    private LocalDateTime createdAt;
}