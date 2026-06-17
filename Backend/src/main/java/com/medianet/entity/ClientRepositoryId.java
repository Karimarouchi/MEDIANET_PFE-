package com.medianet.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class ClientRepositoryId implements Serializable {

    @Column(name = "client_id")
    private Long clientId;

    @Column(name = "repository_id")
    private Long repositoryId;
}