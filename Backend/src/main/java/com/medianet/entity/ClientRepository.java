package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "client_repositories")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientRepository {

    @EmbeddedId
    private ClientRepositoryId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("clientId")
    @JoinColumn(name = "client_id")
    private Client client;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("repositoryId")
    @JoinColumn(name = "repository_id")
    private Repository repository;

    /** Null on rows created before roles existed: callers treat that as OTHER. */
    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ProjectRepoRole role;
}