package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

/** Link between a project and a server: a project can run on several servers, a server can serve several projects. */
@Entity
@Table(name = "client_servers", uniqueConstraints = @UniqueConstraint(columnNames = { "client_id", "server_node_id" }))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ClientServer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "server_node_id", nullable = false)
    private ServerNode serverNode;
}
