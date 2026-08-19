package com.medianet.repository;

import com.medianet.entity.ClientRepository;
import com.medianet.entity.ClientRepositoryId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ClientRepositoryRepo extends JpaRepository<ClientRepository, ClientRepositoryId> {
    @org.springframework.data.jpa.repository.Query("""
            select cr from ClientRepository cr
            left join fetch cr.repository
            where cr.client.id = :clientId
            """)
    List<ClientRepository> findByClient_Id(@org.springframework.data.repository.query.Param("clientId") Long clientId);

    @org.springframework.data.jpa.repository.Query("""
            select cr from ClientRepository cr
            left join fetch cr.client
            left join fetch cr.repository
            where cr.repository.id = :repositoryId
            """)
    List<ClientRepository> findByRepository_Id(@org.springframework.data.repository.query.Param("repositoryId") Long repositoryId);

    @org.springframework.data.jpa.repository.Query("""
            select cr from ClientRepository cr
            left join fetch cr.client
            left join fetch cr.repository
            """)
    List<ClientRepository> findAllWithClientAndRepository();
}