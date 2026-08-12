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

    List<ClientRepository> findByRepository_Id(Long repositoryId);
}