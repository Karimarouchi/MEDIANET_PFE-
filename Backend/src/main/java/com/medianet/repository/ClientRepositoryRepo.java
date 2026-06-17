package com.medianet.repository;

import com.medianet.entity.ClientRepository;
import com.medianet.entity.ClientRepositoryId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ClientRepositoryRepo extends JpaRepository<ClientRepository, ClientRepositoryId> {
    List<ClientRepository> findByClient_Id(Long clientId);

    List<ClientRepository> findByRepository_Id(Long repositoryId);
}