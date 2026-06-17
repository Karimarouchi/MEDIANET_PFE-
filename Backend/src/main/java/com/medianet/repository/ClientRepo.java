package com.medianet.repository;

import com.medianet.entity.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ClientRepo extends JpaRepository<Client, Long> {

    @Query("""
            select distinct c from Client c
            left join fetch c.employeeLinks ec
            left join fetch c.repositoryLinks cr
            left join fetch cr.repository r
            where c.id = :clientId
            """)
    Optional<Client> findDetailedById(@Param("clientId") Long clientId);

    @Query("""
            select distinct c from Client c
            join c.employeeLinks ec
            where ec.employee.id = :employeeId
            order by c.createdAt desc
            """)
    List<Client> findAllAssignedToEmployee(@Param("employeeId") Long employeeId);

    List<Client> findAllByOrderByCreatedAtDesc();
}