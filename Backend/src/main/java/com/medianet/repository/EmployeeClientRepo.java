package com.medianet.repository;

import com.medianet.entity.EmployeeClient;
import com.medianet.entity.EmployeeClientId;
import com.medianet.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EmployeeClientRepo extends JpaRepository<EmployeeClient, EmployeeClientId> {
    List<EmployeeClient> findByEmployee_Id(Long employeeId);

    @org.springframework.data.jpa.repository.Query("""
            select ec from EmployeeClient ec
            left join fetch ec.employee
            where ec.client.id = :clientId
            """)
    List<EmployeeClient> findByClient_Id(@org.springframework.data.repository.query.Param("clientId") Long clientId);

    @org.springframework.data.jpa.repository.Query("""
            select distinct emp
            from EmployeeClient ec
            join ec.employee emp
            join ec.client c
            join ClientRepository cr
            where cr.client = c
              and cr.repository.id = :repositoryId
            """)
    List<User> findCollaboratorsByRepositoryId(
            @org.springframework.data.repository.query.Param("repositoryId") Long repositoryId);
}