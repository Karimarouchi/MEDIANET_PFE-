package com.medianet.repository;

import com.medianet.entity.EmployeeClient;
import com.medianet.entity.EmployeeClientId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface EmployeeClientRepo extends JpaRepository<EmployeeClient, EmployeeClientId> {
    List<EmployeeClient> findByEmployee_Id(Long employeeId);

    List<EmployeeClient> findByClient_Id(Long clientId);
}