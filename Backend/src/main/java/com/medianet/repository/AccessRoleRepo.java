package com.medianet.repository;

import com.medianet.entity.AccessRole;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AccessRoleRepo extends JpaRepository<AccessRole, Long> {
    Optional<AccessRole> findByRoleKeyIgnoreCase(String roleKey);

    boolean existsByRoleKeyIgnoreCase(String roleKey);

    List<AccessRole> findAllByOrderBySystemRoleDescNameAsc();
}