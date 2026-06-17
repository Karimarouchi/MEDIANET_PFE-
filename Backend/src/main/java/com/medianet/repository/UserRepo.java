package com.medianet.repository;

import com.medianet.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepo extends JpaRepository<User, Long> {
    Optional<User> findByLogin(String login);

    Optional<User> findByEmailIgnoreCase(String email);

    List<User> findAllByAccessRole_Id(Long accessRoleId);

    boolean existsByAccessRole_Id(Long accessRoleId);
}