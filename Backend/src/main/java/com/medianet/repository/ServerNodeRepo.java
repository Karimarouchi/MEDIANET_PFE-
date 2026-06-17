package com.medianet.repository;

import com.medianet.entity.ServerNode;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ServerNodeRepo extends JpaRepository<ServerNode, Long> {
    boolean existsByNameIgnoreCase(String name);

    List<ServerNode> findAllByOrderByNodeTypeAscNameAsc();
}