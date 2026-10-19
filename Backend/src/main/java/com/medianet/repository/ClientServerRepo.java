package com.medianet.repository;

import com.medianet.entity.ClientServer;
import com.medianet.entity.ServerNode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface ClientServerRepo extends JpaRepository<ClientServer, Long> {

    @Query("select cs.serverNode from ClientServer cs where cs.clientId = :clientId order by cs.serverNode.name")
    List<ServerNode> findServersByClientId(@Param("clientId") Long clientId);

    boolean existsByClientIdAndServerNode_Id(Long clientId, Long serverNodeId);

    void deleteByClientId(Long clientId);

    void deleteByClientIdAndServerNode_Id(Long clientId, Long serverNodeId);

    long countByServerNode_Id(Long serverNodeId);
}
