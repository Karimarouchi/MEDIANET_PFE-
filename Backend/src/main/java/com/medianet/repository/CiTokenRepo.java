package com.medianet.repository;

import com.medianet.entity.CiToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface CiTokenRepo extends JpaRepository<CiToken, Long> {

    @Query("""
            select distinct t from CiToken t
            join fetch t.client
            left join fetch t.repositories
            where t.tokenHash = :tokenHash
            """)
    Optional<CiToken> findDetailedByTokenHash(@Param("tokenHash") String tokenHash);

    @Query("""
            select distinct t from CiToken t
            join fetch t.client
            left join fetch t.repositories
            where t.client.id = :clientId
            """)
    List<CiToken> findDetailedByClientId(@Param("clientId") Long clientId);

    @Query("""
            select distinct t from CiToken t
            join fetch t.client
            left join fetch t.repositories
            where t.id = :id
            """)
    Optional<CiToken> findDetailedById(@Param("id") Long id);
}
