package com.medianet.repository;

import com.medianet.entity.Repository;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface RepositoryRepo extends JpaRepository<Repository, Long> {
    Optional<Repository> findByRepoUrl(String repoUrl);

    Optional<Repository> findByRepoUrlAndOwnerLogin(String repoUrl, String ownerLogin);

    List<Repository> findByOwnerLoginOrderByCreatedAtDesc(String ownerLogin);

    @Query("""
            select distinct r from Repository r
            left join r.clientLinks cr
            left join cr.client c
            left join c.employeeLinks ec
            where r.ownerUser.id = :userId or ec.employee.id = :userId
            order by r.createdAt desc
            """)
    List<Repository> findVisibleToEmployee(@Param("userId") Long userId);

    @Query("""
            select (count(r) > 0) from Repository r
            where r.id = :repoId
                and (
                        r.ownerUser.id = :userId
                        or exists (
                        select cr from ClientRepository cr
                        join cr.client c
                        join c.employeeLinks ec
                        where cr.repository = r and ec.employee.id = :userId
                )
                )
            """)
    boolean canEmployeeAccess(@Param("repoId") Long repoId, @Param("userId") Long userId);
}
