package com.medianet.repository;

import com.medianet.entity.AppNotification;
import com.medianet.entity.NotificationType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface AppNotificationRepo extends JpaRepository<AppNotification, Long> {

    List<AppNotification> findByRecipient_IdOrderByCreatedAtDesc(Long recipientId);

    long countByRecipient_IdAndReadFalse(Long recipientId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("UPDATE AppNotification n SET n.read = true WHERE n.recipient.id = :userId AND n.read = false")
    int markAllReadForUser(@Param("userId") Long userId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM AppNotification n WHERE n.recipient.id = :userId")
    int deleteAllForUser(@Param("userId") Long userId);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            DELETE FROM AppNotification n
            WHERE n.relatedRequestId = :requestId
              AND n.type = :type
            """)
    int deleteByRelatedRequestIdAndType(
            @Param("requestId") Long requestId,
            @Param("type") NotificationType type);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            DELETE FROM AppNotification n
            WHERE n.recipient.id = :userId
              AND n.type IN :types
              AND n.createdAt < :before
            """)
    int deleteExpiredOutcomesForUser(
            @Param("userId") Long userId,
            @Param("types") List<NotificationType> types,
            @Param("before") LocalDateTime before);
}
