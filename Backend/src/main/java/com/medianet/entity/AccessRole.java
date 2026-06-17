package com.medianet.entity;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "access_roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccessRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String roleKey;

    @Column(nullable = false)
    private String name;

    @Column(length = 600)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole baseRole;

    @Column(nullable = false)
    @Builder.Default
    private Boolean systemRole = false;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "access_role_permissions", joinColumns = @JoinColumn(name = "access_role_id"))
    @Column(name = "permission_name", nullable = false)
    @Enumerated(EnumType.STRING)
    @Builder.Default
    private Set<AccessPermission> permissions = new LinkedHashSet<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (systemRole == null) {
            systemRole = false;
        }
        if (permissions == null) {
            permissions = new LinkedHashSet<>();
        }
    }
}