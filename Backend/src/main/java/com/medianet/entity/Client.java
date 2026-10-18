package com.medianet.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "clients")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    private String company;

    @Column(name = "domain_name")
    private String domainName;

    private String email;

    /** Client-imposed delivery date. Product calendar — not CISA dueDate, not lab 15/30/60. */
    @Column(name = "release_deadline")
    private LocalDate releaseDeadline;

    @Column(name = "release_label")
    private String releaseLabel;

    /** Day the project should be warned about the domain certificate, on or before its expiry. */
    @Column(name = "ssl_alert_date")
    private LocalDate sslAlertDate;

    /** Alert date already sent to the inbox, so the same day is not notified twice. */
    @Column(name = "ssl_alert_notified_on")
    private LocalDate sslAlertNotifiedOn;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by")
    private User createdBy;

    @Builder.Default
    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<EmployeeClient> employeeLinks = new LinkedHashSet<>();

    @Builder.Default
    @OneToMany(mappedBy = "client", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<ClientRepository> repositoryLinks = new LinkedHashSet<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
    }
}