package com.medianet.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.*;

import java.io.Serializable;

@Embeddable
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class EmployeeClientId implements Serializable {

    @Column(name = "employee_id")
    private Long employeeId;

    @Column(name = "client_id")
    private Long clientId;
}