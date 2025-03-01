package com.restaurant.management.model;

import com.restaurant.management.enums.SalaryStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Salary {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Employee employee;

    private LocalDate payDate;

    private Double totalHoursWorked;
    private Double hourlyRate;
    private Double totalSalary;
    private Double bonus;

    @Enumerated(EnumType.STRING)
    private SalaryStatus status;
}

