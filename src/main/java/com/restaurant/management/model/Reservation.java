package com.restaurant.management.model;

import com.restaurant.management.enums.ReservationStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.time.LocalTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Reservation {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String customerName;
    private String email;

    @Column(name = "time_to_come")
    private LocalTime timeToCome;

    @Column(name = "date_to_come")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private LocalDate dateToCome;

    @Column(name = "number_of_persons")
    private Integer numberOfPersons;

    private String note;

    @Enumerated(EnumType.STRING)
    private ReservationStatus status = ReservationStatus.PENDING;

    @ManyToOne()
    @JoinColumn(name = "table_id", referencedColumnName = "id")
    private DiningTable table;
}
