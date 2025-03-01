package com.restaurant.management.model;

import com.restaurant.management.enums.ShiftType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;

import java.time.LocalDate;
import java.time.LocalTime;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Shift {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long shiftId;
    private String shiftName;
    @Enumerated(EnumType.STRING)
    private ShiftType shiftType;

    private LocalTime startTime;
    private LocalTime endTime;

    // Open Shift
    private Integer available;
    @Column(nullable = false)
    private int maxRegistration;
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    private LocalDate workingDate;

    // Fixed Shitf
    @ManyToOne(optional = true)
    private Employee employee;

    private boolean isActive;

    @PrePersist
    public void setDefaultValues() {
        if(shiftId == null) {
            if (maxRegistration == 0) {
                maxRegistration = 999;
            }
            available = maxRegistration;
            if (workingDate == null) {
                workingDate = LocalDate.now();
            }
        }
    }

    public void registerShift() {
        if (available > 0) available--;
        else throw new IllegalStateException("No available slots to register.");
    }

    public void cancelRegistration() {
        if (available < maxRegistration) available++;
        else throw new IllegalStateException("Slots are full, cannot increase.");
    }
}
