package com.restaurant.management.repository;

import com.restaurant.management.model.Schedule;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface ScheduleRepository extends JpaRepository<Schedule, Long> {
    List<Schedule> findByWorkingDateBetween(LocalDate startDate, LocalDate endDate);
    List<Schedule> findByEmployeeIdAndWorkingDateBetween(Long employeeId,LocalDate startDate, LocalDate endDate);
    List<Schedule> findByEmployeeIdAndWorkingDateBetweenAndStatus(
            Long employeeId,
            LocalDate startDate,
            LocalDate endDate,
            String status
    );
}
