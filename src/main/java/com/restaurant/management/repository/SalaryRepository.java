package com.restaurant.management.repository;

import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Salary;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

@Repository
public interface SalaryRepository extends JpaRepository<Salary, Long> {
    List<Salary> findByEmployeeAndPayDateBetween(Employee employee, LocalDate startDate, LocalDate endDate);
    Salary findByEmployeeIdAndPayDateBetween(Long employeeId, LocalDate startDate, LocalDate endDate);
    List<Salary> findByPayDateBetween(LocalDate startDate, LocalDate endDate);
}

