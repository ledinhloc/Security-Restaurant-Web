package com.restaurant.management.repository;

import com.restaurant.management.model.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {
    public Employee findByEmail(String email);
    @Query("SELECT e.id FROM Employee e WHERE e.position = :position")
    List<Long> findEmployeeIdsByPosition(@Param("position") String position);

    public Employee findByPhone(String phone);
}
