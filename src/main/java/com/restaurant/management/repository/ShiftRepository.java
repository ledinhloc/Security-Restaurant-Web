package com.restaurant.management.repository;

import com.restaurant.management.enums.ShiftType;
import com.restaurant.management.model.Shift;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.util.List;

public interface ShiftRepository extends JpaRepository<Shift, Long> {
    List<Shift> findByShiftType(ShiftType shiftType);

    @Query("SELECT s FROM Shift s WHERE s.available > 0 AND s.shiftType = 'OPEN'")
    List<Shift> findAvailableShifts();

    @Query("SELECT s.shiftId FROM Shift s WHERE s.shiftType = :shiftType")
    List<Long> findShiftIdsByShiftType(@Param("shiftType") ShiftType shiftType);
}
