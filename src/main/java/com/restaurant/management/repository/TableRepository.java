package com.restaurant.management.repository;

import com.restaurant.management.model.DiningTable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TableRepository extends JpaRepository<DiningTable, Long> {
    Optional<DiningTable> findByTableNumber(int tableNumber);
    @Query("SELECT t.tableNumber FROM DiningTable t WHERE t.id = :tableId")
    Long getTableNumberById(@Param("tableId") Long tableId);
}

