package com.restaurant.management.repository;

import com.restaurant.management.enums.ReservationStatus;
import com.restaurant.management.model.DiningTable;
import com.restaurant.management.model.Reservation;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;

public interface ReservationRepository extends JpaRepository<Reservation, Long> {
    long countByStatus(ReservationStatus status);
    long countByDateToCome(LocalDate date);

    @Query("SELECT t FROM DiningTable t " +
            "WHERE t.id NOT IN (" +
            "   SELECT DISTINCT r.table.id FROM Reservation r " +
            "   WHERE r.dateToCome = :date " +
            "   AND r.timeToCome BETWEEN :startTime AND :endTime " +
            "   AND r.status != 'CANCELLED'" +
            ") AND t.capacity >= :numPeople")
    List<DiningTable> findAvailableTables(
            @Param("date") LocalDate date,
            @Param("startTime") LocalTime startTime,
            @Param("endTime") LocalTime endTime,
            @Param("numPeople") Long numPeople
    );

    @Query("""
        SELECT r 
        FROM Reservation r 
        WHERE r.dateToCome = :today 
          AND r.status = 'PENDING'
          AND r.timeToCome <= :deadlineTime
    """)
    List<Reservation> findExpiredReservations(
            @Param("today") LocalDate today,
            @Param("deadlineTime") LocalTime deadlineTime
    );

    @Query("""
        SELECT r 
        FROM Reservation r 
        WHERE r.dateToCome = :today 
          AND r.status = 'ACCEPTED'
          AND r.timeToCome <= :upTime
    """)
    List<Reservation> findReservationsUpcoming(
            @Param("today") LocalDate today,
            @Param("upTime") LocalTime upTime
    );

    @Query("SELECT r.dateToCome AS date, r.status AS status, COUNT(r) AS count " +
            "FROM Reservation r " +
            "WHERE r.dateToCome BETWEEN :startDate AND :endDate " +
            "GROUP BY r.dateToCome, r.status " +
            "ORDER BY r.dateToCome ASC")
    List<Object[]> countReservationsByStatusAndDate(@Param("startDate") LocalDate startDate,
                                                    @Param("endDate") LocalDate endDate);

}

