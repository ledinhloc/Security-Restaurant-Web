package com.restaurant.management.repository;

import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.model.OrderItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface OrderItemRepository extends JpaRepository<OrderItem, Long> {

    @Query("SELECT o FROM OrderItem o WHERE"+
            " (:keyword IS NULL OR LOWER(o.dish.name) LIKE %:keyword% OR CAST(o.order.id AS STRING ) LIKE %:keyword%) AND "+
            "(:status IS NULL OR o.orderStatus = :status)")
    List<OrderItem> findByKeywordAndStatus(@Param("keyword") String keyword, @Param("status") OrderStatus status);

    //tinh số lượng dish 
    @Query("SELECT oi.dish.name AS dishName, SUM(oi.quantity) AS totalQuantity"+
            " FROM OrderItem oi join oi.order o"+
            " WHERE oi.orderStatus = :status "+
            " AND o.orderDate BETWEEN :startDate AND :endDate " +
            " GROUP BY oi.dish.name"+
            " ORDER BY totalQuantity DESC")
    List<Object[]> getDishSalesStats(@Param("status") OrderStatus status,
                                     @Param("startDate") LocalDateTime startDate,
                                     @Param("endDate") LocalDateTime endDate);

    @Query("SELECT o.orderDate AS orderDate, " +
            "       SUM(oi.cost * oi.quantity) AS totalCost, " +
            "       (SUM(oi.price * oi.quantity) - SUM(oi.cost * oi.quantity)) AS totalProfit " +
            "FROM Order o " +
            "JOIN OrderItem oi ON o.id = oi.order.id " +
            "WHERE o.orderDate BETWEEN :startDate AND :endDate " +
            "GROUP BY o.orderDate " +
            "ORDER BY o.orderDate ASC")
    List<Object[]> getProfitAndRevenueByDateRange(@Param("startDate") LocalDateTime startDate,
                                                @Param("endDate") LocalDateTime endDate);

    //thong ke mon an, so luong, gia tien giam dan theo trang thai
    @Query("SELECT oi.dish.name AS dishName, SUM(oi.quantity) AS totalQuantity, SUM(oi.quantity * oi.price) AS totalSales " +
            "FROM OrderItem oi " +
            "JOIN oi.order o " +
            "WHERE oi.orderStatus = :status " +
            "AND o.orderDate BETWEEN :startDate AND :endDate " +
            "GROUP BY oi.dish.name " +
            "ORDER BY totalSales DESC   "+
            "LIMIT 5"
    )
    List<Object[]> findDishSalesStatsBetweenDates(
            @Param("status") OrderStatus status,
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate
    );
}
