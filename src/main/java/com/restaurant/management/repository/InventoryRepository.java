package com.restaurant.management.repository;

import com.restaurant.management.model.Inventory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface InventoryRepository extends JpaRepository<Inventory, Long> {
    @Query("SELECT i.itemName, i.quantity FROM Inventory i")
    List<Object[]> getInventoryData();

}
