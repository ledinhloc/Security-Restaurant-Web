package com.restaurant.management.repository;

import com.restaurant.management.model.Dish;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DishRepository extends JpaRepository<Dish, Long> {
    List<Dish> findByCategoryId(Long categoryId);
    List<Dish> findByNameContainingIgnoreCase(String query);
    List<Dish> findAllByCategoryId(Long categoryId);
}
