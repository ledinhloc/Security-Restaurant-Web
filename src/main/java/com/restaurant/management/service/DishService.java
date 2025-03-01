package com.restaurant.management.service;

import com.restaurant.management.model.Dish;
import com.restaurant.management.model.Inventory;
import com.restaurant.management.model.Recipe;
import com.restaurant.management.repository.DishRepository;
import com.restaurant.management.repository.InventoryRepository;
import com.restaurant.management.repository.RecipeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Service
public class DishService {

    @Autowired
    private DishRepository dishRepository;

    @Autowired
    private StorageService storageService;

    @Autowired
    private RecipeRepository recipeRepository;

    @Autowired
    private InventoryRepository inventoryRepository;

    public List<Dish> getAllDishes() {
        return dishRepository.findAll();
    }

    public Page<Dish> getDishesWithPagination(int page, int size) {
        PageRequest pageRequest = PageRequest.of(page, size);
        return dishRepository.findAll(pageRequest);
    }


    public Dish findById(Long id) {
        return dishRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Dish not found"));
    }

    public Dish saveDish(Dish dish, MultipartFile file) throws IOException {
        if (file != null && !file.isEmpty()) {
            String imageUrl = storageService.uploadImage(file);
            dish.setImage(imageUrl);
            dish.setCost(0D);
        }
        return dishRepository.save(dish);
    }

    public void updateDish(Long id, Dish updatedDish, MultipartFile file) throws IOException {
        Dish existingDish = dishRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Dish not found with id: " + id));

        existingDish.setName(updatedDish.getName());
        existingDish.setDescription(updatedDish.getDescription());
        existingDish.setPrice(updatedDish.getPrice());
        existingDish.setCategory(updatedDish.getCategory());

        if (file != null && !file.isEmpty()) {
            existingDish.setImage(storageService.uploadImage(file));
        }

        dishRepository.save(existingDish);
    }

    public List<Dish> searchDishes(String name) {
        return dishRepository.findByNameContainingIgnoreCase(name);
    }

    public List<Dish> findDishesByCategoryId(Long categoryId) {
        return dishRepository.findAllByCategoryId(categoryId);
    }

    public void deleteDish(Long id) {
        dishRepository.deleteById(id);
    }

    public List<Dish> getDishesByCategory(Long categoryId) {
        return dishRepository.findByCategoryId(categoryId);
    }

    public boolean processDish(Long dishID, int quantity) {
        List<Recipe> recipes = recipeRepository.findRecipeByDishId(dishID);
        for (Recipe recipe : recipes) {
            Inventory inventory = recipe.getInventory();
            int newQuantity = inventory.getQuantity() - recipe.getQuantityRequired()*quantity;

            if(newQuantity <= 0) {
                return false;
            }
        }

        for (Recipe recipe : recipes) {
            Inventory inventory = recipe.getInventory();
            int newQuantity = inventory.getQuantity() - recipe.getQuantityRequired()*quantity;

            inventory.setQuantity(newQuantity);
            inventoryRepository.save(inventory);
        }
        return true;
    }
}
