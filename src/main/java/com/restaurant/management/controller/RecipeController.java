package com.restaurant.management.controller;

import com.restaurant.management.model.Dish;
import com.restaurant.management.model.Inventory;
import com.restaurant.management.model.Recipe;
import com.restaurant.management.service.DishService;
import com.restaurant.management.service.InventoryService;
import com.restaurant.management.service.RecipeService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
@RequestMapping("/recipes")
public class RecipeController {
    @Autowired
    private RecipeService recipeService;

    @Autowired
    private DishService dishService;

    @Autowired
    private InventoryService inventoryService;

    @GetMapping("/edit/{dishId}")
    public String showEditDishForm(@PathVariable Long dishId, Model model) {
        Dish dish = dishService.findById(dishId); // Lấy Dish từ database
        List<Inventory> inventories = inventoryService.getAllInventory(); // Lấy tất cả inventory

        List<Recipe> recipes = dish.getRecipes();
         Map<Long, Integer> inventoryQuantityMap = new HashMap<>();
        if(recipes != null) {
            for (Recipe recipe : recipes) {
                inventoryQuantityMap.put(recipe.getInventory().getInventoryId(), recipe.getQuantityRequired());
            }
        }

        model.addAttribute("dish", dish);
        model.addAttribute("inventories", inventories);
        model.addAttribute("inventoryQuantityMap", inventoryQuantityMap);
        return "pages/recipe/updateRecipe";
    }

    // Xử lý form cập nhật công thức món ăn
    @PostMapping("/update/{dishId}")
    public String updateRecipes(@PathVariable Long dishId,
                                @RequestParam Map<String, String> params,
                                Model model) throws IOException {

        Dish dish = dishService.findById(dishId);
        if (dish == null) {
            // Nếu món ăn không tồn tại, trả về lỗi
            model.addAttribute("error", "Món ăn không tồn tại!");
            return "error";
        }

        //xoa cong thuc cu va chi them nguyen lieu co so luong > 0
        recipeService.updateRecipesForDish(dish, params);
        return "redirect:/recipes/edit/" + dishId;
    }
}
