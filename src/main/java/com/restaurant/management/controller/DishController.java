package com.restaurant.management.controller;

import com.restaurant.management.model.Dish;
import com.restaurant.management.service.CategoryService;
import com.restaurant.management.service.DishService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("/dishes")
public class DishController {
    @Autowired
    private DishService dishService;
    @Autowired
    private CategoryService categoryService;

    @GetMapping
    public String listDishes(@RequestParam(defaultValue = "0") int page,
                             @RequestParam(defaultValue = "5") int size,
                             Model model) {
        Page<Dish> dishPage = dishService.getDishesWithPagination(page, size);
        model.addAttribute("dishes", dishPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", dishPage.getTotalPages());
        model.addAttribute("categories", categoryService.getAllCategories());
        return "pages/admin/dish";
    }

    // Thêm món ăn mới
    @PostMapping("/add")
    public String addDish(@ModelAttribute Dish dish,
                          @RequestParam("file") MultipartFile file) {
        try {
            System.out.println(dish);
            dishService.saveDish(dish, file);
            return "redirect:/dishes";
        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/dishes";
        }
    }

    // Cập nhật món ăn
    @PostMapping("/edit/{id}")
    public String updateDish(@PathVariable Long id,
                             @ModelAttribute Dish dish,
                             @RequestParam("file") MultipartFile file) {
        try {
            dishService.updateDish(id, dish, file);
            return "redirect:/dishes";
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }

    @GetMapping("/delete/{id}")
    public String deleteDish(@PathVariable Long id) {
        dishService.deleteDish(id);
        return "redirect:/dishes";
    }

    // Lọc món ăn theo danh mục (nếu cần)
    @GetMapping("/category/{categoryId}")
    public String getDishesByCategory(@PathVariable Long categoryId, Model model) {
        model.addAttribute("dishes", dishService.getDishesByCategory(categoryId));
        return "pages/dish/list";
    }
}

