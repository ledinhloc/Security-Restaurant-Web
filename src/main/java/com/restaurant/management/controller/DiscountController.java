package com.restaurant.management.controller;

import com.restaurant.management.model.Discount;
import com.restaurant.management.service.DiscountService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/discounts")
public class DiscountController {
    @Autowired
    private final DiscountService discountService;

    @GetMapping
    public String listDiscounts(Model model) {
        model.addAttribute("discount", new Discount());
        model.addAttribute("discounts", discountService.getAllDiscounts());
        return "pages/discount/discount-list";
    }

    @GetMapping("/create")
    public String createDiscountForm(Model model) {
        model.addAttribute("discount", new Discount());
        model.addAttribute("modalStatus", "open");
        return "pages/discount/discount-list";
    }

    @GetMapping("/edit/{id}")
    public String createDiscountForm(Model model, @PathVariable Long id) {
        model.addAttribute("discount", discountService.getDiscountById(id));
        model.addAttribute("modalStatus", "open");
        return "pages/discount/discount-list";
    }

    @PostMapping
    public String saveDiscount(@ModelAttribute("discount") Discount discount) {
        discountService.saveDiscount(discount);
        return "redirect:/discounts";
    }

    @GetMapping("/delete/{id}")
    public String deleteDiscount(@PathVariable Long id) {
        discountService.deleteDiscount(id);
        return "redirect:/discounts";
    }

}

