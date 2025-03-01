package com.restaurant.management.controller;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Supplier;
import com.restaurant.management.service.CustomerService;
import com.restaurant.management.service.SupplierService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequestMapping("/suppliers")
public class SupplierController {
    @Autowired
    private SupplierService supplierService;

    @GetMapping
    public String listSupplier(@RequestParam(defaultValue = "0") int page,
                               @RequestParam(defaultValue = "10") int size,
                               Model model) {
        Page<Supplier> supplierPage = supplierService.getSuppliersWithPagination(page, size);
        model.addAttribute("suppliers", supplierPage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", supplierPage.getTotalPages());
        return "pages/admin/Supplier/supplierList";
    }


    @PostMapping("/add")
    public String addSupplier(@ModelAttribute Supplier supplier) {
        try {
               Supplier sup =  supplierService.saveSupplier(supplier);
        }
        catch (Exception e) {
            System.err.println("Error saving supplier: " + e.getMessage());
            e.printStackTrace();
        }
        return "redirect:/suppliers";
    }

    @GetMapping("/delete/{id}")
    public String deleteSupplier(@PathVariable Long id) {
        supplierService.deleteSupplier(id);
        return "redirect:/suppliers";
    }

    @PostMapping("/edit/{id}")
    public String editSupplier(@PathVariable Long id, @ModelAttribute Supplier supplier) {
        try {
            supplier.setSupplierId(id);
            Supplier updatedsupplier = supplierService.updateSupplier(supplier);

            return "redirect:/suppliers";
        } catch (Exception e) {
            e.printStackTrace();
            return "error";
        }
    }
}
