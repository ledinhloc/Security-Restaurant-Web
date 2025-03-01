package com.restaurant.management.controller;

import com.google.zxing.WriterException;
import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.model.DiningTable;
import com.restaurant.management.model.Order;
import com.restaurant.management.service.OrderService;
import com.restaurant.management.service.TableService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Controller
@RequestMapping("/tables")
public class TableController {

    @Autowired
    private TableService tableService;
    @Autowired
    private OrderService orderService;

    @GetMapping
    public String listTables(@RequestParam(defaultValue = "0") int page,
                             @RequestParam(defaultValue = "5") int size,
                             Model model) {
        Page<DiningTable> tablePage = tableService.getTablesWithPagination(page, size);
        model.addAttribute("tables", tablePage.getContent());
        model.addAttribute("currentPage", page);
        model.addAttribute("totalPages", tablePage.getTotalPages());
        model.addAttribute("diningTable", new DiningTable());
        return "pages/tables/tables";
    }

    @GetMapping("/{tableId}")
    public String getOrderByTable(@PathVariable("tableId") Long tableId, Model model) {
        Optional<Order> orderOptional = orderService.findOrderByTableId(tableId);

        if (orderOptional.isPresent()) {
            Order order = orderOptional.get();
            if (order.getOrderStatus() != null && order.getOrderStatus() != OrderStatus.COMPLETED) {
                model.addAttribute("order", order);
                model.addAttribute("orderItems", order.getOrderItems());
                model.addAttribute("tableId", tableId);
                model.addAttribute("tableNumber", tableService.getTableNumberByTableId(tableId));
                model.addAttribute("orderId", order.getId());
                return "pages/tables/table-orders";
            }
            return "/error";
        } else {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            String customerEmail = ((UserDetails) principal).getUsername();
            Order order = orderService.createOrder(tableId, customerEmail);

            return "redirect:/orders/menu?orderId=" + order.getId();
        }
    }

    @PostMapping("/add")
    public String addTable(@ModelAttribute DiningTable diningTable, HttpServletRequest request) {
        System.out.println(diningTable);
        try {
            tableService.createTable(diningTable, request);
        } catch (WriterException | IOException e) {
            e.printStackTrace();
            return "error";
        }
        return "redirect:/tables";
    }

    @GetMapping("/edit/{id}")
    public String showEditForm(@PathVariable Long id, Model model) {
        DiningTable diningTable = tableService.getTableById(id).orElseThrow(() -> new IllegalArgumentException("Invalid table Id:" + id));
        model.addAttribute("table", diningTable);
        return "tables/edit"; // Thymeleaf template for editing a table
    }

    @PostMapping("/edit/{id}")
    public String editTable(@PathVariable Long id, @ModelAttribute DiningTable diningTable) {
        tableService.updateTable(id, diningTable);
        return "redirect:/tables";
    }

    @GetMapping("/delete/{id}")
    public String deleteTable(@PathVariable Long id) {
        tableService.deleteTable(id);
        return "redirect:/tables";
    }
}
