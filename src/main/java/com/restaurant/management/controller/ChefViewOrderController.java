package com.restaurant.management.controller;

import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.model.OrderItem;
import com.restaurant.management.service.DishService;
import com.restaurant.management.service.OrderItemService;
import com.restaurant.management.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/order-item")
public class ChefViewOrderController {
    @Autowired
    private OrderItemService orderItemService;

    @Autowired
    private DishService dishService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN') AND hasRole('CHEF')")
    public String listOrder(@RequestParam(required = false) String keyword, @RequestParam(required = false) String statusFilter,Model model) {
       //tim kiem ten dish hoac orderid va status
        List<OrderItem> orderItems = orderItemService.searchOrderItems(keyword, statusFilter);
        model.addAttribute("orderItems", orderItems);

        //gan lai gia tri tim kiem
        model.addAttribute("keyword", keyword);
        model.addAttribute("statusFilter", statusFilter);
        return "pages/ChefViewOrder/view-order";
    }

    @PostMapping("/updateOrderStatus")
    @PreAuthorize("hasRole('ADMIN') AND hasRole('CHEF')")
    public String updateOrderStatus(@RequestParam Long orderItemId, @RequestParam Long dishId, @RequestParam OrderStatus orderStatus, @RequestParam int quantity , RedirectAttributes redirectAttributes, Model model ) throws IllegalAccessException {
        //cập nhật lại kho hàng
        if(orderStatus.equals(OrderStatus.COMPLETED)) {
            if(!dishService.processDish(dishId, quantity)){
                redirectAttributes.addFlashAttribute("message", "Kho hang khong du!!!");
                return "redirect:/order-item";
            };
        }
        // Cập nhật trạng thái của order item
        orderItemService.updateOrderStatus(orderItemId, orderStatus);
        return "redirect:/order-item";
    }

}
