package com.restaurant.management.controller;

import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
public class AdminController {
    @Autowired
    private OrderService orderService;

    @Autowired
    private DishService dishService;

    @Autowired
    private OrderItemService orderItemService;

    @Autowired
    private ReservationService reservationService;

    @Autowired
    private InventoryService inventoryService;

    @RequestMapping(value = "/dashboard", method = {RequestMethod.GET, RequestMethod.POST})
    public String showDashboard(@RequestParam(value = "startDate", required = false) String start,
                                @RequestParam(value = "endDate", required = false) String end,
                                Model model) {
        // Chuyển đổi String thành LocalDateTime
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");

        // Nếu startDate hoặc endDate không có giá trị (trong trường hợp là GET request), sử dụng giá trị mặc định
        if (start == null || end == null) {
            start = LocalDate.now().minusMonths(3).toString();  // Mặc định 1 tháng trước
            end = LocalDate.now().plusMonths(2).toString();  // Mặc định đến 2 tháng sau
        }

        //xu ly ngay tu form gui len hoac mac dinh
        LocalDate startDate = LocalDate.parse(start, formatter);
        LocalDate endDate = LocalDate.parse(end, formatter);
        LocalDateTime startDateTime = startDate.atStartOfDay();
        LocalDateTime endDateTime = endDate.atTime(23, 59, 59);

        System.out.println(startDateTime+" -------------- "+endDateTime);

        //lay data tu service
        Map<String, Integer> orderStats = orderService.getOrderStatistics(startDateTime, endDateTime);
        Map<String, Integer> dishStats = orderItemService.getDishStatistics(OrderStatus.COMPLETED, startDateTime, endDateTime);
        Map<String, Object> revenueAndProfit = orderItemService.getRevenueAndProfitData(startDateTime, endDateTime);
        List<Object []> reservationData = reservationService.getReservationStatusCounts(startDate, endDate);
        List<Object[]> inventoryData = inventoryService.getInventoryData();
        List<Object[]> dishSalesStats = orderItemService.getDishSalesStats(OrderStatus.COMPLETED, startDateTime, endDateTime);

        //truyen data vao dashboard
        model.addAttribute("orderStats", orderStats);
        model.addAttribute("dishStats", dishStats);
        model.addAttribute("revenueAndProfit", revenueAndProfit);
        model.addAttribute("reservationData", reservationData);
        model.addAttribute("inventoryData", inventoryData);
        model.addAttribute("dishSalesStats", dishSalesStats);
        model.addAttribute("startDate", startDate);  // Đưa giá trị startDate vào model
        model.addAttribute("endDate", endDate);      // Đưa giá trị endDate vào model

        //System.out.println("----"+orderStats);
        return "pages/admin/dashboard";
    }
}
