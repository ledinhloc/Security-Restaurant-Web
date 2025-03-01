package com.restaurant.management.service;

import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.model.Order;
import com.restaurant.management.model.OrderItem;
import com.restaurant.management.repository.OrderItemRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class OrderItemService {
    @Autowired
    private OrderItemRepository orderItemRepository;

    public List<OrderItem> getAllOrderItem(){
        return orderItemRepository.findAll();
    }

    public OrderItem getOrderItemById(Long id){
        return orderItemRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("OrderItem Not Found"));
    }
    public void updateOrderStatus(Long orderItemID, OrderStatus orderStatus){
        OrderItem orderItem = orderItemRepository.findById(orderItemID)
                .orElseThrow(() -> new RuntimeException("Order item not found"));
        orderItem.setOrderStatus(orderStatus);
        orderItemRepository.save(orderItem);
    }

    public List<OrderItem> searchOrderItems(String keyword, String statusFilter) {
        //chuan hoa keyword
        String searchKeyword = (keyword != null && !keyword.trim().isEmpty()) ? keyword.trim().toLowerCase() : null;
        //chuan hoa status
        OrderStatus status = (statusFilter != null && !statusFilter.isEmpty()) ? OrderStatus.valueOf(statusFilter) : null;
        return orderItemRepository.findByKeywordAndStatus(searchKeyword, status);
    }

    public Map<String, Integer> getDishStatistics(OrderStatus orderStatus, LocalDateTime startDate, LocalDateTime endDate) {
        List<Object[]> result = orderItemRepository.getDishSalesStats(orderStatus, startDate, endDate);
        Map<String, Integer> dishStatistics = new HashMap<>();
        for(Object[] row : result){
            String dishName = (String) row[0];
            Integer quantity = ((Number) row[1]).intValue();
            dishStatistics.put(dishName, quantity);
        }
        return dishStatistics;
    }

    // dashboard chi phi va loi nhuan
    public Map<String, Object> getRevenueAndProfitData(LocalDateTime startDate, LocalDateTime endDate) {
        List<Object[]> results = orderItemRepository.getProfitAndRevenueByDateRange(startDate, endDate);

        List<String> dates = new ArrayList<>();
        List<Double> totalCosts = new ArrayList<>();
        List<Double> totalRevenues = new ArrayList<>();

        for (Object[] result : results) {
            dates.add(((LocalDateTime) result[0]).toLocalDate().toString());
            totalCosts.add((Double) result[1]);
            totalRevenues.add((Double) result[2]);
        }

        Map<String, Object> response = new HashMap<>();
        response.put("dates", dates);
        response.put("totalCosts", totalCosts);
        response.put("totalRevenues", totalRevenues);

        return response;
    }

    public List<Object[]> getDishSalesStats(OrderStatus status, LocalDateTime startDate, LocalDateTime endDate) {
        // table tên dish, so luong, tong price giam dan
        List<Object[]> results = orderItemRepository.findDishSalesStatsBetweenDates(status, startDate, endDate);

        return results;
    }

}
