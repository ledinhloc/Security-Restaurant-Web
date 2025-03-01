package com.restaurant.management.service;

import com.restaurant.management.enums.OrderMethod;
import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.enums.TableStatus;
import com.restaurant.management.model.*;
import com.restaurant.management.repository.DishRepository;
import com.restaurant.management.repository.OrderItemRepository;
import com.restaurant.management.repository.OrderRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Service
public class OrderService {
    @Autowired
    private OrderRepository orderRepository;
    @Autowired
    private OrderItemRepository orderItemRepository;
    @Autowired
    private DishRepository dishRepository;
    @Autowired
    private PaymentService paymentService;
    @Autowired
    private TableService tableService;
    @Autowired
    private CustomerService customerService;

    public Order createOrder(Long tableId, String customerEmail) {
        DiningTable diningTable = tableService.getTableById(tableId)
                .orElseThrow(() -> new IllegalArgumentException("Table not found"));

        diningTable.setStatus(TableStatus.OCCUPIED);
        diningTable = tableService.save(diningTable);
        Optional<Customer> customer = customerService.getCustomerByEmail(customerEmail);

        if (!customer.isPresent()) {
            customer = customerService.getCustomerByEmail("noinfo@default.com");
        }
        String customerId = customer.get().getCustomerId().toString();
        Order order = Order.builder()
                .id(generateOrderID(customerId))
                .customer(customer.get())
                .orderDate(LocalDateTime.now())
                .diningTable(diningTable)
                .totalAmount(0.0)
                .build();

        return orderRepository.save(order);
    }

    @Transactional
    public void addDishToOrder(String orderId, Long dishId, int quantity) {
        Order order = getOrderById(orderId);
        Dish dish = dishRepository.findById(dishId)
                .orElseThrow(() -> new RuntimeException("Dish not found"));

        Optional<OrderItem> existingItem = order.getOrderItems()
                .stream()
                .filter(item -> item.getDish().getDishId().equals(dishId))
                .findFirst();

        if (existingItem.isPresent()) {
            OrderItem orderItem = existingItem.get();
            orderItem.setQuantity(orderItem.getQuantity() + quantity);
            orderItemRepository.save(orderItem);
        } else {
            OrderItem orderItem = new OrderItem();
            orderItem.setOrder(order);
            orderItem.setDish(dish);
            orderItem.setQuantity(quantity);
            orderItem.setPrice(dish.getPrice());
            orderItem.setCost(dish.getCost());
            orderItemRepository.save(orderItem);
        }
        order = getOrderById(orderId);
        updateTotalAmount(order);
    }

    private void updateTotalAmount(Order order) {
        double totalAmount = order.getOrderItems().stream()
                .mapToDouble(item -> item.getPrice() * item.getQuantity())
                .sum();
        order.setTotalAmount(totalAmount);
        orderRepository.save(order);
    }

    public void updateOrderItemQuantity(String orderId, Long orderItemId, int delta) {
        OrderItem orderItem = orderItemRepository.findById(orderItemId)
                .orElseThrow(() -> new RuntimeException("Order item not found"));

        int newQuantity = orderItem.getQuantity() + delta;

        if (newQuantity <= 0) {
            orderItemRepository.delete(orderItem);
        } else {
            orderItem.setQuantity(newQuantity);
            orderItemRepository.save(orderItem);
        }
        Order order = getOrderById(orderId);
        updateTotalAmount(order);
    }

    @Transactional
    public List<OrderItem> getOrderDetailByOrderId(String orderId) {
        return orderRepository.findOrderDetailByOrderId(orderId);
    }

    private String generateOrderID(String customerId) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyyMMdd");
        String date = LocalDateTime.now().format(formatter);
        String randomNumber = String.format("%04d", new Random().nextInt(10000));
        return date + customerId + randomNumber;
    }

    public String payOrder(String orderId) {
        Order order = orderRepository.findById(orderId).orElseThrow(()
                -> new RuntimeException("Order not found with id: " + orderId));
        return paymentService.payOrder(orderId, order.getTotalAmount(), "Thanh toan don hang " + order.getId());
    }

    public boolean checkOrderId(String orderId) {
        return orderRepository.existsById(orderId);
    }

    public boolean checkAmount(String orderId, Double amount) {
        Optional<Order> order = orderRepository.findById(orderId);
        return order.map(o -> o.getTotalAmount().equals(amount / 100.0)).orElse(false);
    }

    public boolean checkOrderPendingStatus(String orderId) {
        Optional<Order> order = orderRepository.findById(orderId);
        return order.map(o -> o.getOrderStatus() == OrderStatus.PENDING).orElse(false); // Checks if status is pending
    }

    public boolean updateOrderStatus(String orderId, OrderStatus newStatus) {
        return orderRepository.findById(orderId).map(order -> {
            order.setOrderStatus(newStatus);
            orderRepository.save(order);
            return true;
        }).orElse(false);
    }

    public void completedOrder(String orderId) {
        Order order = getOrderById(orderId);
        order.setOrderStatus(OrderStatus.COMPLETED);
        orderRepository.save(order);
        tableService.updateTableStatus(order.getDiningTable().getId(), TableStatus.AVAILABLE);
    }

    public Optional<Order> findOrderByTableId(Long tableId) {
        return orderRepository.findFirstByDiningTableIdAndAndOrderStatusIn(tableId, Arrays.asList(OrderStatus.PAID, OrderStatus.UNPAID, OrderStatus.PENDING));
    }

    public Order getOrderById(String id) {
        return orderRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("Order not found with id: " + id));
    }

    public List<Order> getAllOrders() {
        return orderRepository.findAll();
    }

    public void saveOrder(Order order) {
        orderRepository.save(order);
    }

    public Map<String, Integer> getOrderStatistics(LocalDateTime startDate, LocalDateTime endDate) {
        // Lấy danh sách kết quả từ truy vấn
        List<Object[]> stats = orderRepository.countOrdersByOrderDay(startDate, endDate);
        Map<String, Integer> orderStats = new LinkedHashMap<>();

        for (Object[] stat : stats) {
            // Kiểm tra và chuyển đổi date từ Object[]
            String date = "";
            if (stat[0] instanceof java.sql.Date) {
                // Nếu stat[0] là java.sql.Date, chuyển đổi nó thành String
                date = new SimpleDateFormat("yyyy-MM-dd").format((java.sql.Date) stat[0]);
            } else if (stat[0] instanceof String) {
                // Nếu stat[0] là String, giữ nguyên
                date = (String) stat[0];
            }

            // Kiểm tra và chuyển đổi số lượng đơn hàng (stat[1])
            Integer quantity = ((Number) stat[1]).intValue();

            orderStats.put(date, quantity);
        }
        return orderStats;
    }
}
