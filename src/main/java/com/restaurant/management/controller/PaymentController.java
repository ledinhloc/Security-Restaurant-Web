package com.restaurant.management.controller;

import com.restaurant.management.config.payment.VNPayConfig;
import com.restaurant.management.enums.OrderStatus;
import com.restaurant.management.service.OrderService;
import com.restaurant.management.service.PaymentService;
import com.restaurant.management.service.TableService;
import com.restaurant.management.util.VNPayUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/payment")
public class PaymentController {
    @Autowired
    private PaymentService paymentService;
    @Autowired
    private VNPayConfig vnPayConfig;
    @Autowired
    private OrderService orderService;
    @Autowired
    private TableService tableService;

    @GetMapping("/vn-pay-callback")
    @ResponseBody
    public ResponseEntity<Map<String, String>> handleVNPayReturn(HttpServletRequest request) {
        Map<String, String> response = new HashMap<>();

        try {
            Map<String, String> fields = new HashMap<>();
            Enumeration<String> params = request.getParameterNames();
            while (params.hasMoreElements()) {
                String fieldName = params.nextElement();
                String fieldValue = URLEncoder.encode(request.getParameter(fieldName), StandardCharsets.US_ASCII.toString());
                if (fieldValue != null && !fieldValue.isEmpty()) {
                    fields.put(fieldName, fieldValue);
                }
            }

            String vnpSecureHash = request.getParameter("vnp_SecureHash");
            fields.remove("vnp_SecureHashType");
            fields.remove("vnp_SecureHash");

            String signValue = VNPayUtil.hashAllFields(fields, vnPayConfig.getSecretKey());
            if (!signValue.equals(vnpSecureHash)) {
                response.put("RspCode", "97");
                response.put("Message", "Invalid Checksum");
                return new ResponseEntity<>(response, HttpStatus.OK);
            }
            String orderId = request.getParameter("vnp_TxnRef");
            boolean checkOrderId = orderService.checkOrderId(orderId);
            boolean checkAmount = orderService.checkAmount(orderId, Double.parseDouble(request.getParameter("vnp_Amount")));
            boolean checkOrderStatus = orderService.checkOrderPendingStatus(orderId);

            if (!checkOrderId) {
                response.put("RspCode", "01");
                response.put("Message", "Order not Found");
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            if (!checkAmount) {
                response.put("RspCode", "04");
                response.put("Message", "Invalid Amount");
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            if (!checkOrderStatus) {
                response.put("RspCode", "02");
                response.put("Message", "Order already confirmed");
                return new ResponseEntity<>(response, HttpStatus.OK);
            }

            String responseCode = request.getParameter("vnp_ResponseCode");
            if ("00".equals(responseCode)) {
                orderService.completedOrder(orderId);
                return ResponseEntity.status(HttpStatus.FOUND)
                        .header(HttpHeaders.LOCATION, "/orders/reviews/" + orderId)
                        .build();
            } else {
                orderService.updateOrderStatus(orderId, OrderStatus.UNPAID);
                response.put("Message", "Error when pay");
            }
        } catch (Exception e) {
            response.put("RspCode", "99");
            response.put("Message", "Unknown error");
        }

        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}

