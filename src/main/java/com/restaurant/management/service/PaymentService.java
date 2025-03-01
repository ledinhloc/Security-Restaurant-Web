package com.restaurant.management.service;

import com.restaurant.management.config.payment.VNPayConfig;
import com.restaurant.management.util.VNPayUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.*;

import static com.restaurant.management.util.VNPayUtil.hmacSHA512;

@Controller
public class PaymentService {
    @Autowired
    VNPayConfig vnpayConfig;
    public String payOrder(String orderId, double amount, String orderInfo) {
        Map<String, String> vnp_HashFields = new HashMap<>();
        Map<String, String> vnp_Params = vnpayConfig.getVNPayConfig();
        vnp_Params.put("vnp_Amount", String.valueOf((int)amount * 100));
        vnp_HashFields.put("vnp_Amount", String.valueOf((int)amount * 100));
        vnp_Params.put("vnp_IpAddr", VNPayUtil.getIpAddress2());
        vnp_Params.put("vnp_TxnRef",  orderId);
        vnp_Params.put("vnp_OrderInfo", orderInfo.isEmpty() ? "Thanh toan don hang:" + orderId : orderInfo);
        vnp_HashFields.put("vnp_OrderInfo", orderInfo.isEmpty() ? "Thanh toan don hang:" + orderId : orderInfo);

        String queryUrl = VNPayUtil.getPaymentURL(vnp_Params, true);
        String hashData = VNPayUtil.getPaymentURL(vnp_Params, false);

        String vnpSecureHash = VNPayUtil.hmacSHA512(vnpayConfig.secretKey, hashData);
        System.out.println(vnpSecureHash);
        queryUrl += "&vnp_SecureHash=" + vnpSecureHash;
        return vnpayConfig.vnp_PayUrl + "?" + queryUrl;
    }


}
