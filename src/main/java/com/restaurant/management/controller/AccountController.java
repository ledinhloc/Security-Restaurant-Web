package com.restaurant.management.controller;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Dish;
import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Otp;
import com.restaurant.management.repository.CustomerRepository;
import com.restaurant.management.repository.OtpRepository;
import com.restaurant.management.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.UUID;

@Controller
public class AccountController {

    @Autowired
    private SmsService smsService;

    @Autowired
    private OtpService otpService;

    @Autowired
    private CustomerService customerService;

    @Autowired
    private EmployeeService employeeService;

    @Autowired
    private DishService dishService;

    @PostMapping("/request-otp")
    public String requestOtp(@RequestParam String phoneNumber, Model model) {
        // Tạo OTP
        String otpCode = String.format("%06d", new Random().nextInt(1000000));
        Otp otp = new Otp();
        otp.setPhoneNumber(phoneNumber);
        otp.setOtpCode(otpCode);
        otp.setExpiryTime(LocalDateTime.now().plusMinutes(5));
        otp.setUsed(false);
        otpService.save(otp);

        // Gửi OTP qua SMS
        smsService.sendSms(phoneNumber, "Your OTP is: " + otpCode);
        model.addAttribute("phoneNumber", phoneNumber);
        model.addAttribute("message", "OTP has been sent to your phone.");
        return "pages/auth/verify-otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String phoneNumber, @RequestParam String otpCode, Model model) throws IOException {
        Otp otp = otpService.findOtp(phoneNumber, otpCode);

        // Kiểm tra OTP tồn tại và chưa được sử dụng
        if (otp == null || otp.isUsed() || otp.getExpiryTime().isBefore(LocalDateTime.now())) {
            model.addAttribute("error", "Invalid, expired, or already used OTP.");
            return "pages/auth/verify-otp";
        }

        // Đánh dấu OTP là đã sử dụng
        otpService.markOtpAsUsed(otp);

        // Tạo mật khẩu mới
        String newPassword = UUID.randomUUID().toString().substring(0, 8);
        System.out.println(phoneNumber + " --------- password: " + newPassword);

        //cập nhật mật khẩu
        if (updatePasswordForUser(phoneNumber, newPassword)) {
            // Gửi SMS
            smsService.sendSms(phoneNumber, "Your new password is: " + newPassword);
            model.addAttribute("message", "A new password has been sent to your phone.");
            return "pages/auth/password-reset-success";
        }

        model.addAttribute("error", "Unable to reset the password. User not found.");
        return "pages/auth/verify-otp";
    }

    private boolean updatePasswordForUser(String phoneNumber, String newPassword) throws IOException {
        // Xử lý cập nhật mật khẩu cho Employee
        Employee employee = employeeService.getEmployeeByPhone(phoneNumber);
        if (employee != null) {
            employee.setPassword(newPassword);
            employeeService.saveEmployee(employee);
            return true;
        }

        // Xử lý cập nhật mật khẩu cho Customer
        Customer customer = customerService.getCustomerByPhone(phoneNumber);
        if (customer != null) {
            customer.setPassword(newPassword);
            customerService.saveCustomer(customer);
            return true;
        }

        // Không tìm thấy người dùng
        return false;
    }

    //hien thi form dang ki
    @GetMapping("/register")
    public String showRegistrationForm(){
        return "pages/auth/registerCustomer";
    }

    //luu customer
    @PostMapping("/register")
    public String registerCustomer(@ModelAttribute("customer") Customer customer){
        customerService.saveCustomer(customer);
        return "redirect:/login";
    }

    @GetMapping("/")
    public String showHomePage(Model model){
        List<Dish> dishes = dishService.getAllDishes();
        model.addAttribute("dishes", dishes);
        return "pages/auth/homePage";
    }
}
