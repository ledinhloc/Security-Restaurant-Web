package com.restaurant.management.controller;

import com.restaurant.management.model.Customer;
import com.restaurant.management.model.Dish;
import com.restaurant.management.model.Employee;
import com.restaurant.management.model.Otp;
import com.restaurant.management.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

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

    // In-memory storage for login attempts
    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();

    // Class to store attempt count and lockout time
    private static class LoginAttempt {
        int attempts;
        LocalDateTime lockoutUntil;

        LoginAttempt() {
            this.attempts = 0;
            this.lockoutUntil = null;
        }
    }

    @GetMapping("/login")
    public String showLoginPage(Model model, @RequestParam(value = "error", required = false) String error,
                                @RequestParam(value = "username", required = false) String username) {
        System.out.println("Login page accessed. Error: " + error + ", Username: " + username); // Debug
        if (error != null && username != null && !username.isEmpty()) {
            LoginAttempt attempt = loginAttempts.computeIfAbsent(username, k -> new LoginAttempt());
            System.out.println("Attempts for " + username + ": " + attempt.attempts + ", Locked until: " + attempt.lockoutUntil); // Debug
            if (error.equals("locked") || (attempt.lockoutUntil != null && attempt.lockoutUntil.isAfter(LocalDateTime.now()))) {
                model.addAttribute("error", "Tài khoản bị khóa. Vui lòng thử lại sau 1 phút.");
            } else {
                model.addAttribute("error", "Email hoặc mật khẩu không đúng.");
            }
        } else if (error != null) {
            model.addAttribute("error", "Vui lòng nhập email và mật khẩu.");
        }
        return "pages/auth/login";
    }

    @PostMapping("/request-otp")
    public String requestOtp(@RequestParam String phoneNumber, Model model) {
        String otpCode = String.format("%06d", new Random().nextInt(1000000));
        Otp otp = new Otp();
        otp.setPhoneNumber(phoneNumber);
        otp.setOtpCode(otpCode);
        otp.setExpiryTime(LocalDateTime.now().plusMinutes(5));
        otp.setUsed(false);
        otpService.save(otp);

        smsService.sendSms(phoneNumber, "Your OTP is: " + otpCode);
        model.addAttribute("phoneNumber", phoneNumber);
        model.addAttribute("message", "OTP has been sent to your phone.");
        return "pages/auth/verify-otp";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String phoneNumber, @RequestParam String otpCode, Model model) throws IOException {
        Otp otp = otpService.findOtp(phoneNumber, otpCode);

        if (otp == null || otp.isUsed() || otp.getExpiryTime().isBefore(LocalDateTime.now())) {
            model.addAttribute("error", "Invalid, expired, or already used OTP.");
            return "pages/auth/verify-otp";
        }

        otpService.markOtpAsUsed(otp);

        String newPassword = UUID.randomUUID().toString().substring(0, 8);
        System.out.println(phoneNumber + " --------- password: " + newPassword);

        if (updatePasswordForUser(phoneNumber, newPassword)) {
            smsService.sendSms(phoneNumber, "Your new password is: " + newPassword);
            model.addAttribute("message", "A new password has been sent to your phone.");
            return "pages/auth/password-reset-success";
        }

        model.addAttribute("error", "Unable to reset the password. User not found.");
        return "pages/auth/verify-otp";
    }

    private boolean updatePasswordForUser(String phoneNumber, String newPassword) throws IOException {
        Employee employee = employeeService.getEmployeeByPhone(phoneNumber);
        if (employee != null) {
            employee.setPassword(newPassword);
            employeeService.saveEmployee(employee);
            return true;
        }

        Customer customer = customerService.getCustomerByPhone(phoneNumber);
        if (customer != null) {
            customer.setPassword(newPassword);
            customerService.saveCustomer(customer);
            return true;
        }

        return false;
    }

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "pages/auth/registerCustomer";
    }

    @PostMapping("/register")
    public String registerCustomer(@ModelAttribute("customer") Customer customer, Model model) {
        String password = customer.getPassword();
        if (!isValidPassword(password)) {
            model.addAttribute("error", "Mật khẩu phải chứa ít nhất 10 ký tự, bao gồm chữ hoa, số và 1 ký tự đặc biệt.(!@#$%^&*)");
            return "pages/auth/registerCustomer";
        }
        customerService.saveCustomer(customer);
        return "redirect:/login";
    }

    private boolean isValidPassword(String password) {
        if (password == null) return false;
        if (password.length() < 10) return false;
        if (!password.matches(".*[A-Z].*")) return false;
        if (!password.matches(".*[0-9].*")) return false;
        if (!password.matches(".*[!@#$%^&*].*")) return false;
        return true;
    }

    @GetMapping("/")
    public String showHomePage(Model model) {
        List<Dish> dishes = dishService.getAllDishes();
        model.addAttribute("dishes", dishes);
        return "pages/auth/homePage";
    }

    @GetMapping("/profile/{id}")
    @PreAuthorize("hasRole('CUSTOMER')")
    public String showProfileFile(@PathVariable Long id, Model model) {
        Customer customer = customerService.getCustomerById(id);
        if (customer != null) {
            model.addAttribute("customer", customer);
            return "pages/customer/profile-customer";
        }
        return "redirect:/";
    }

    @PostMapping("/profile/update")
    @PreAuthorize("hasRole('CUSTOMER')")
    public String updateProfile(@ModelAttribute Customer customer) {
        customerService.saveCustomer(customer);
        return "redirect:/profile/" + customer.getCustomerId();
    }

    public void resetLoginAttempts(String username) {
        System.out.println("Resetting attempts for: " + username); // Debug
        loginAttempts.remove(username);
    }

    public void incrementLoginAttempts(String username) {
        LoginAttempt attempt = loginAttempts.computeIfAbsent(username, k -> new LoginAttempt());
        // Kiểm tra nếu hết thời gian khóa, đặt lại attempts
        if (attempt.lockoutUntil != null && attempt.lockoutUntil.isBefore(LocalDateTime.now())) {
            attempt.attempts = 0;
            attempt.lockoutUntil = null;
            loginAttempts.remove(username); // Xóa bản ghi để làm sạch
            System.out.println("Reset attempts for " + username + " after lockout expired"); // Debug
            attempt = new LoginAttempt(); // Tạo mới attempt
            loginAttempts.put(username, attempt);
        }
        attempt.attempts++;
        System.out.println("Incremented attempts for " + username + ": " + attempt.attempts); // Debug
        if (attempt.attempts >= 5) {
            attempt.lockoutUntil = LocalDateTime.now().plusMinutes(2);
            System.out.println("Account " + username + " locked until: " + attempt.lockoutUntil); // Debug
        }
    }

    public boolean isAccountLocked(String username) {
        LoginAttempt attempt = loginAttempts.get(username);
        if (attempt == null) {
            return false;
        }
        // Nếu hết thời gian khóa, đặt lại attempts và xóa bản ghi
        if (attempt.lockoutUntil != null && attempt.lockoutUntil.isBefore(LocalDateTime.now())) {
            attempt.attempts = 0;
            attempt.lockoutUntil = null;
            loginAttempts.remove(username);
            System.out.println("Lockout expired for " + username + ", attempts reset to 0"); // Debug
            return false;
        }
        boolean locked = attempt.lockoutUntil != null && attempt.lockoutUntil.isAfter(LocalDateTime.now());
        System.out.println("Is " + username + " locked? " + locked); // Debug
        return locked;
    }
}