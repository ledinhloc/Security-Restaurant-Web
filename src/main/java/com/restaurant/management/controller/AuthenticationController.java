package com.restaurant.management.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthenticationController {
    @GetMapping("/login")
    public String loginPage(Model model) {
        return "pages/auth/login";
    }

    @GetMapping("/profile")
    public String viewDashboard(Model model) {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String customerEmail = ((UserDetails) principal).getUsername();
        model.addAttribute("customerEmail", customerEmail);
        return "pages/auth/profile";
    }

    @GetMapping("/forgot-password")
    public String forgotPassword(Model model) {
        return "pages/auth/request-otp";
    }
}
